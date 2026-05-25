"""Passive and active AI endpoint mapping and fingerprinting."""

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

COMMON_AI_ROUTES: list[str] = [
    "/api/v1/chat",
    "/v1/chat/completions",
    "/api/predict",
    "/chat",
    "/api/chat",
    "/v1/completions",
    "/api/v1/completions",
    "/inference",
    "/generate",
    "/api/generate",
]

FRAMEWORK_SIGNATURES: dict[str, list[str]] = {
    "LangChain": ["langchain", "lc_kwargs", "lc_id"],
    "FastAPI": ["fastapi", "openapi.json", "/docs", "/redoc"],
    "Flask": ["werkzeug", "flask"],
    "LlamaIndex": ["llama_index", "llama-index"],
    "OpenAI_Proxy": ["openai", "model", "choices", "usage"],
    "Anthropic_Proxy": ["anthropic", "content", "stop_reason"],
}


@dataclass
class EndpointFingerprint:
    """Results from probing a single endpoint."""

    route: str
    reachable: bool = False
    http_status: int = 0
    detected_frameworks: list[str] = field(default_factory=list)
    cors_open: bool = False
    server_header: str = ""
    content_type: str = ""
    error_leak: bool = False
    raw_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class DiscoveryReport:
    """Aggregated reconnaissance results for a target."""

    target_url: str
    reachable_endpoints: list[EndpointFingerprint] = field(default_factory=list)
    detected_frameworks: list[str] = field(default_factory=list)
    cors_misconfiguration: bool = False
    verbose_errors: bool = False
    attack_surface_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize report to a dictionary."""
        return {
            "target_url": self.target_url,
            "reachable_endpoints": [
                {
                    "route": ep.route,
                    "http_status": ep.http_status,
                    "detected_frameworks": ep.detected_frameworks,
                    "cors_open": ep.cors_open,
                    "server_header": ep.server_header,
                    "error_leak": ep.error_leak,
                }
                for ep in self.reachable_endpoints
            ],
            "detected_frameworks": self.detected_frameworks,
            "cors_misconfiguration": self.cors_misconfiguration,
            "verbose_errors": self.verbose_errors,
            "attack_surface_score": self.attack_surface_score,
        }


class EndpointDiscoverer:
    """Async reconnaissance engine for AI endpoint discovery and fingerprinting."""

    def __init__(
        self,
        target_url: str,
        auth_headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._target_url = target_url.rstrip("/")
        self._auth_headers = auth_headers or {}
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "EndpointDiscoverer":
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            headers=self._auth_headers,
            follow_redirects=True,
            verify=False,
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    async def _probe_endpoint(self, route: str) -> EndpointFingerprint:
        """Probe a single route and analyze the response."""
        url = f"{self._target_url}{route}"
        fp = EndpointFingerprint(route=route)

        if not self._client:
            return fp

        try:
            response = await self._client.post(
                url,
                json={"message": "hello", "prompt": "test"},
            )
            fp.reachable = True
            fp.http_status = response.status_code
            fp.raw_headers = dict(response.headers)
            fp.server_header = response.headers.get("server", "")
            fp.content_type = response.headers.get("content-type", "")

            cors_origin = response.headers.get("access-control-allow-origin", "")
            if cors_origin == "*":
                fp.cors_open = True

            response_text = response.text.lower()
            for framework, signatures in FRAMEWORK_SIGNATURES.items():
                if any(sig in response_text for sig in signatures):
                    fp.detected_frameworks.append(framework)

            if any(
                keyword in response_text
                for keyword in ["traceback", "stacktrace", "exception", "error"]
            ):
                if response.status_code >= 400:
                    fp.error_leak = True

            logger.info(
                "Probed %s -> status=%d frameworks=%s",
                url,
                response.status_code,
                fp.detected_frameworks,
            )

        except httpx.TimeoutException:
            logger.debug("Timeout probing %s", url)
        except httpx.ConnectError:
            logger.debug("Connection refused for %s", url)
        except httpx.HTTPError as exc:
            logger.debug("HTTP error probing %s: %s", url, exc)

        return fp

    async def _check_cors(self) -> bool:
        """Send an OPTIONS request to detect wide-open CORS."""
        if not self._client:
            return False
        try:
            response = await self._client.options(
                self._target_url,
                headers={"Origin": "https://attacker.example.com"},
            )
            allow_origin = response.headers.get("access-control-allow-origin", "")
            return allow_origin in ("*", "https://attacker.example.com")
        except httpx.HTTPError:
            return False

    async def run_discovery(self) -> DiscoveryReport:
        """Execute the full reconnaissance workflow and return structured findings."""
        logger.info("Starting discovery against %s", self._target_url)
        report = DiscoveryReport(target_url=self._target_url)

        fingerprints: list[EndpointFingerprint] = []
        for route in COMMON_AI_ROUTES:
            fp = await self._probe_endpoint(route)
            if fp.reachable:
                fingerprints.append(fp)

        report.reachable_endpoints = fingerprints

        all_frameworks: set[str] = set()
        for fp in fingerprints:
            all_frameworks.update(fp.detected_frameworks)
            if fp.cors_open:
                report.cors_misconfiguration = True
            if fp.error_leak:
                report.verbose_errors = True

        report.detected_frameworks = sorted(all_frameworks)

        report.cors_misconfiguration = (
            report.cors_misconfiguration or await self._check_cors()
        )

        score = 0.0
        score += len(fingerprints) * 10.0
        score += len(all_frameworks) * 5.0
        if report.cors_misconfiguration:
            score += 15.0
        if report.verbose_errors:
            score += 20.0
        report.attack_surface_score = min(score, 100.0)

        logger.info(
            "Discovery complete: %d endpoints, score=%.1f, frameworks=%s",
            len(fingerprints),
            report.attack_surface_score,
            report.detected_frameworks,
        )
        return report
