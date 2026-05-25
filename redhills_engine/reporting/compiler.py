"""JSON vulnerability aggregator and OWASP/ATLAS report compiler."""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from redhills_engine.database.connection import get_db_session
from redhills_engine.database.models import (
    Payload,
    Scan,
    Target,
    Vulnerability,
)

logger = logging.getLogger(__name__)

OWASP_LLM_MAPPING: dict[str, dict[str, str]] = {
    "LLM01: Prompt Injection": {
        "id": "LLM01",
        "title": "Prompt Injection",
        "description": (
            "An attacker manipulates a large language model through crafted inputs, "
            "causing unintended actions by the LLM."
        ),
        "reference": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    "LLM02: Insecure Output Handling": {
        "id": "LLM02",
        "title": "Insecure Output Handling",
        "description": (
            "Insufficient validation or sanitization of LLM outputs leading to "
            "downstream security issues."
        ),
        "reference": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    "LLM06: Sensitive Information Disclosure": {
        "id": "LLM06",
        "title": "Sensitive Information Disclosure",
        "description": (
            "The LLM inadvertently reveals sensitive information in its responses, "
            "leading to unauthorized data access or privacy violations."
        ),
        "reference": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    "LLM07: Insecure Plugin Design / API Abuse": {
        "id": "LLM07",
        "title": "Insecure Plugin Design",
        "description": (
            "LLM plugins can have insecure inputs and insufficient access control, "
            "enabling attackers to abuse exposed functionality."
        ),
        "reference": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
}

MITRE_ATLAS_MAPPING: dict[str, dict[str, str]] = {
    "LLM01: Prompt Injection": {
        "technique_id": "AML.T0051",
        "technique_name": "LLM Prompt Injection",
        "tactic": "Initial Access",
        "matrix": "MITRE ATLAS",
        "reference": "https://atlas.mitre.org/techniques/AML.T0051",
    },
    "LLM06: Sensitive Information Disclosure": {
        "technique_id": "AML.T0024",
        "technique_name": "Exfiltration via ML Inference API",
        "tactic": "Exfiltration",
        "matrix": "MITRE ATLAS",
        "reference": "https://atlas.mitre.org/techniques/AML.T0024",
    },
    "LLM07: Insecure Plugin Design / API Abuse": {
        "technique_id": "AML.T0040",
        "technique_name": "ML Model Inference API Access",
        "tactic": "Collection",
        "matrix": "MITRE ATLAS",
        "reference": "https://atlas.mitre.org/techniques/AML.T0040",
    },
}


@dataclass
class FindingSummary:
    """A single finding in the compiled report."""

    vulnerability_id: str
    severity: str
    vulnerability_type: str
    owasp_mapping: dict[str, str] = field(default_factory=dict)
    atlas_mapping: dict[str, str] = field(default_factory=dict)
    exploit_chain: list[dict[str, Any]] = field(default_factory=list)
    remediation_steps: str = ""
    egress_confirmed: bool = False


@dataclass
class ComplianceReport:
    """Full compliance report for a completed scan."""

    scan_id: str
    target_url: str
    client_id: str
    scan_start: str
    scan_end: str
    total_payloads_tested: int
    total_blocked: int
    total_vulnerabilities: int
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    findings: list[FindingSummary] = field(default_factory=list)
    owasp_coverage: list[dict[str, str]] = field(default_factory=list)
    atlas_coverage: list[dict[str, str]] = field(default_factory=list)
    executive_summary: str = ""
    generated_at: str = ""

    def to_json(self, indent: int = 2) -> str:
        """Serialize the full report to JSON."""
        return json.dumps(self._to_dict(), indent=indent, default=str)

    def _to_dict(self) -> dict[str, Any]:
        """Convert report to a nested dictionary."""
        return {
            "report_metadata": {
                "scan_id": self.scan_id,
                "target_url": self.target_url,
                "client_id": self.client_id,
                "scan_start": self.scan_start,
                "scan_end": self.scan_end,
                "generated_at": self.generated_at,
            },
            "statistics": {
                "total_payloads_tested": self.total_payloads_tested,
                "total_blocked": self.total_blocked,
                "total_vulnerabilities": self.total_vulnerabilities,
                "severity_breakdown": self.severity_breakdown,
            },
            "executive_summary": self.executive_summary,
            "findings": [
                {
                    "id": f.vulnerability_id,
                    "severity": f.severity,
                    "type": f.vulnerability_type,
                    "owasp_mapping": f.owasp_mapping,
                    "atlas_mapping": f.atlas_mapping,
                    "exploit_chain": f.exploit_chain,
                    "remediation": f.remediation_steps,
                    "egress_confirmed": f.egress_confirmed,
                }
                for f in self.findings
            ],
            "compliance_frameworks": {
                "owasp_top_10_llm": self.owasp_coverage,
                "mitre_atlas": self.atlas_coverage,
            },
        }


class ReportCompiler:
    """Compiles scan results into enterprise compliance reports."""

    async def compile_report(self, scan_id: str) -> ComplianceReport:
        """Query a finished scan and compile a full compliance report."""
        logger.info("Compiling report for scan %s", scan_id)

        scan, target = await self._load_scan_and_target(scan_id)
        payloads = await self._load_payloads(scan_id)
        vulnerabilities = await self._load_vulnerabilities(scan_id)

        report = ComplianceReport(
            scan_id=scan_id,
            target_url=target.target_url if target else "unknown",
            client_id=target.client_id if target else "unknown",
            scan_start=scan.start_time.isoformat() if scan and scan.start_time else "",
            scan_end=scan.end_time.isoformat() if scan and scan.end_time else "",
            total_payloads_tested=len(payloads),
            total_blocked=sum(1 for p in payloads if p.was_blocked),
            total_vulnerabilities=len(vulnerabilities),
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

        report.severity_breakdown = self._compute_severity_breakdown(vulnerabilities)
        report.findings = self._compile_findings(vulnerabilities)
        report.owasp_coverage = self._map_owasp_coverage(vulnerabilities)
        report.atlas_coverage = self._map_atlas_coverage(vulnerabilities)
        report.executive_summary = self._generate_executive_summary(report)

        logger.info(
            "Report compiled: %d findings, %d payloads tested",
            report.total_vulnerabilities,
            report.total_payloads_tested,
        )
        return report

    async def _load_scan_and_target(
        self, scan_id: str
    ) -> tuple[Scan | None, Target | None]:
        """Load scan and associated target from the database."""
        async with get_db_session() as session:
            scan_stmt = select(Scan).where(Scan.id == scan_id)
            scan_result = await session.execute(scan_stmt)
            scan = scan_result.scalar_one_or_none()

            if scan is None:
                logger.error("Scan %s not found", scan_id)
                return None, None

            target_stmt = select(Target).where(Target.id == scan.target_id)
            target_result = await session.execute(target_stmt)
            target = target_result.scalar_one_or_none()

            return scan, target

    async def _load_payloads(self, scan_id: str) -> list[Payload]:
        """Load all payloads associated with a scan."""
        async with get_db_session() as session:
            stmt = select(Payload).where(Payload.scan_id == scan_id)
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def _load_vulnerabilities(self, scan_id: str) -> list[Vulnerability]:
        """Load all vulnerabilities associated with a scan."""
        async with get_db_session() as session:
            stmt = select(Vulnerability).where(Vulnerability.scan_id == scan_id)
            result = await session.execute(stmt)
            return list(result.scalars().all())

    @staticmethod
    def _compute_severity_breakdown(
        vulnerabilities: list[Vulnerability],
    ) -> dict[str, int]:
        """Count vulnerabilities by severity level."""
        breakdown: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }
        for vuln in vulnerabilities:
            breakdown[vuln.severity.value] = breakdown.get(vuln.severity.value, 0) + 1
        return breakdown

    @staticmethod
    def _compile_findings(vulnerabilities: list[Vulnerability]) -> list[FindingSummary]:
        """Transform raw vulnerability records into report findings."""
        findings: list[FindingSummary] = []

        for vuln in vulnerabilities:
            exploit_chain: list[dict[str, Any]] = []
            if vuln.exploit_chain:
                try:
                    parsed = json.loads(vuln.exploit_chain)
                    if isinstance(parsed, list):
                        exploit_chain = parsed
                    elif isinstance(parsed, dict):
                        exploit_chain = [parsed]
                except json.JSONDecodeError:
                    exploit_chain = [{"raw": vuln.exploit_chain}]

            owasp = OWASP_LLM_MAPPING.get(vuln.vulnerability_type, {})
            atlas = MITRE_ATLAS_MAPPING.get(vuln.vulnerability_type, {})

            findings.append(
                FindingSummary(
                    vulnerability_id=vuln.id,
                    severity=vuln.severity.value,
                    vulnerability_type=vuln.vulnerability_type,
                    owasp_mapping=owasp,
                    atlas_mapping=atlas,
                    exploit_chain=exploit_chain,
                    remediation_steps=vuln.remediation_steps or "",
                    egress_confirmed=vuln.egress_token_triggered,
                )
            )

        return sorted(
            findings,
            key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(f.severity),
        )

    @staticmethod
    def _map_owasp_coverage(
        vulnerabilities: list[Vulnerability],
    ) -> list[dict[str, str]]:
        """Map findings to OWASP Top 10 for LLM Applications."""
        covered: set[str] = set()
        coverage: list[dict[str, str]] = []

        for vuln in vulnerabilities:
            mapping = OWASP_LLM_MAPPING.get(vuln.vulnerability_type)
            if mapping and mapping["id"] not in covered:
                covered.add(mapping["id"])
                coverage.append({
                    **mapping,
                    "finding_severity": vuln.severity.value,
                })

        return coverage

    @staticmethod
    def _map_atlas_coverage(
        vulnerabilities: list[Vulnerability],
    ) -> list[dict[str, str]]:
        """Map findings to MITRE ATLAS adversarial techniques."""
        covered: set[str] = set()
        coverage: list[dict[str, str]] = []

        for vuln in vulnerabilities:
            mapping = MITRE_ATLAS_MAPPING.get(vuln.vulnerability_type)
            if mapping and mapping["technique_id"] not in covered:
                covered.add(mapping["technique_id"])
                coverage.append({
                    **mapping,
                    "finding_severity": vuln.severity.value,
                })

        return coverage

    @staticmethod
    def _generate_executive_summary(report: ComplianceReport) -> str:
        """Generate a human-readable executive summary."""
        critical_count = report.severity_breakdown.get("CRITICAL", 0)
        high_count = report.severity_breakdown.get("HIGH", 0)

        if critical_count > 0:
            risk_level = "CRITICAL"
            urgency = "Immediate remediation required."
        elif high_count > 0:
            risk_level = "HIGH"
            urgency = "Prompt remediation strongly recommended."
        elif report.total_vulnerabilities > 0:
            risk_level = "MODERATE"
            urgency = "Remediation recommended within standard SLA."
        else:
            risk_level = "LOW"
            urgency = "No significant vulnerabilities detected."

        egress_confirmed = any(
            f.egress_confirmed for f in report.findings
        )

        summary_parts = [
            f"Risk Assessment: {risk_level}",
            f"Total Payloads Tested: {report.total_payloads_tested}",
            f"Payloads Blocked: {report.total_blocked}",
            f"Confirmed Vulnerabilities: {report.total_vulnerabilities}",
            f"Critical Findings: {critical_count}",
            f"High Findings: {high_count}",
            f"Out-of-Band Exfiltration Confirmed: {'Yes' if egress_confirmed else 'No'}",
            "",
            urgency,
        ]

        return "\n".join(summary_parts)
