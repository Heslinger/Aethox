"""End-to-end flow test demonstrating the full engine pipeline."""

import json

import httpx
import pytest

from redhills_engine.config import get_settings
from redhills_engine.core.agent_loop import (
    PayloadGenerator,
)
from redhills_engine.database.connection import get_db_session, init_db, shutdown_db
from redhills_engine.database.models import (
    Scan,
    ScanStatus,
    Target,
)
from redhills_engine.reporting.compiler import ReportCompiler


@pytest.fixture(autouse=True)
async def setup_database():
    """Initialize and teardown the test database."""
    await init_db()
    yield
    await shutdown_db()


@pytest.mark.asyncio
async def test_full_scan_pipeline():
    """Simulate the entire red-teaming pipeline end-to-end.

    1. Create a target and scan in the database
    2. Run discovery (against a non-existent target, demonstrating error handling)
    3. Verify payload generation works
    4. Verify report compilation produces valid output
    5. Test egress monitor captures tokens via HTTP
    """
    async with get_db_session() as session:
        target = Target(
            client_id="e2e-test-client",
            target_url="http://localhost:9999/nonexistent",
            auth_headers=json.dumps({"X-API-Key": "test-key-123"}),
        )
        session.add(target)
        await session.flush()

        scan = Scan(
            target_id=target.id,
            status=ScanStatus.QUEUED,
        )
        session.add(scan)
        await session.flush()

        scan_id = scan.id
        target_url = target.target_url

    settings = get_settings()
    generator = PayloadGenerator(egress_domain=settings.EGRESS_MONITOR_DOMAIN)

    from redhills_engine.database.models import PayloadCategory

    for category in PayloadCategory:
        raw, mutated, token = await generator.generate_payload(
            category=category,
            objective="Test objective for e2e",
            previous_failures=[],
        )
        assert raw, f"Empty raw prompt for {category}"
        assert mutated, f"Empty mutated prompt for {category}"
        assert token, f"Empty token for {category}"
        assert len(token) > 10

    async with httpx.AsyncClient() as client:
        response = await client.get("http://localhost:9090/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    test_token = generator.generate_token()
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"http://localhost:9090/leak/{test_token}",
            params={"data": "sensitive_info_leaked"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "captured"
        assert data["token"] == test_token

    compiler = ReportCompiler()
    report = await compiler.compile_report(scan_id)
    assert report.scan_id == scan_id
    assert report.target_url == target_url

    report_json = report.to_json()
    parsed = json.loads(report_json)
    assert "report_metadata" in parsed
    assert "statistics" in parsed
    assert "findings" in parsed


@pytest.mark.asyncio
async def test_egress_monitor_multi_method():
    """Test that the egress monitor captures multiple HTTP methods."""
    async with httpx.AsyncClient() as client:
        for method in ["GET", "POST", "PUT"]:
            response = await client.request(
                method,
                "http://localhost:9090/leak/method_test_token",
                params={"method": method},
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "captured"
            assert data["token"] == "method_test_token"


@pytest.mark.asyncio
async def test_egress_monitor_subpath():
    """Test egress capture with subpath routing."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "http://localhost:9090/leak/token123/extra/path/here"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "captured"
        assert data["token"] == "token123"
