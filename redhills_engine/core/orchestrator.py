"""Async scan manager, worker loop, and state machine."""

import asyncio
import logging
from datetime import datetime, timezone

import redis.asyncio as aioredis
from sqlalchemy import select, update

from redhills_engine.config import get_settings
from redhills_engine.core.agent_loop import AdversarialAgentLoop
from redhills_engine.core.discovery import EndpointDiscoverer
from redhills_engine.database.connection import get_db_session, get_session_factory
from redhills_engine.database.models import Scan, ScanStatus, Target

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Manages the lifecycle of red-teaming scans with concurrency control."""

    def __init__(self) -> None:
        self._settings = get_settings()
        self._semaphore = asyncio.Semaphore(self._settings.MAX_CONCURRENT_SCANS)
        self._redis: aioredis.Redis | None = None
        self._running: bool = False
        self._active_tasks: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        """Initialize connections and begin the worker loop."""
        self._redis = aioredis.from_url(
            self._settings.REDIS_URL, decode_responses=True
        )
        self._running = True
        logger.info(
            "Orchestrator starting with concurrency limit=%d",
            self._settings.MAX_CONCURRENT_SCANS,
        )
        await self._worker_loop()

    async def stop(self) -> None:
        """Gracefully shut down the orchestrator."""
        self._running = False
        if self._active_tasks:
            logger.info("Waiting for %d active tasks to complete", len(self._active_tasks))
            await asyncio.gather(*self._active_tasks, return_exceptions=True)
        if self._redis:
            await self._redis.aclose()
        logger.info("Orchestrator stopped")

    async def _worker_loop(self) -> None:
        """Main polling loop: check Redis pub/sub and fallback to DB polling."""
        logger.info("Worker loop started, polling interval=%.1fs", self._settings.ORCHESTRATOR_POLL_INTERVAL)

        while self._running:
            try:
                scan_id = await self._dequeue_scan()
                if scan_id:
                    task = asyncio.create_task(self._execute_scan(scan_id))
                    self._active_tasks.add(task)
                    task.add_done_callback(self._active_tasks.discard)
                else:
                    await asyncio.sleep(self._settings.ORCHESTRATOR_POLL_INTERVAL)
            except asyncio.CancelledError:
                logger.info("Worker loop cancelled")
                break
            except Exception:
                logger.exception("Unexpected error in worker loop")
                await asyncio.sleep(self._settings.ORCHESTRATOR_POLL_INTERVAL)

    async def _dequeue_scan(self) -> str | None:
        """Attempt to dequeue a scan from Redis, falling back to DB polling."""
        if self._redis:
            try:
                result = await self._redis.lpop("redhills:scan_queue")  # type: ignore[misc]
                if result:
                    logger.info("Dequeued scan %s from Redis", result)
                    return str(result)
            except Exception:
                logger.debug("Redis unavailable, falling back to DB poll")

        return await self._poll_database()

    async def _poll_database(self) -> str | None:
        """Poll the database for the oldest QUEUED scan and claim it atomically."""
        factory = get_session_factory()
        async with factory() as session:
            stmt = (
                select(Scan)
                .where(Scan.status == ScanStatus.QUEUED)
                .order_by(Scan.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            result = await session.execute(stmt)
            scan = result.scalar_one_or_none()

            if scan is None:
                return None

            scan.status = ScanStatus.PROCESSING
            scan.start_time = datetime.now(timezone.utc)
            await session.commit()
            logger.info("Claimed scan %s from database", scan.id)
            return scan.id

    async def _execute_scan(self, scan_id: str) -> None:
        """Run a full scan lifecycle under the concurrency semaphore."""
        async with self._semaphore:
            logger.info("Executing scan %s (semaphore acquired)", scan_id)
            try:
                await self._mark_processing(scan_id)
                target = await self._load_target_for_scan(scan_id)

                if target is None:
                    await self._mark_failed(scan_id, "Target not found for scan")
                    return

                auth_headers = self._parse_auth_headers(target.auth_headers)

                async with EndpointDiscoverer(
                    target_url=target.target_url,
                    auth_headers=auth_headers,
                ) as discoverer:
                    discovery_report = await discoverer.run_discovery()

                logger.info(
                    "Discovery for scan %s complete: score=%.1f",
                    scan_id,
                    discovery_report.attack_surface_score,
                )

                if not discovery_report.reachable_endpoints:
                    await self._mark_failed(
                        scan_id, "No reachable AI endpoints discovered"
                    )
                    return

                agent_loop = AdversarialAgentLoop(
                    scan_id=scan_id,
                    target_url=target.target_url,
                    auth_headers=auth_headers,
                    discovery_report=discovery_report,
                )
                await agent_loop.run()

                await self._mark_completed(scan_id)

            except Exception as exc:
                logger.exception("Scan %s failed with exception", scan_id)
                await self._mark_failed(scan_id, str(exc))

    async def _load_target_for_scan(self, scan_id: str) -> Target | None:
        """Load the target associated with a scan."""
        async with get_db_session() as session:
            stmt = select(Scan).where(Scan.id == scan_id)
            result = await session.execute(stmt)
            scan = result.scalar_one_or_none()
            if scan is None:
                return None

            stmt_target = select(Target).where(Target.id == scan.target_id)
            result_target = await session.execute(stmt_target)
            return result_target.scalar_one_or_none()

    @staticmethod
    def _parse_auth_headers(auth_headers_raw: str | None) -> dict[str, str]:
        """Parse encrypted JSON auth headers string."""
        if not auth_headers_raw:
            return {}
        import json
        try:
            return json.loads(auth_headers_raw)
        except (json.JSONDecodeError, TypeError):
            logger.warning("Failed to parse auth_headers, using empty dict")
            return {}

    async def _mark_processing(self, scan_id: str) -> None:
        """Update scan status to PROCESSING with timestamp."""
        async with get_db_session() as session:
            stmt = (
                update(Scan)
                .where(Scan.id == scan_id)
                .where(Scan.status != ScanStatus.PROCESSING)
                .values(
                    status=ScanStatus.PROCESSING,
                    start_time=datetime.now(timezone.utc),
                )
            )
            await session.execute(stmt)

    async def _mark_completed(self, scan_id: str) -> None:
        """Mark a scan as successfully completed."""
        async with get_db_session() as session:
            stmt = (
                update(Scan)
                .where(Scan.id == scan_id)
                .values(
                    status=ScanStatus.COMPLETED,
                    end_time=datetime.now(timezone.utc),
                )
            )
            await session.execute(stmt)
        logger.info("Scan %s marked COMPLETED", scan_id)

    async def _mark_failed(self, scan_id: str, error: str) -> None:
        """Mark a scan as failed with an error message."""
        async with get_db_session() as session:
            stmt = (
                update(Scan)
                .where(Scan.id == scan_id)
                .values(
                    status=ScanStatus.FAILED,
                    error_message=error,
                    end_time=datetime.now(timezone.utc),
                )
            )
            await session.execute(stmt)
        logger.error("Scan %s marked FAILED: %s", scan_id, error)


async def run_orchestrator() -> None:
    """Entry point for starting the orchestrator as a standalone process."""
    orchestrator = ScanOrchestrator()
    try:
        await orchestrator.start()
    except KeyboardInterrupt:
        logger.info("Orchestrator interrupted")
    finally:
        await orchestrator.stop()
