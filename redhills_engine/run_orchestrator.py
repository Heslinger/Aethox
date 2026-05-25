"""Entry point for running the scan orchestrator as a standalone process."""

import asyncio
import logging
import sys

from redhills_engine.config import get_settings


def main() -> None:
    """Initialize logging and start the orchestrator event loop."""
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
    )
    logger = logging.getLogger(__name__)
    logger.info("Starting Red Hills Orchestrator")

    from redhills_engine.core.orchestrator import run_orchestrator
    asyncio.run(run_orchestrator())


if __name__ == "__main__":
    main()
