# AGENTS.md

## Cursor Cloud specific instructions

This repository contains the **Red Hills Research** AI Red Teaming Engine backend — an async Python platform built with FastAPI, SQLAlchemy, and Redis.

### Services

| Service | Purpose | How to run |
|---------|---------|------------|
| Egress Monitor | OOB leak detection FastAPI server | `uvicorn redhills_engine.egress.monitor:app --host 0.0.0.0 --port 9090` |
| Orchestrator | Async scan worker daemon | `python -m redhills_engine.run_orchestrator` |

### Key Commands

- **Install deps:** `pip install -r requirements.txt`
- **Run tests:** `pytest tests/ -v`
- **Lint:** `ruff check redhills_engine/ tests/`
- **Type check:** `mypy redhills_engine/ --ignore-missing-imports --no-strict-optional`
- **Start egress monitor (dev):** `uvicorn redhills_engine.egress.monitor:app --reload --port 9090`

### Development Notes

- Uses SQLite (`sqlite+aiosqlite://`) for local dev (via `.env`). Production targets PostgreSQL with `asyncpg`.
- No external Redis/Postgres required for running tests — the test suite uses SQLite in-memory and hits the local egress monitor on port 9090.
- The egress monitor must be running on port 9090 for E2E tests (`tests/test_e2e_flow.py`) to pass.
- `PATH` must include `$HOME/.local/bin` for `pip install --user` binaries (uvicorn, pytest, ruff, mypy).
