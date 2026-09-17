import asyncio
import json
from pathlib import Path
from typing import Dict, Optional, List

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend import database
from backend.collectors.registry import get_collectors, estimate_total, VALID_TYPES
from backend.collectors.username.site_checker import list_categories, site_count

app = FastAPI(title="Footprint Engine", version="0.2.0")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

POLL_INTERVAL_SECONDS = 0.3


@app.on_event("startup")
async def startup() -> None:
    database.init_db()


class ScanRequest(BaseModel):
    indicator: str
    indicator_type: str  # username, email, phone, ip
    categories: Optional[List[str]] = None


@app.get("/api/v1/username/categories")
async def get_categories():
    cats = list_categories()
    return {"categories": cats, "total_sites": site_count()}


@app.post("/api/v1/scan")
async def start_scan(req: ScanRequest):
    raw_indicator = req.indicator
    if req.indicator_type == "password":
        # Passwords are used only transiently to compute a check -- never
        # written to disk. Everything else gets its normal trimmed value.
        indicator_for_check = raw_indicator
        indicator_for_storage = "[redacted]"
    else:
        indicator_for_check = raw_indicator.strip()
        indicator_for_storage = indicator_for_check

    if not indicator_for_check:
        raise HTTPException(status_code=400, detail="indicator is required")
    if req.indicator_type not in VALID_TYPES:
        raise HTTPException(status_code=400, detail=f"indicator_type must be one of {VALID_TYPES}")

    collectors = get_collectors(req.indicator_type)
    if not collectors:
        raise HTTPException(status_code=501, detail=f"No collectors registered for '{req.indicator_type}' yet")

    total = estimate_total(req.indicator_type, indicator_for_check, categories=req.categories)
    scan_id = database.create_scan(indicator_for_storage, req.indicator_type, total_sources=total)

    asyncio.create_task(_run_scan(scan_id, indicator_for_check, collectors, req.categories))

    return {"scan_id": scan_id, "indicator": indicator_for_storage, "indicator_type": req.indicator_type, "total_sources": total}


async def _run_scan(
    scan_id: str,
    indicator: str,
    collectors: List,
    categories: Optional[List[str]],
) -> None:
    """
    Runs every collector for this indicator concurrently and persists each
    result to SQLite as it arrives. Deliberately does NOT push to any
    in-memory queue -- the SSE endpoint below polls the database instead,
    which avoids a race where a fast scan's results get delivered twice to
    a client that connects right as the scan finishes (once via replay,
    once via a still-unconsumed queue item).
    """
    async def consume(collector) -> None:
        try:
            async for result in collector.run(indicator, categories=categories):
                database.add_result(scan_id, result)
        except Exception as e:
            # A collector misbehaving should never take down the whole scan.
            database.add_result(scan_id, {
                "source": getattr(collector, "name", "unknown_collector"),
                "category": "system",
                "status": "error",
                "url": "",
                "details": {"reason": f"collector_crashed: {str(e)[:200]}"},
            })

    try:
        await asyncio.gather(*(consume(c) for c in collectors))
    finally:
        database.finish_scan(scan_id, status="completed")


@app.get("/api/v1/stream/{scan_id}")
async def stream_scan(scan_id: str):
    scan = database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")

    async def event_generator():
        last_id = 0
        while True:
            new_rows = database.get_results_since(scan_id, last_id)
            for row in new_rows:
                last_id = max(last_id, row["id"])
                yield f"data: {json.dumps(row)}\n\n"

            current = database.get_scan(scan_id)
            if current and current["status"] == "completed" and not new_rows:
                yield "event: done\ndata: {}\n\n"
                break

            await asyncio.sleep(POLL_INTERVAL_SECONDS)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/v1/scan/{scan_id}")
async def get_scan_detail(scan_id: str):
    scan = database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    results = database.get_results(scan_id)
    return {"scan": scan, "results": results}


@app.get("/api/v1/scans")
async def list_recent_scans(limit: int = Query(25, ge=1, le=100)):
    return {"scans": database.recent_scans(limit)}


# --- Static frontend ---

app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/")
async def index():
    return FileResponse(str(FRONTEND_DIR / "index.html"))
