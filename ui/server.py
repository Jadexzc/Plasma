"""
ui/server.py
-------------
Flask web server for the Plasma dashboard.

Routes:
  GET  /              → dashboard HTML
  GET  /api/scans     → list all scans
  POST /api/scans     → start a new scan
  GET  /api/scans/<id>→ get scan status + findings
  POST /api/scans/<id>/pause|resume|cancel
  GET  /api/detectors → list detectors
  POST /api/upload-file → receive a file for upload testing; returns server path
  GET  /stream/<id>   → Server-Sent Events (per-scan queue — no cross-scan leakage)

Each scan has its own asyncio.Queue so SSE events are never lost or mixed
between concurrent scans.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import queue as _queue
import tempfile
import threading
from pathlib import Path
from typing import Optional

from flask import Flask, Response, jsonify, request, send_from_directory

from config import UI_HOST, UI_PORT, UI_DEBUG, UI_SECRET
from core.detector_registry import DetectorRegistry
from core.models import ScanSettings
from core.scan_manager import ScanManager

log = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"

app  = Flask(__name__, static_folder=str(_STATIC_DIR))
app.secret_key = UI_SECRET

# ── Global manager + event loop ───────────────────────────────────────────────
_manager: Optional[ScanManager] = None
_loop:    Optional[asyncio.AbstractEventLoop] = None


def _get_manager() -> ScanManager:
    global _manager, _loop
    if _manager is None:
        new_loop  = asyncio.new_event_loop()
        _registry = DetectorRegistry()
        _registry.load_all()
        new_manager = ScanManager(registry=_registry)
        t = threading.Thread(target=new_loop.run_forever, daemon=True)
        t.start()
        # Assign atomically after fully initialised
        _loop    = new_loop
        _manager = new_manager
    return _manager


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(str(_STATIC_DIR), "index.html")


@app.route("/api/scans", methods=["GET"])
def list_scans():
    return jsonify({"scans": _get_manager().list_scans()})


@app.route("/api/scans", methods=["POST"])
def start_scan():
    """
    Start a new scan.

    JSON body:
        {
          "target":         "http://...",
          "profile":        "default",
          "depth":          2,
          "timeout":        10,
          "detectors":      ["csrf", "sqli"],   // optional subset
          "generate_poc":   false,
          "report_formats": ["html"]            // [] = no report
        }
    """
    global _loop
    body   = request.get_json(force=True) or {}
    target = body.get("target", "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400

    report_formats = body.get("report_formats", [])
    # Normalise: remove duplicates, lower-case
    report_formats = list(dict.fromkeys(f.lower() for f in report_formats))

    settings = ScanSettings(
        profile=body.get("profile", "default"),
        max_depth=int(body.get("depth", 2)),
        timeout=int(body.get("timeout", 10)),
        enabled_detectors=set(body.get("detectors", [])) or set(),
        generate_poc=bool(body.get("generate_poc", False)),
        report_formats=report_formats,
        # GUI file upload: server path returned by /api/upload-file, or None
        upload_file=body.get("upload_file") or None,
    )

    manager = _get_manager()
    context = manager.create_context(target, settings)

    # Non-blocking: run scan in the background event loop
    asyncio.run_coroutine_threadsafe(manager.scan(context), _loop)

    return jsonify({"scan_id": context.scan_id, "status": "started"}), 202


@app.route("/api/scans/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    manager = _get_manager()
    ctx     = manager.get_context(scan_id)
    if not ctx:
        return jsonify({"error": "scan not found"}), 404
    return jsonify({
        "summary":  ctx.to_summary_dict(),
        "findings": [f.to_dict() for f in ctx.findings],
        "log":      list(ctx.history)[-50:],
    })


@app.route("/api/scans/<scan_id>/pause", methods=["POST"])
def pause_scan(scan_id: str):
    return jsonify({"ok": _get_manager().pause(scan_id)})


@app.route("/api/scans/<scan_id>/resume", methods=["POST"])
def resume_scan(scan_id: str):
    return jsonify({"ok": _get_manager().resume(scan_id)})


@app.route("/api/scans/<scan_id>/cancel", methods=["POST"])
def cancel_scan(scan_id: str):
    return jsonify({"ok": _get_manager().cancel(scan_id)})


@app.route("/api/upload-file", methods=["POST"])
def upload_file_for_scan():
    """
    Receive a file from the GUI file picker and save it to a temporary
    directory on the server.  Returns the server-side path so the scan
    API can pass it through to ScanSettings.upload_file — the same field
    the CLI --upload flag uses.

    Multipart form field name: ``file``
    Returns: { "path": "/tmp/.../filename.ext" } or { "error": "..." }
    """
    if "file" not in request.files:
        return jsonify({"error": "No file field in request"}), 400

    f = request.files["file"]
    filename = f.filename or ""
    if not filename:
        return jsonify({"error": "Empty filename"}), 400

    # Sanitise: keep only the basename, reject path traversal attempts
    safe_name = os.path.basename(filename)
    if not safe_name:
        return jsonify({"error": "Invalid filename"}), 400

    try:
        tmp_dir = tempfile.mkdtemp(prefix="plasma_upload_")
        dest    = os.path.join(tmp_dir, safe_name)
        f.save(dest)
        log.info("GUI upload saved: %s", dest)
        return jsonify({"path": dest, "filename": safe_name}), 200
    except Exception as exc:
        log.error("GUI upload failed: %s", exc)
        return jsonify({"error": f"Upload failed: {exc}"}), 500


@app.route("/api/detectors", methods=["GET"])
def list_detectors():
    return jsonify({"detectors": _get_manager()._registry.list_all()})


@app.route("/stream/<scan_id>")
def stream(scan_id: str):
    """
    Server-Sent Events stream for one scan.
    Uses the per-scan asyncio.Queue — zero cross-scan leakage.
    """
    manager = _get_manager()

    def _generate():
        import time

        # Confirm the scan exists
        ctx = manager.get_context(scan_id)
        if ctx is None:
            yield f"data: {json.dumps({'type': 'error', 'data': {'msg': 'Scan not found'}})}\n\n"
            return

        yield f"data: {json.dumps({'type': 'connected', 'scan_id': scan_id})}\n\n"

        q = manager.get_scan_queue(scan_id)
        if q is None:
            yield f"data: {json.dumps({'type': 'error', 'data': {'msg': 'No event queue'}})}\n\n"
            return

        finished = False
        while not finished:
            # Drain available events from the per-scan queue
            drained = 0
            while drained < 50:  # batch up to 50 per iteration
                try:
                    event = q.get_nowait()
                    yield f"data: {json.dumps(event)}\n\n"
                    if event.get("type") in ("scan_finished",):
                        finished = True
                    drained += 1
                except _queue.Empty:
                    break

            if not finished:
                # Check if scan is already done (in case we missed the event)
                ctx_check = manager.get_context(scan_id)
                if ctx_check and ctx_check.state.value in (
                    "completed", "failed", "cancelled"
                ):
                    # Drain remaining events then finish
                    while True:
                        try:
                            event = q.get_nowait()
                            yield f"data: {json.dumps(event)}\n\n"
                        except _queue.Empty:
                            break
                    finished = True
                    yield f"data: {json.dumps({'type': 'scan_finished', 'scan_id': scan_id, 'data': {'state': ctx_check.state.value}})}\n\n"
                else:
                    time.sleep(0.15)
                    yield ": heartbeat\n\n"

    return Response(
        _generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def run_server(host: str = UI_HOST, port: int = UI_PORT, debug: bool = UI_DEBUG) -> None:
    """Start the Flask development server."""
    _get_manager()  # pre-init manager + event loop
    log.info("Plasma UI: http://%s:%d", host, port)
    app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)


if __name__ == "__main__":
    run_server()
