#!/usr/bin/env python3
"""Threaded static payload HTTP server for latency labs."""

from __future__ import annotations

import argparse
import http.server
import signal
from dataclasses import dataclass


PAYLOAD_SIZES = {
    "/": 1024,
    "/1k": 1024,
    "/4k": 4 * 1024,
    "/16k": 16 * 1024,
    "/64k": 64 * 1024,
    "/1m": 1024 * 1024,
}


@dataclass(frozen=True)
class ServerConfig:
    host: str
    port: int


class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class PayloadHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    payloads = {path: b"x" * size for path, size in PAYLOAD_SIZES.items()}

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        body = self.payloads.get(path, self.payloads["/"])
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


def parse_args() -> ServerConfig:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    return ServerConfig(host=args.host, port=args.port)


def main() -> None:
    cfg = parse_args()
    httpd = ThreadingHTTPServer((cfg.host, cfg.port), PayloadHandler)
    signal.signal(signal.SIGTERM, lambda *_: httpd.shutdown())
    signal.signal(signal.SIGINT, lambda *_: httpd.shutdown())
    httpd.serve_forever()


if __name__ == "__main__":
    main()
