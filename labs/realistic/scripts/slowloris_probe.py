#!/usr/bin/env python3
import argparse
import socket
import threading
import time
import json


def slow_socks_client(host, port, interval, duration, idx, results):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        started = time.time()
        s.connect((host, port))
        sent = 0
        payload = [b"\x05", b"\x01", b"\x00"]
        while time.time() - started < duration:
            try:
                s.sendall(payload[sent % len(payload)])
                sent += 1
            except BrokenPipeError:
                results[idx] = {"closed": True, "sent": sent, "seconds": time.time() - started}
                return
            except ConnectionResetError:
                results[idx] = {"closed": True, "sent": sent, "seconds": time.time() - started}
                return
            time.sleep(interval)
        results[idx] = {"closed": False, "sent": sent, "seconds": time.time() - started}
    except Exception as e:
        results[idx] = {"error": repr(e)}
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1080)
    ap.add_argument("--clients", type=int, default=25)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--duration", type=float, default=15.0)
    ap.add_argument("--expect-close", action="store_true")
    args = ap.parse_args()

    results = [None] * args.clients
    threads = []
    for i in range(args.clients):
        t = threading.Thread(
            target=slow_socks_client,
            args=(args.host, args.port, args.interval, args.duration, i, results),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    closed = sum(1 for r in results if r and r.get("closed"))
    open_ = sum(1 for r in results if r and r.get("closed") is False)
    errors = sum(1 for r in results if r and "error" in r)

    report = {
        "clients": args.clients,
        "closed": closed,
        "still_open_after_duration": open_,
        "errors": errors,
        "duration": args.duration,
        "interval": args.interval,
        "results": results,
    }
    print(json.dumps(report, indent=2))

    if args.expect_close and open_ > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
