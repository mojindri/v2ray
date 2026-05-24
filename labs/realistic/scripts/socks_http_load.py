#!/usr/bin/env python3
import argparse, asyncio, json, socket, ssl, time, urllib.parse, statistics


def build_connect_request(host: str, port: int) -> bytes:
    host_b = host.encode()
    if len(host_b) > 255:
        raise ValueError("SOCKS domain too long")
    return b"\x05\x01\x00" + bytes([3, len(host_b)]) + host_b + port.to_bytes(2, "big")


async def socks_connect(reader, writer, host, port):
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    data = await reader.readexactly(2)
    if data != b"\x05\x00":
        raise RuntimeError(f"SOCKS auth rejected: {data!r}")
    writer.write(build_connect_request(host, port))
    await writer.drain()
    head = await reader.readexactly(4)
    if head[1] != 0:
        raise RuntimeError(f"SOCKS connect failed rep={head[1]}")
    atyp = head[3]
    if atyp == 1:
        await reader.readexactly(4)
    elif atyp == 3:
        ln = (await reader.readexactly(1))[0]
        await reader.readexactly(ln)
    elif atyp == 4:
        await reader.readexactly(16)
    else:
        raise RuntimeError(f"SOCKS bad atyp={atyp}")
    await reader.readexactly(2)


async def one_request(args, sem, idx):
    async with sem:
        start = time.perf_counter()
        parsed = urllib.parse.urlparse(args.target_url)
        target_host = parsed.hostname
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(args.socks_host, args.socks_port),
                timeout=args.connect_timeout,
            )
            await asyncio.wait_for(socks_connect(reader, writer, target_host, target_port), timeout=args.connect_timeout)
            # HTTPS through SOCKS is intentionally not implemented here because asyncio TLS upgrade
            # varies by Python version. Use http targets for deterministic CI load gates.
            if parsed.scheme != "http":
                raise RuntimeError("only http:// TARGET_URL is supported by this load script")
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {target_host}\r\n"
                "Connection: close\r\n"
                "User-Agent: blackwire-load/1\r\n"
                "\r\n"
            ).encode()
            writer.write(req)
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(4096), timeout=args.read_timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            status_ok = raw.startswith(b"HTTP/1.1 200") or raw.startswith(b"HTTP/1.0 200")
            dur = time.perf_counter() - start
            return {"ok": bool(status_ok), "latency_ms": dur * 1000.0, "error": None if status_ok else "non_200_or_no_http"}
        except Exception as e:
            dur = time.perf_counter() - start
            return {"ok": False, "latency_ms": dur * 1000.0, "error": type(e).__name__ + ": " + str(e)}


def pct(values, p):
    if not values:
        return None
    values = sorted(values)
    k = int(round((p / 100.0) * (len(values) - 1)))
    return values[k]


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socks-host", default="127.0.0.1")
    ap.add_argument("--socks-port", type=int, default=1080)
    ap.add_argument("--target-url", default="http://127.0.0.1:18080/")
    ap.add_argument("--concurrency", type=int, default=100)
    ap.add_argument("--requests", type=int, default=1000)
    ap.add_argument("--connect-timeout", type=float, default=5)
    ap.add_argument("--read-timeout", type=float, default=10)
    ap.add_argument("--json", required=True)
    args = ap.parse_args()
    sem = asyncio.Semaphore(args.concurrency)
    t0 = time.perf_counter()
    tasks = [asyncio.create_task(one_request(args, sem, i)) for i in range(args.requests)]
    results = await asyncio.gather(*tasks)
    elapsed = time.perf_counter() - t0
    oks = [r for r in results if r["ok"]]
    lats = [r["latency_ms"] for r in results]
    errors = {}
    for r in results:
        if not r["ok"]:
            errors[r["error"]] = errors.get(r["error"], 0) + 1
    summary = {
        "target_url": args.target_url,
        "socks": f"{args.socks_host}:{args.socks_port}",
        "requests": args.requests,
        "concurrency": args.concurrency,
        "ok": len(oks),
        "failed": len(results) - len(oks),
        "success_rate": len(oks) / len(results) if results else 0,
        "elapsed_secs": elapsed,
        "requests_per_sec": len(results) / elapsed if elapsed > 0 else None,
        "latency_ms": {"p50": pct(lats, 50), "p95": pct(lats, 95), "p99": pct(lats, 99), "max": max(lats) if lats else None},
        "errors": errors,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    with open(args.json, "w") as f:
        json.dump({"summary": summary, "samples": results[:1000]}, f, indent=2, sort_keys=True)
    if summary["success_rate"] < 0.99:
        raise SystemExit(2)

if __name__ == "__main__":
    asyncio.run(main())
