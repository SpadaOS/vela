"""Exercise a specific Vela executable, including extracted release packages.

Only Python's standard library is required. Every child has a deadline and
every assertion checks the artifact or bytes produced by the guest.
"""

import argparse
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
from pathlib import Path
import subprocess
import socket
import struct
import threading
import tarfile
import tempfile
import time


def verify_dynamic_fixture(guests):
    """Reject substituted static PIE and changed executable/loader fixtures."""
    expected = {
        "hello-dyn": "93e1eeae49d6741ffc8d70df4469e0a733075a8930f0a825fcf1aaea2566199e",
        "ld-musl-x86_64.so.1": "dfa50f37956bd60a1d3c53d844154129881c2e46a81b032136ca1e91ee796512",
    }
    data = (guests / "hello-dyn").read_bytes()
    assert data[:6] == b"\x7fELF\x02\x01", "hello-dyn: expected ELF64 little endian"
    assert struct.unpack_from("<H", data, 18)[0] == 62, "hello-dyn: expected x86_64"
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    assert size == 56 and offset + size * count <= len(data), "hello-dyn: invalid program headers"
    interpreters = []
    for index in range(count):
        header = struct.unpack_from("<IIQQQQQQ", data, offset + index * size)
        if header[0] == 3:  # PT_INTERP
            start, length = header[2], header[5]
            assert start + length <= len(data), "hello-dyn: invalid PT_INTERP"
            interpreters.append(data[start:start + length])
    assert interpreters == [b"/lib/ld-musl-x86_64.so.1\0"], "hello-dyn: missing musl PT_INTERP (static PIE is not dynamic coverage)"
    for name, digest in expected.items():
        assert hashlib.sha256((guests / name).read_bytes()).hexdigest() == digest, f"dynamic musl fixture changed: {name}"
    return {"interpreter": "/lib/ld-musl-x86_64.so.1", "sha256": expected}


class Harness:
    def __init__(self, exe, guests, report, timeout=30):
        self.exe = Path(exe).resolve(strict=True)
        self.guests = Path(guests).resolve(strict=True)
        self.report = Path(report).resolve()
        self.report.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.results = []
        self.dynamic_fixture = None

    def run(self, label, args, *, expected=0, stdin=None):
        command = [str(self.exe), *map(str, args)]
        started = time.monotonic()
        process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = process.communicate(stdin, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            # Guest fork children are native Windows processes too.
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           capture_output=True, timeout=10)
            process.kill()
            stdout, stderr = process.communicate(timeout=10)
            (self.report / f"{label}.stdout").write_bytes(stdout)
            (self.report / f"{label}.stderr").write_bytes(stderr)
            raise AssertionError(f"{label}: deadline exceeded ({self.timeout}s)")
        (self.report / f"{label}.stdout").write_bytes(stdout)
        (self.report / f"{label}.stderr").write_bytes(stderr)
        self.results.append(dict(label=label, command=command, exit=process.returncode,
                                 seconds=round(time.monotonic() - started, 3)))
        if expected is not None and process.returncode != expected:
            raise AssertionError(f"{label}: exit {process.returncode}, expected {expected}; "
                                 f"stderr={stderr[-3000:]!r}")
        return stdout, stderr, process.returncode

    def guest(self, label, name, *args, root=None, trap="auto", **kwargs):
        options = ["run", "--soft-tls", f"--trap={trap}"]
        if root is not None:
            options += ["--root", str(root)]
        return self.run(label, [*options, (self.guests / name).as_posix(), *args], **kwargs)

    def busybox(self, network=False):
        with tempfile.TemporaryDirectory(prefix="vela-acceptance-") as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "bin").mkdir()
            (root / "bin/busybox").write_bytes((self.guests / "busybox").read_bytes())
            source = b"needle\nother\n" + bytes(range(256)) * 32
            (root / "data/input.bin").write_bytes(source)
            (root / "data/input.txt").write_bytes(b"needle\nother\n")

            def busy(label, *args, **kwargs):
                return self.guest(label, "busybox", *args, root=root, **kwargs)

            out, _, _ = busy("grep", "grep", "needle", "/data/input.txt")
            assert out == b"needle\n", f"grep: wrong bytes {out!r}"
            out, _, _ = busy("find", "find", "/data", "-name", "input.txt")
            assert out.strip() == b"/data/input.txt", f"find: {out!r}"
            out, _, _ = busy("gzip", "gzip", "-c", "/data/input.bin")
            assert gzip.decompress(out) == source, "gzip: corrupt or incomplete output"
            (root / "data/input.gz").write_bytes(out)
            out, _, _ = busy("gunzip", "gzip", "-dc", "/data/input.gz")
            assert out == source, "gunzip: byte mismatch"
            out, _, _ = busy("gzip-pipe", "sh", "-c", "cat /data/input.bin | gzip -c")
            assert gzip.decompress(out) == source, "gzip pipeline: byte mismatch"
            busy("tar-create", "tar", "-cf", "/data/archive.tar", "/data/input.bin")
            with tarfile.open(root / "data/archive.tar") as archive:
                member = archive.getmembers()[0]
                assert archive.extractfile(member).read() == source, "tar: content mismatch"
            (root / "data/input.bin").unlink()
            busy("tar-extract", "tar", "-xf", "/data/archive.tar", "-C", "/")
            assert (root / "data/input.bin").read_bytes() == source, "tar extract: mismatch"
            # The shell may hide the producer's exit; content must still fail.
            out, _, _ = busy("pipeline-failure", "sh", "-c",
                             "cat /data/missing | gzip -c", expected=None)
            try:
                decoded = gzip.decompress(out)
            except (EOFError, gzip.BadGzipFile):
                decoded = b""
            assert decoded != source, "failure injection unexpectedly matched fixture"
            (root / "data/bad.gz").write_bytes(b"not a gzip stream")
            _, _, code = busy("gzip-corrupt", "gzip", "-dc", "/data/bad.gz", expected=None)
            assert code != 0, "gzip must reject corrupt input"
            if network:
                self.network(root, busy)

    def network(self, root, busy):
        payload = bytes(range(256)) * 129 + b"Vela loopback HTTP\n"

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/missing":
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload) + (100 if self.path == "/short" else 0)))
                self.end_headers()
                self.wfile.write(payload)
                self.wfile.flush()
                self.close_connection = True

            def log_message(self, *args):
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            server.daemon_threads = True
            ready = threading.Event()

            def serve():
                ready.set()
                server.serve_forever(poll_interval=0.05)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            if not ready.wait(5):
                raise AssertionError("HTTP server did not become ready")
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                busy("wget", "wget", "-O", "/data/download.bin", base + "/payload")
                actual = (root / "data/download.bin").read_bytes()
                assert hashlib.sha256(actual).digest() == hashlib.sha256(payload).digest(), "wget: download hash mismatch"
                for endpoint in ("missing", "short"):
                    _, _, code = busy(f"wget-{endpoint}", "wget", "-O", "/data/failure.bin", base + "/" + endpoint, expected=None)
                    assert code != 0, f"wget: {endpoint} must fail"
            finally:
                server.shutdown()
                worker.join(timeout=5)
                assert not worker.is_alive(), "HTTP server failed to stop"

        request = b"Vela nc request\n" + bytes(range(256))*4
        response = b"Vela nc response\n" + bytes(range(255,-1,-1))*4
        errors = []
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10)

            def tcp_server():
                try:
                    with listener.accept()[0] as connection:
                        connection.settimeout(10)
                        connection.sendall(response)
                        connection.shutdown(socket.SHUT_WR)
                        received = bytearray()
                        while len(received) < len(request):
                            chunk = connection.recv(4096)
                            if not chunk:
                                break
                            received.extend(chunk)
                        assert received == request, "nc: request bytes mismatch"
                except BaseException as error:
                    errors.append(error)

            worker = threading.Thread(target=tcp_server, daemon=True)
            worker.start()
            try:
                stdout, _, _ = busy("nc", "nc", "127.0.0.1", str(listener.getsockname()[1]), stdin=request)
                assert stdout == response, f"nc: wrong response bytes ({len(stdout)})"
            finally:
                worker.join(timeout=12)
                assert not worker.is_alive(), "TCP server failed to stop"
            if errors:
                raise errors[0]

    def save(self, error=None):
        payload = dict(executable=str(self.exe), guests=str(self.guests),
                       sha256=hashlib.sha256(self.exe.read_bytes()).hexdigest(),
                       guest_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in self.guests.iterdir() if p.is_file()},
                       passed=error is None, error=error, checks=self.results)
        payload["dynamic_fixture"] = self.dynamic_fixture
        (self.report / "acceptance.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe")
    parser.add_argument("--guests", required=True)
    parser.add_argument("--report", default="release/validation")
    parser.add_argument("--busybox", action="store_true")
    parser.add_argument("--threads", action="store_true")
    parser.add_argument("--signals", action="store_true")
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--check-fixtures", action="store_true")
    args = parser.parse_args()
    if args.check_fixtures:
        print(json.dumps(verify_dynamic_fixture(Path(args.guests)), indent=2))
        return
    if not args.exe:
        parser.error("--exe is required unless --check-fixtures is used")
    harness = Harness(args.exe, args.guests, args.report)
    try:
        harness.dynamic_fixture = verify_dynamic_fixture(harness.guests)
        harness.run("version", ["--version"])
        doctor, _, _ = harness.run("doctor", ["doctor"])
        assert b"missing" not in doctor, "doctor: missing packaged assets"
        for trap in ("auto", "veh", "island"):
            _, trace, _ = harness.run(f"island-{trap}", ["run", f"--trap={trap}", "-v", str(harness.guests/"island-test")])
            if trap != "veh":
                assert re.search(rb"island trampoline: [1-9][0-9]* sites", trace), "island test silently fell back to VEH"
        for trap in ("auto", "veh", "island"):
            stdout, trace, _ = harness.run(f"hello-dyn-{trap}", ["run", "--soft-tls", f"--trap={trap}", "-v", str(harness.guests/"hello-dyn")])
            assert stdout == b"hello from musl\n", "dynamic musl: incorrect guest output"
            assert b"interp /lib/ld-musl-x86_64.so.1" in trace, "dynamic musl: loader was not executed"
        for name in ("hello", "torture", "tls", "hello-musl", "file-io", "fs-exec", "fork-test"):
            if name == "file-io":
                with tempfile.TemporaryDirectory(prefix="vela-file-io-") as directory:
                    (Path(directory) / "mnt/c/Windows/Temp").mkdir(parents=True)
                    harness.guest(name, name, root=directory)
            else:
                harness.guest(name, name)
        out, _, _ = harness.guest("pipe-a", "pipe-a")
        piped, _, _ = harness.guest("pipe-b", "pipe-b", stdin=out)
        assert b"29 bytes, 3 lines" in piped, f"pipe output mismatch: {piped!r}"
        for enabled, names in ((args.threads, ["pthread-test"]),
                               (args.signals, ["signal-test", "signal-wait-test", "signal-lifecycle-test"]),
                               (args.network, ["socket-test", "socket-edge-test", "network-concurrency-test", "epoll-test"])):
            if enabled:
                for name in names:
                    for trap in ("auto", "veh"):
                        for iteration in range(3):
                            harness.guest(f"{name}-{trap}-{iteration}", name, trap=trap)
        if args.busybox:
            harness.busybox(network=args.network)
    except BaseException as error:
        harness.save(str(error))
        raise
    harness.save()
    print(f"acceptance passed: {len(harness.results)} checks; report: {harness.report}")


if __name__ == "__main__":
    main()
