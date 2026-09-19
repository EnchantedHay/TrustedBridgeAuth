#!/usr/bin/env python3
"""Synthetic TLS and login checks against a disposable loopback Velocity proxy."""
from pathlib import Path
import json
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def binding_test(root, data, classpath):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(root / "https.key"), "-out", str(root / "https.crt"),
                    "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["keytool", "-importcert", "-noprompt", "-alias", "fixture", "-file", str(root / "https.crt"),
                    "-keystore", str(root / "https.p12"), "-storepass", "fixturepass"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    calls = []

    class IdentityFixture(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert self.headers["Authorization"] == "Bearer " + "a" * 64
            calls.append((self.path, body))
            if self.path == "/candidate":
                result = {"candidate": True}
            elif self.path == "/verify-login":
                assert body["username"] == "AuditUser" and body["server_id"]
                result = {"code": "012345"}
            else:
                raise AssertionError(self.path)
            payload = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), IdentityFixture)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(root / "https.crt", root / "https.key")
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = (data / "config.properties").read_text().replace("identity-mode=premium", "identity-mode=local")
    config += f"skin-api-url=https://127.0.0.1:{server.server_port}/\nskin-api-secret-file=skin-api.secret\n"
    (data / "config.properties").write_text(config)
    (data / "skin-api.secret").write_text("a" * 64)
    try:
        with (root / "binding.log").open("w") as log:
            process = subprocess.Popen(["java", "-Xmx128m", "-XX:ActiveProcessorCount=2",
                                        f"-Djavax.net.ssl.trustStore={root / 'https.p12'}",
                                        "-Djavax.net.ssl.trustStorePassword=fixturepass", "-jar", "velocity.jar"],
                                       cwd=root, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 30
                while "Done (" not in (root / "binding.log").read_text():
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("Binding test proxy unavailable")
                    time.sleep(0.2)
                subprocess.run(["java", "-cp", classpath,
                                "top.pkumc.trustedbridgeauth.PremiumBindingIntegrationTest"], check=True, timeout=20)
                assert [path for path, _ in calls] == ["/candidate", "/verify-login"]
                print("PASS: encrypted premium binding login and authenticated HTTPS API", flush=True)
            except BaseException:
                print((root / "binding.log").read_text()[-6000:])
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                process.stdin.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def main():
    project = Path(__file__).resolve().parent
    core = Path(os.environ.get("VELOCITY_JAR", project.parent.parent / "velocity/velocity-4.2.1-SNAPSHOT-31.jar")).resolve()
    version = json.loads((project / "src/main/resources/velocity-plugin.json").read_text())["version"]
    for port in (32565, 32566, 32570):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    subprocess.run([str(project / "build.sh")], check=True)
    with tempfile.TemporaryDirectory(prefix="bridge-integration-") as tmp:
        root = Path(tmp)
        data = root / "plugins/trusted-bridge-auth"
        data.mkdir(parents=True)
        shutil.copy2(core, root / "velocity.jar")
        shutil.copy2(project / f"build/libs/TrustedBridgeAuth-{version}.jar", root / "plugins")
        subprocess.run(["python3", str(project / "provision-tls.py"), str(root / "keys")], check=True)
        classpath = ":".join(map(str, [core, project / "build/classes/main", project / "build/classes/test"]))
        subprocess.run(["java", "-Xmx96m", "-XX:ActiveProcessorCount=2", "-cp", classpath,
                        "top.pkumc.trustedbridgeauth.BridgeLinkTest", str(root / "keys")], check=True, timeout=90)
        shutil.copytree(root / "keys/thunion", data / "tls")
        (root / "trusted-bridge.secret").write_text(secrets.token_hex(32))
        (root / "forwarding.secret").write_text(secrets.token_hex(32))
        (data / "config.properties").write_text(
            "network-id=thunion\npeer-id=pkumc\nbridge-role=listen\n"
            "bridge-port=32566\nbridge-listen-address=127.0.0.1\n"
            "handoff-secret-file=trusted-bridge.secret\n"
            "transfer-host=127.0.0.1\ntransfer-port=32565\nidentity-mode=premium\n"
        )
        (root / "velocity.toml").write_text('''config-version = "2.9"
bind = "127.0.0.1:32565"
online-mode = true
force-key-authentication = true
player-info-forwarding-mode = "modern"
forwarding-secret-file = "forwarding.secret"
[servers]
fabric = "127.0.0.1:32570"
pkumc = "127.0.0.1:1"
try = ["fabric"]
[forced-hosts]
[advanced]
accepts-transfers = true
login-ratelimit = 3000
[query]
enabled = false
''')
        log_path = root / "console.log"
        with log_path.open("w") as log:
            process = subprocess.Popen(
                ["java", "-Xms32m", "-Xmx128m", "-XX:ActiveProcessorCount=2", "-Dterminal.jline=false",
                 "-Dterminal.ansi=false", "-jar", "velocity.jar"],
                cwd=root, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    output = log_path.read_text()
                    if process.poll() is not None:
                        raise RuntimeError("Isolated proxy exited during startup")
                    if "Done (" in output and "TrustedBridgeAuth ready" in output:
                        break
                    time.sleep(0.2)
                else:
                    raise RuntimeError("Isolated proxy did not become ready")
                for protocol in (766, 774, 776):
                    subprocess.run(
                        ["java", "-Xmx96m", "-XX:ActiveProcessorCount=2", "-cp", classpath,
                         "top.pkumc.trustedbridgeauth.LoginIntegrationTest",
                         str(root / "trusted-bridge.secret"), str(protocol), "127.0.0.1", "32566",
                         "127.0.0.1", "32565", "pkumc", "thunion", str(root / "keys/pkumc")],
                        check=True, timeout=50,
                    )
                    print(f"PASS: protocol {protocol}", flush=True)
                    time.sleep(3.1)
            except BaseException:
                print(log_path.read_text()[-8000:])
                raise
            finally:
                if process.poll() is None:
                    try:
                        process.stdin.write(b"end\n")
                        process.stdin.flush()
                        process.wait(timeout=8)
                    except (BrokenPipeError, subprocess.TimeoutExpired):
                        process.terminate()
                        try:
                            process.wait(timeout=8)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                process.stdin.close()
        binding_test(root, data, classpath)


if __name__ == "__main__":
    main()
