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
            "transfer-host=127.0.0.1\ntransfer-port=32565\nidentity-mode=source\n"
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


if __name__ == "__main__":
    main()
