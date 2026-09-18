#!/usr/bin/env python3
"""Separate EC identities and reciprocal certificate pins in a new private directory."""
from pathlib import Path
import argparse
import os
import secrets
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path)
args = parser.parse_args()
root = args.output.resolve()
if root.exists():
    raise SystemExit("Output already exists; refusing to replace bridge identities")
os.umask(0o077)
root.mkdir(parents=True)
for name in ("pkumc", "thunion"):
    folder = root / name
    folder.mkdir()
    password = folder / "store.password"
    password.write_text(secrets.token_hex(32))
    subprocess.run(["keytool", "-genkeypair", "-alias", name, "-keyalg", "EC", "-groupname", "secp256r1",
                    "-dname", f"CN={name}", "-validity", "825", "-storetype", "PKCS12",
                    "-keystore", str(folder / "identity.p12"), "-storepass:file", str(password),
                    "-ext", "KU=digitalSignature", "-ext", "EKU=serverAuth,clientAuth"], check=True)
    subprocess.run(["keytool", "-exportcert", "-rfc", "-alias", name,
                    "-keystore", str(folder / "identity.p12"), "-storepass:file", str(password),
                    "-file", str(folder / "public.crt")], check=True)
for name, peer in (("pkumc", "thunion"), ("thunion", "pkumc")):
    shutil.copy2(root / peer / "public.crt", root / name / "peer.crt")
print("Created separate private identities with reciprocal certificate pins (825 days)")
