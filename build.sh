#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
api="${VELOCITY_JAR:-../../velocity/velocity-4.2.1-SNAPSHOT-31.jar}"
version="$(python3 -c 'import json; print(json.load(open("src/main/resources/velocity-plugin.json"))["version"])')"
mkdir -p build/classes/main build/classes/test build/libs
find build/classes -type f -delete
mapfile -t main_sources < <(find src/main/java -name '*.java' -print)
mapfile -t test_sources < <(find src/test/java -name '*.java' -print)
javac --release 21 -cp "$api" -d build/classes/main "${main_sources[@]}"
javac --release 21 -cp "$api:build/classes/main" -d build/classes/test "${test_sources[@]}"
java -cp "$api:build/classes/main:build/classes/test" top.pkumc.trustedbridgeauth.HandoffProtocolTest
java -cp "$api:build/classes/main:build/classes/test" top.pkumc.trustedbridgeauth.BridgeStatusTest
jar --create --file "build/libs/TrustedBridgeAuth-$version.jar" -C build/classes/main . -C src/main/resources .
