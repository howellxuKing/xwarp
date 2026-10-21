#!/usr/bin/env python3
"""Start the backend only in an ephemeral CI fixture and exercise security routes."""
import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
import shutil
import struct
import subprocess
import tempfile
import time
from pathlib import Path


def code(secret):
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return "%06d" % ((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000)


def request(path, method="GET", data=None, token=None, cookie=None):
    connection = http.client.HTTPConnection("127.0.0.1", 18081, timeout=15)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if cookie:
        headers["Cookie"] = cookie
    connection.request(method, path, json.dumps(data) if data is not None else None, headers)
    response = connection.getresponse()
    body = response.read()
    result = None
    if body:
        try:
            result = json.loads(body)
        except ValueError:
            result = body.decode()
    status, response_headers = response.status, dict(response.getheaders())
    connection.close()
    return status, result, response_headers


def success(path, method="GET", data=None, token=None):
    status, result, _ = request(path, method, data, token)
    assert status == 200 and isinstance(result, dict) and result.get("code") == 20000, "API action failed: " + path
    return result.get("data")


def rejected(path, method="GET", data=None, token=None):
    status, result, _ = request(path, method, data, token)
    assert status != 200 or not isinstance(result, dict) or result.get("code") != 20000, "Unauthorized action accepted: " + path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--database-container", required=True)
    parser.add_argument("--redis-container", required=True)
    args = parser.parse_args()
    if os.getenv("XWARP_CI") != "1" or os.getenv("GITHUB_ACTIONS") != "true":
        raise SystemExit("Refusing to start fixture outside ephemeral GitHub Actions")
    subprocess.run(["docker", "exec", args.database_container, "sh", "-c", 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mariadb -uroot -e "CREATE DATABASE IF NOT EXISTS trojan_panel_db"'], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["docker", "exec", args.redis_container, "redis-cli", "CONFIG", "SET", "requirepass", "isolated-test-password"], check=True, stdout=subprocess.DEVNULL)
    binary = str(Path(args.binary).resolve())
    with tempfile.TemporaryDirectory(prefix="xwarp-api-ci-") as folder:
        folder = Path(folder)
        with open(folder / "fixture.log", "wb") as log:
            environment = dict(os.environ, GIN_MODE="release")
            process = subprocess.Popen([binary, "-host=127.0.0.1", "-port=3306", "-user=root", "-password=isolated-test-password", "-redisHost=127.0.0.1", "-redisPort=6379", "-redisPassword=isolated-test-password", "-serverPort=18081"], cwd=folder, env=environment, stdout=log, stderr=log)
            try:
                for _ in range(60):
                    if process.poll() is not None:
                        raise AssertionError("Backend fixture exited before accepting requests; log suppressed to protect credentials")
                    try:
                        if request("/api/auth/health")[0] == 204:
                            break
                    except (OSError, http.client.HTTPException):
                        pass
                    time.sleep(1)
                else:
                    raise AssertionError("Backend fixture startup timed out")
                password = (folder / "config/initial-admin-password.txt").read_text().strip()
                assert len(password) == 16
                login = success("/api/auth/login", "POST", {"username": "sysadmin", "pass": password})
                token = login["token"]
                rejected("/api/security/status")
                state = success("/api/security/status", token=token)
                assert not state["totpEnabled"]
                subscription = success("/api/account/clashSubscribe", token=token)
                assert request(subscription)[0] == 200 and "rules:" in request(subscription)[1]
                enrollment = success("/api/security/totp/setup", "POST", {"password": password}, token)
                recovery = success("/api/security/totp/confirm", "POST", {"password": password, "code": code(enrollment["secret"])}, token)["recoveryCodes"]
                assert len(recovery) == 8
                rejected("/api/auth/login", "POST", {"username": "sysadmin", "pass": password})
                token2 = success("/api/auth/login", "POST", {"username": "sysadmin", "pass": password, "otp": recovery[0]})["token"]
                rejected("/api/security/status", token=token)  # Previous signed JWT must no longer authorize.
                rejected("/api/auth/login", "POST", {"username": "sysadmin", "pass": password, "otp": recovery[0]})
                rotated = success("/api/security/subscription/rotate", "POST", {"password": password, "code": recovery[1]}, token2)
                assert request(subscription)[0] == 404
                assert request(rotated)[0] == 200
                new_password = "new-secure-password-123"
                success("/api/account/updateAccountPass", "POST", {"oldPass": password, "newPass": new_password, "otp": recovery[2]}, token2)
                rejected("/api/security/status", token=token2)
                rejected("/api/auth/login", "POST", {"username": "sysadmin", "pass": password, "otp": recovery[3]})
                token3 = success("/api/auth/login", "POST", {"username": "sysadmin", "pass": new_password, "otp": recovery[3]})["token"]
                assert request(rotated)[0] == 200, "Login password change altered node/subscription credentials"
                success("/api/security/totp/disable", "POST", {"password": new_password, "code": recovery[4]}, token3)
                assert not success("/api/security/status", token=token3)["totpEnabled"]
                rotation = success("/api/security/nodes/rotate", "POST", {"password": new_password}, token3)
                assert rotation["restartRequired"]
                assert request(rotated)[0] == 200
                assert request("/api/auth/entry/verify")[0] == 403, "Missing entry key failed open"
                # Entry key grants a cookie, never an account session, and is removed from the URL.
                key = "ci-entry-key-" + "x" * 40
                (folder / "config/entry.key").write_text(key)
                assert request("/api/auth/entry/verify")[0] == 403
                status, _, headers = request("/api/auth/entry/open?key=" + key)
                assert status == 303 and headers["Location"] == "/"
                cookie = headers["Set-Cookie"].split(";", 1)[0]
                assert "Secure" in headers["Set-Cookie"] and "HttpOnly" in headers["Set-Cookie"]
                assert request("/api/auth/entry/verify", cookie=cookie)[0] == 204
                rejected("/api/security/status")
                (folder / "config/entry.key").write_text("rotated-entry-key-" + "y" * 40)
                assert request("/api/auth/entry/verify", cookie=cookie)[0] == 403
                assert success("/api/account/clashSubscribe", token=token3) == rotated
                print("API acceptance passed: login, MFA, recovery, session revocation, subscription isolation and entry gate")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()


if __name__ == "__main__":
    main()
