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
                initial_rules = request(subscription)[1]
                assert "DOMAIN-SUFFIX,douyin.com,DIRECT" in initial_rules, "Bundled domestic domain routing missing"
                assert "IP-CIDR6,fc00::/7,DIRECT,no-resolve" in initial_rules
                assert initial_rules.index("DOMAIN-SUFFIX,openai.com,PROXY") < initial_rules.index("DOMAIN-SUFFIX,douyin.com,DIRECT") < initial_rules.index("GEOIP,CN,DIRECT")
                assert initial_rules.rstrip().endswith("MATCH,PROXY")
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
                # Registration is username-only. Generated credentials are disclosed once, not in account info.
                system = success("/api/system/selectSystemByName", token=token3)
                # An edited template must not silently acquire automatic rule lists.
                original_template = system["clashRule"]
                system["clashRule"] = "# administrator rule-provider configuration; jsdelivr disabled\nrules:\n  - DOMAIN,admin-fixture.example,DIRECT\n  - MATCH,PROXY\n"
                success("/api/system/updateSystemById", "POST", system, token3)
                custom_template_subscription = request(rotated)[1]
                assert "admin-fixture.example,DIRECT" in custom_template_subscription
                assert "DOMAIN-SUFFIX,douyin.com,DIRECT" not in custom_template_subscription
                system["clashRule"] = original_template
                success("/api/system/updateSystemById", "POST", system, token3)
                baseline_subscription = request(rotated)[1]
                # Exercise the exact template-save -> subscription path used by the panel.
                system.update(clashDirectDomains="https://0996zp.com/", clashProxyDomains="example.org")
                success("/api/system/updateSystemById", "POST", system, token3)
                status, subscription_text, _ = request(rotated)
                assert status == 200 and isinstance(subscription_text, str)
                lines = subscription_text.splitlines()
                header = next(i for i, line in enumerate(lines) if line.strip() == "rules:")
                direct = next(i for i, line in enumerate(lines) if "DOMAIN-SUFFIX,0996zp.com,DIRECT" in line)
                proxy = next(i for i, line in enumerate(lines) if "DOMAIN-SUFFIX,example.org,PROXY" in line)
                assert header < proxy < direct, "Custom rules escaped the rules list; subscription is invalid YAML"
                assert lines[proxy].startswith(" ") and lines[direct].startswith(" ")
                system.update(clashDirectDomains="", clashProxyDomains="")
                success("/api/system/updateSystemById", "POST", system, token3)
                clear_status, cleared_subscription, _ = request(rotated)
                if cleared_subscription != baseline_subscription:
                    if isinstance(cleared_subscription, str) and isinstance(baseline_subscription, str):
                        before_rules = baseline_subscription[baseline_subscription.find("rules:"):].splitlines()
                        after_rules = cleared_subscription[cleared_subscription.find("rules:"):].splitlines()
                        different = [(i, a, b) for i, (a, b) in enumerate(zip(before_rules, after_rules)) if a != b]
                        print("Rule restoration mismatch:", len(before_rules), len(after_rules), different[:3], flush=True)
                    else:
                        print("Rule restoration response:", clear_status, type(cleared_subscription).__name__, flush=True)
                assert cleared_subscription == baseline_subscription, "Clearing custom lists did not restore the original subscription"
                system.update(registerEnable=1, captchaEnable=0, registerQuota=1, registerExpireDays=1)
                success("/api/system/updateSystemById", "POST", system, token3)
                rejected("/api/auth/register", "POST", {"username": "manualuser", "pass": "supplied-password-123"})
                status, registration, headers = request("/api/auth/register", "POST", {"username": "fixtureuser"})
                assert status == 200 and registration["code"] == 20000
                assert headers.get("Cache-Control") == "no-store"
                credentials = registration["data"]
                assert credentials["username"] == "fixtureuser" and len(credentials["initialPassword"]) == 16
                assert "token" not in credentials
                user_password = credentials["initialPassword"]
                rejected("/api/auth/register", "POST", {"username": "fixtureuser"})
                user_token = success("/api/auth/login", "POST", {"username": "fixtureuser", "pass": user_password})["token"]
                user_info = success("/api/account/getAccountInfo", token=user_token)
                assert "initialPassword" not in user_info and "password" not in user_info
                rejected("/api/account/updateAccountPass", "POST", {"oldPass": user_password, "newPass": "forbidden-user-password"}, user_token)
                reset_payload = {"id": user_info["id"], "username": "fixtureuser", "roleId": 3,
                                 "deleted": 0, "quota": 1, "expireTime": int(time.time() * 1000) + 86400000,
                                 "pass": "admin-reset-password-123"}
                rejected("/api/account/updateAccountById", "POST", reset_payload, user_token)
                user_subscription = success("/api/account/clashSubscribe", token=user_token)
                success("/api/account/updateAccountById", "POST", reset_payload, token3)
                rejected("/api/security/status", token=user_token)
                rejected("/api/auth/login", "POST", {"username": "fixtureuser", "pass": user_password})
                user_token = success("/api/auth/login", "POST", {"username": "fixtureuser", "pass": reset_payload["pass"]})["token"]
                assert success("/api/account/clashSubscribe", token=user_token) == user_subscription
                system["captchaEnable"] = 1
                success("/api/system/updateSystemById", "POST", system, token3)
                rejected("/api/auth/register", "POST", {"username": "captchatest"})
                system.update(captchaEnable=0, registerEnable=0)
                success("/api/system/updateSystemById", "POST", system, token3)
                rejected("/api/auth/register", "POST", {"username": "closeduser"})
                print("API acceptance passed: login, MFA, recovery, session revocation, subscription isolation and entry gate")
                print("Registration passed: generated credentials, login, admin-only password changes, reset revocation, captcha and closed registration")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()


if __name__ == "__main__":
    main()
