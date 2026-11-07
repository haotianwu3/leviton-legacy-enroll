#!/usr/bin/env python3
"""
My Leviton cloud claim for a 1st-gen Decora Smart Wi-Fi switch that is
ALREADY online on home Wi-Fi (steady green LED).

This mirrors what the My Leviton app does after Wi-Fi join:
  1. POST /Person/login  -> session token (LoopBack)
  2. Find the user's residence(s)
  3. POST /IotSwitches/<serial>/identify?seconds=1  -> cloud device id
  4. POST /Residences/<residenceId>/registerDevice?deviceId=<id>&regKey=<key>

Run on the Mac, on HOME Wi-Fi (NOT on the Leviton Device AP):
    /usr/bin/python3 claim_device.py

Security, by design:
  - Email/password are typed locally with getpass for the password.
    They are NEVER written to disk, NEVER printed, and NEVER sent to Muse.
  - The registration key is read from leviton_regkey.txt next to this script
    (the file written by the successful secure_connect run). It is NEVER
    printed in full, and neither is the session token.
  - Only status lines, ids, and short error messages are printed.
    When you report back, paste only those status lines, not any token/key.

Requires only Python 3 stdlib. Tested against /usr/bin/python3 (3.8) on macOS.
If a step fails, the script stops and prints what it saw, so the failure
can be diagnosed without guessing.
"""

import getpass
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SERIAL_DEFAULT = ""  # e.g. "1000_000F_XXXX" - enter your switch's serial
BASE_HOST = "https://my.leviton.com"
BASE_PORT = ":443"


def mask(s):
    """Show only first/last chars of a secret, for local diagnostics only."""
    if not s:
        return "<empty>"
    if len(s) <= 4:
        return "***"
    return s[:2] + "***" + s[-2:]


def http(method, url, token=None, body=None, timeout=30):
    """One HTTP call. Returns (status, parsed_json_or_text)."""
    data = None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    elif method == "POST":
        # SDK always sends an empty JSON object for POSTs like identify /
        # registerDevice, never a body-less POST. Match that exactly.
        data = b"{}"
    # LoopBack accepts the token as a query param and as Authorization.
    # Send both; never print the full URL (it contains the token).
    req_url = url
    if token:
        sep = "&" if "?" in url else "?"
        req_url = url + sep + "access_token=" + urllib.parse.quote(token)
        headers["Authorization"] = token
    req = urllib.request.Request(req_url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            try:
                return resp.status, json.loads(raw)
            except ValueError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw
    except Exception as e:  # network error etc.
        return None, {"error": str(e)}


def short_err(obj, limit=300):
    s = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    return s[:limit]


def main():
    print("My Leviton claim - device must already be online (steady green).")
    print("Make sure this Mac is on HOME Wi-Fi, not the Leviton Device AP.")
    print("")

    # --- Serial first (multi-switch fix), then per-device key file ---
    # Old order read the generic leviton_regkey.txt before knowing which
    # switch this is. For multiple switches, each run of secure_connect
    # now also writes leviton_regkey_<serial>.txt, and that file wins.
    serial = input("Device serial (e.g. 1000_000F_XXXX): ").strip()
    if not serial:
        print("Serial is required.")
        return 1
    print("Serial: %s" % serial)

    # --- Registration key (local file, never printed in full) ---
    here = os.path.dirname(os.path.abspath(__file__))
    safe_serial = "".join(c if (c.isalnum() or c in "-_") else "_" for c in serial)
    candidates = [
        os.path.join(here, "leviton_regkey_%s.txt" % safe_serial),
        os.path.join(here, "leviton_regkey.txt"),
    ]
    regkey = None
    used_path = None
    for key_path in candidates:
        if os.path.exists(key_path):
            with open(key_path, "r") as f:
                regkey = f.read().strip()
            if regkey:
                used_path = key_path
                break
    if not regkey:
        print("No registration-key file found for this serial (looked for %s, then leviton_regkey.txt)." % candidates[0])
        regkey = getpass.getpass(
            "Registration key from this switch's secure_connect run: "
        ).strip()
    else:
        print("Registration key file used: %s" % used_path)
    if len(regkey) != 12:
        print("Warning: registration key length is %d, expected 12. Continuing anyway."
              % len(regkey))
    print("Registration key found, length %d (not printed)." % len(regkey))

    email = input("My Leviton email: ").strip()
    password = getpass.getpass("My Leviton password (typed locally, not echoed): ")
    if not email or not password:
        print("Email/password required. Nothing was sent.")
        return 1

    # --- Step 0: API version (info only, NOT a URL segment) ---
    # Correction (2026-10-24): /apiversion returns a feature-gate version
    # (e.g. 1.68.0) used by the app only for feature checks. The LoopBack
    # SDK builds URLs as getPath() + "/" + getApiVersion() + "/Person/...",
    # where getPath() is https://my.leviton.com and getApiVersion() defaults
    # to "api". So the correct base is https://my.leviton.com/api, NOT
    # https://my.leviton.com:443/api/1.68.0 (that 404s on Person/login).
    print("\nStep 0: checking cloud reachability ...")
    try:
        with urllib.request.urlopen(BASE_HOST + "/apiversion", timeout=15) as resp:
            api_version = resp.read().decode("utf-8", "replace").strip()
    except Exception as e:
        print("  FAILED to fetch /apiversion: %s" % e)
        print("  Check internet on home Wi-Fi and retry.")
        return 1
    print("  Server reports version: %s (info only, not used in URLs)" % api_version)
    api = "%s/api" % BASE_HOST

    # --- Step 1: Login ---
    print("\nStep 1: logging in to My Leviton ...")
    status, login = http(
        "POST", api + "/Person/login?include=user",
        body={"credentials": {"email": email, "password": password}},
    )
    # Password is now out of scope; drop the reference.
    password = None
    if status != 200 or not isinstance(login, dict) or not login.get("id"):
        print("  FAILED: HTTP %s: %s" % (status, short_err(login)))
        print("  If this is a verification-code / 2FA prompt, stop here and report it;")
        print("  this script does not yet handle the code step.")
        return 1
    token = login["id"]
    user_id = login.get("userId")
    print("  Login OK. userId: %s (token not printed)." % user_id)
    if not user_id:
        print("  FAILED: login response had no userId.")
        return 1

    # --- Step 2: Find residences ---
    print("\nStep 2: finding residences ...")
    residences = []
    # Path A: Person -> residentialAccounts -> residences
    status, accounts = http("GET", api + "/Person/%s/residentialAccounts" % user_id,
                            token=token)
    if status == 200 and isinstance(accounts, list):
        for acc in accounts:
            acc_id = acc.get("id")
            if acc_id is None:
                continue
            s2, res_list = http(
                "GET", api + "/ResidentialAccounts/%s/residences" % acc_id,
                token=token)
            if s2 == 200 and isinstance(res_list, list):
                residences.extend(res_list)
    # Path B: Person -> residentialPermissions -> residence (fallback)
    # App does this via GET /ResidentialPermissions/{permId}/residence,
    # not by trusting a residenceId field on the permission object.
    if not residences:
        status, perms = http("GET", api + "/Person/%s/residentialPermissions" % user_id,
                             token=token)
        if status == 200 and isinstance(perms, list):
            for perm in perms:
                pid = perm.get("id")
                if pid is None:
                    continue
                s2, res = http(
                    "GET", api + "/ResidentialPermissions/%s/residence" % pid,
                    token=token)
                if s2 == 200 and isinstance(res, dict) and res.get("id") is not None:
                    residences.append(res)
                elif perm.get("residenceId"):
                    residences.append({"id": perm["residenceId"]})
    # Deduplicate by id, keep order.
    seen = set()
    uniq = []
    for r in residences:
        if isinstance(r, dict) and r.get("id") not in seen:
            seen.add(r.get("id"))
            uniq.append(r)
    residences = uniq
    if not residences:
        # Multi-switch / browser lesson: the API accounts call can return
        # 200 with no residences even when the account has one (the first
        # switch's browser claim hit exactly this). Do not fail here -
        # ask for the residence id, defaulting to the first switch's
        # known residence (same house, almost certainly the same residence).
        print("  No residences found via accounts or permissions.")
        print("  (This can happen even when the account has a residence.")
        print("   Find yours in the web app's localStorage key names, e.g.")
        print("   sorting$residence:<id>$rooms - see README.md.)")
        rid = input("  Residence ID: ").strip()
        if not rid:
            print("  Residence ID is required.")
            return 1
        residences = [{"id": rid, "name": "(entered manually)"}]
    print("  Found %d residence(s)." % len(residences))
    for i, r in enumerate(residences, 1):
        name = r.get("name") or r.get("title") or "(no name in response)"
        print("    %d) id=%s name=%s" % (i, r.get("id"), name))
    if len(residences) == 1:
        residence = residences[0]
    else:
        choice = input("  Pick a residence number: ").strip()
        try:
            residence = residences[int(choice) - 1]
        except Exception:
            print("  Invalid choice.")
            return 1
    residence_id = residence["id"]
    print("  Residence selected: id=%s" % residence_id)

    # --- Step 3: Identify device by serial (retry, device may take a moment) ---
    print("\nStep 3: identifying device by serial in the cloud ...")
    device = None
    device_id = None
    for attempt in range(1, 11):
        status, ident = http(
            "POST",
            api + "/IotSwitches/%s/identify?seconds=1" % urllib.parse.quote(serial),
            token=token)
        print("  attempt %d: HTTP %s" % (attempt, status))
        if status == 200 and isinstance(ident, dict):
            # Response shape varies: either the device itself, or {"device": {...}}
            cand = ident.get("device") if isinstance(ident.get("device"), dict) else ident
            if cand.get("id") is not None:
                device = cand
                device_id = cand["id"]
                break
            # If identify returned something without an id, keep the raw for diagnosis.
            print("    identify returned no device id: %s" % short_err(ident))
        else:
            print("    %s" % short_err(ident))
        if attempt < 10:
            time.sleep(5)
    if device is None:
        print("  FAILED: device not found in the cloud after 10 attempts.")
        print("  Possible causes: device not yet cloud-registered, wrong serial,")
        print("  or the cloud identify endpoint differs for this model.")
        print("  Do NOT re-run secure_connect yet; report this output first.")
        return 1
    print("  Device found: cloud id=%s, serial=%s, residenceId=%s"
          % (device_id, device.get("serial"), device.get("residenceId")))

    # --- Step 4: Register to residence (skip if already there) ---
    if device.get("residenceId") == residence_id:
        print("\nStep 4: device already belongs to this residence. Nothing to register.")
    else:
        print("\nStep 4: registering device to residence ...")
        status, reg = http(
            "POST",
            api + "/Residences/%s/registerDevice?deviceId=%s&regKey=%s"
            % (residence_id, urllib.parse.quote(str(device_id)),
               urllib.parse.quote(regkey)),
            token=token)
        # Drop the key reference once used.
        regkey = None
        print("  registerDevice: HTTP %s" % status)
        if status not in (200, 201, 204):
            print("  FAILED: %s" % short_err(reg))
            print("  If this says the registration key is invalid, the key from")
            print("  the successful secure_connect run may not match; report it.")
            return 1
        print("  Register OK.")

    # --- Step 5: Verify ---
    print("\nStep 5: verifying ...")
    status, check = http(
        "GET", api + "/IotSwitches/%s" % urllib.parse.quote(str(device_id)),
        token=token)
    if status == 200 and isinstance(check, dict):
        print("  Device now shows residenceId=%s" % check.get("residenceId"))
        if check.get("residenceId") == residence_id:
            print("  VERIFIED: device is in the selected residence.")
        else:
            print("  NOTE: residenceId does not match yet; check the app after a refresh.")
    else:
        print("  Verify GET returned HTTP %s: %s" % (status, short_err(check)))
        print("  The register step may still have succeeded; check the app.")

    print("\nDone. Now open the My Leviton app on home Wi-Fi and refresh the")
    print("device list. If the switch appears, name it and put it in a room.")
    print("If it does not appear after a minute, report the steps above.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
