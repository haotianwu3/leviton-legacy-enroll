# Leviton 1st-gen Decora Smart Wi-Fi: enroll without an old phone

Enroll a 1st-generation Leviton Decora Smart Wi-Fi switch/dimmer (firmware
below 1.4.32) from a Mac, when a modern iPhone or Android phone can no
longer join the switch's own setup access point.

This is the workaround that actually worked for the author in October
2026, after the official workaround (borrow an older device) was not an
option. It is unofficial, not affiliated with or endorsed by Leviton.

## The problem

Leviton documents it here:
<https://leviton.com/support/resources/product-support/decora-smart-support/decora-smart-wi-fi/when-enrolling-a-decora-smart-wi-fi-device-my-mobile-device-cannot-connect-to-the-leviton-device-in-the-wi-fi-settings>

- Devices made before November 2019 with firmware below 1.4.32 cannot be
  enrolled by a phone running a post-August-2020 OS.
- The failure happens at the step where the phone joins the switch's own
  `Leviton Device xxxx` access point, *before* any home Wi-Fi password is
  entered. It is not a password, 2.4 vs 5 GHz, or signal problem.
- Leviton's only official fixes are: enroll with an older device and then
  update the firmware, or contact Leviton support.

The author's switch reported firmware **1.4.13** via the device itself.
Turning off the iPhone's Private Wi-Fi Address for that network did not
help. A Mac, however, *could* join the switch's access point, and the
switch exposes the same 1st-generation HTTP API the old app used.

## What this does

Two steps, one switch at a time:

1. **`secure_connect.py` (Mac, on the switch's AP)** — replicates the old
   app's secure enrollment: it reads the switch's firmware/serial/
   certificate over plain HTTP at `192.168.0.1`, encrypts the home Wi-Fi
   credentials with the switch's RSA certificate (RSAES-PKCS1-V1_5), and
   sends them with `secure_connect`. The switch then joins home Wi-Fi.
   A fresh 12-character registration key is generated per switch and
   saved locally, including a per-serial copy
   (`leviton_regkey_<serial>.txt`), so later switches cannot overwrite
   an earlier switch's key.

2. **Claim the switch to your My Leviton account** — joining Wi-Fi alone
   does *not* put the switch in your account. The claim step is
   `POST /IotSwitches/<serial>/identify` followed by
   `POST /Residences/<residenceId>/registerDevice?deviceId=<id>&regKey=<key>`
   against `https://my.leviton.com/api`.
   - **Recommended: `claim_in_browser.js`.** Run it in the DevTools
     console on the logged-in My Leviton web app
     (`myapp.leviton.com/landing-tabs/devices`). It reads the session
     token and user id from that page's own localStorage
     (`$LevDB$id`, `$LevDB$userId`), finds the residence id from the
     page's storage key names, prompts for the serial(s) and, per
     switch, for that switch's registration key (browser only, never
     sent anywhere else), then identifies, registers and verifies.
     This avoids the password-login API entirely.
   - **Alternative: `claim_device.py`.** A Python script that logs in
     with your My Leviton email/password (typed locally, never stored)
     and does the same three calls. Note: repeated failed logins can
     trigger Leviton's `Too many failed attempts` (HTTP 403) lockout
     on the login API. If that happens, stop retrying and use the
     browser method, or wait for the lockout to clear and retry once
     with the verified password.

After a successful claim, refresh the Devices page / My Leviton app:
the switch should appear. Name it, put it in a room, test on/off, and
check for a firmware update. Updating past 1.4.32 should make any
future re-enrollment work from a phone again.

## Prerequisites

- A 1st-generation Leviton Decora Smart Wi-Fi device, in setup mode
  (LED flashing green, broadcasting `Leviton Device xxxx`).
- A Mac (tested on a 2017 iMac, macOS Ventura, `/usr/bin/python3` 3.8;
  the scripts use only the Python standard library).
- Home Wi-Fi: 2.4 GHz SSID and password. The switch is 2.4 GHz only.
- A My Leviton account, and a browser logged into the My Leviton web
  app for the claim step.

## Usage, one switch at a time

Do **not** batch the Wi-Fi step for several switches and claim them
later: each `secure_connect` run generates a new registration key, and
the claim step needs the key that was sent to *that* switch. Finish
one switch (Wi-Fi + claim + verify in the app) before starting the
next.

### 1. Wi-Fi (Mac)

```
# Join the switch's "Leviton Device xxxx" Wi-Fi network on the Mac first.
# Then, from the folder containing this script:
/usr/bin/python3 secure_connect.py
```

Answer the prompts locally: home Wi-Fi SSID (2.4 GHz, exactly as
scanned), home Wi-Fi password (not echoed, not saved), security key
(default `4194308` = WPA2_AES for most home networks). Watch the LED:
flashing green slows, then solid, then a quick red/amber/green flash,
then steady green means it joined home Wi-Fi and the internet.
Blinking amber means it could not join home Wi-Fi — recheck the SSID,
password, or security key, and retry.

### 2. Claim (browser, recommended)

1. Log into the My Leviton web app and open the Devices page.
2. Open DevTools console, paste the contents of `claim_in_browser.js`,
   press Enter.
3. Enter the switch serial(s), comma-separated, when prompted.
4. When prompted per switch, paste that switch's 12-character
   registration key from its `leviton_regkey_<serial>.txt` file.
   The prompt runs in the browser only; the key is never sent to
   anyone else.
5. Refresh the Devices page and confirm the switch appears.

### 3. Claim (Python, alternative)

```
# Mac on HOME Wi-Fi (not the Leviton Device AP).
/usr/bin/python3 claim_device.py
```

Enter the serial, then your My Leviton email/password locally. If
residence lookup returns empty, enter the residence id manually
(find it in the web app's localStorage key names, e.g.
`sorting$residence:<id>$rooms`).

## Files

| File | What it is |
| --- | --- |
| `secure_connect.py` | Mac Wi-Fi enrollment via the switch's 1st-gen HTTP API |
| `claim_in_browser.js` | Browser-console claim (multi-switch, recommended) |
| `claim_device.py` | Python claim via password login (alternative) |

Not included, deliberately: the My Leviton APK, any unpacked app
code, API keys, Wi-Fi scan results, or any personal identifiers.
The protocol was identified from the app's own client code; no
Leviton code or assets are reproduced here.

## Security and privacy

- The home Wi-Fi password is typed locally and is never written to
  disk, printed, or sent to any third party. It is encrypted with the
  switch's own RSA certificate before leaving the Mac.
- The registration key and session token are used only locally / in
  the logged-in browser page, and are never printed in full by these
  scripts. Do not paste either of them into a chat, issue, or log.
- The switch's local API is plain HTTP on its open setup AP. That is
  how the 1st-generation protocol works; do not run these scripts on
  an untrusted network, and switch the Mac back to home Wi-Fi once
  the switch's AP disappears.
- `leviton_regkey*.txt` files are git-ignored in this repo. Keep them
  locally; they are the link between a switch and its claim.

## Troubleshooting

- `secure_connect.py` cannot reach `192.168.0.1`: the Mac is not on
  the switch's AP. On a Mac, Wi-Fi may be `en1`, not `en0` — check
  which interface holds the `192.168.0.x` address.
- `fw_version.txt` returns a version ≥ 1.4.32: this workaround is
  probably unnecessary; try the normal app enrollment first.
- Identify returns 200 but no device id, or 404 after retries: the
  switch may not have registered in the cloud yet, or the serial is
  wrong. Check the LED is steady green, wait a minute, and confirm
  the serial from `serial_number.txt` (or the AP name suffix).
- Claim login returns 401: the email/password typed into the Python
  script does not match. Verify it by logging into the app/web
  first, and do not retry repeatedly.
- Claim login returns 403 `Too many failed attempts`: the login API
  is rate-limited. Stop retrying; use the browser method, which does
  not call that endpoint.
- Browser claim reports `token found: no`: you are not on the
  logged-in Devices page, or the session storage keys differ from
  `$LevDB$id` / `$LevDB$userId` in your web app version. Check the
  page is logged in, then inspect localStorage key names only.

## Disclaimer

Use at your own risk. This is reverse-engineered, unofficial tooling
for hardware you own. It worked for the author's switches; it may
not work for other models, firmware versions, or account states. If
in doubt, use Leviton's official route (older device, or support at
800-824-3005 option 3 / DSSupport@leviton.com).
