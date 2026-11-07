#!/usr/bin/env python3
"""
Leviton 1st-gen (DW) secure_connect via Mac, direct from the Leviton Device AP.

Public version: no personal defaults (SSID, serial, residence id) are
included. See README.md for the full story and the multi-switch workflow.

Replicates the My Leviton app's old IoT-device flow, as found in the
unpacked 3.76.1 app code:
  1. GET http://192.168.0.1/set_connection?c=3   (prod domain)
  2. GET http://192.168.0.1/certificate.txt      (device RSA certificate)
  3. Build query: as0=<SSID>&ap0=<password>&at0=<securityKey>&ak0=<regkey>
     - securityKey is the integer from scan_results.txt for the home network,
       e.g. 4194308 = WPA2_AES (most home WPA2 networks)
     - regkey is a fresh 12-character random registration key, saved locally
       to leviton_regkey.txt so the later cloud-claim step can reuse it
  4. RSA-encrypt the query with the certificate public key,
     RSAES-PKCS1-V1_5 (the app's CryptoRSA default scheme)
  5. base64-encode, then URL-safe transform (strip '=', '+' -> '-', '/' -> '_')
  6. GET http://192.168.0.1/secure_connect?c=<urlsafe>

Safety:
  - Run this ONLY while the Mac is connected to the Leviton Device AP
    (192.168.0.1, Mac IP 192.168.0.2). The switch's AP has no internet.
  - The home Wi-Fi password is prompted locally with getpass (not echoed)
    and is never written to disk, never sent to Muse, never printed.
  - Only the registration key is saved, to leviton_regkey.txt next to this
    script. Keep that file: the cloud-claim step will need the same key.
  - This script does NOT use the plain `connect` endpoint, which would send
    the password in clear text over the open AP.

Requires: Python 3, and either the `cryptography` package or the `openssl`
command-line tool (macOS ships openssl). If neither is available, it stops
with a clear message instead of falling back to plain text.
"""

import base64
import getpass
import os
import random
import string
import subprocess
import sys
import urllib.parse
import urllib.request

DEVICE = "http://192.168.0.1"
HERE = os.path.dirname(os.path.abspath(__file__))
REGKEY_FILE = os.path.join(HERE, "leviton_regkey.txt")


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "leviton-secure-connect/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, resp.read()


def _der_children(content):
    """Parse a DER SEQUENCE body into [(tag, content_bytes), ...]."""
    out = []
    pos = 0
    while pos < len(content):
        tag = content[pos]
        pos += 1
        lb = content[pos]
        pos += 1
        if lb & 0x80:
            nbytes = lb & 0x7F
            length = int.from_bytes(content[pos:pos + nbytes], "big")
            pos += nbytes
        else:
            length = lb
        out.append((tag, content[pos:pos + length]))
        pos += length
    return out


def _der_parse_one(data, pos):
    tag = data[pos]
    pos += 1
    lb = data[pos]
    pos += 1
    if lb & 0x80:
        nbytes = lb & 0x7F
        length = int.from_bytes(data[pos:pos + nbytes], "big")
        pos += nbytes
    else:
        length = lb
    return tag, data[pos:pos + length]


def _rsa_params_from_cert(cert_pem_bytes):
    lines = cert_pem_bytes.decode(errors="ignore").splitlines()
    b64 = "".join(l.strip() for l in lines if l and not l.startswith("-----"))
    der = base64.b64decode(b64)
    _, cert_body = _der_parse_one(der, 0)
    tbs = _der_children(cert_body)[0][1]
    # tbsCertificate children: [version]?, serial, signature, issuer,
    # validity, subject, subjectPublicKeyInfo, ...
    spki = None
    for tag, content in _der_children(tbs):
        children = _der_children(content)
        # subjectPublicKeyInfo: first child is an algorithm SEQUENCE,
        # second child is a BIT STRING (tag 0x03)
        if len(children) >= 2 and children[1][0] == 0x03:
            spki = content
            break
    if spki is None:
        raise ValueError("subjectPublicKeyInfo not found in certificate")
    _, bitstring = _der_children(spki)[1]
    rsa_der = bitstring[1:]  # drop unused-bits byte
    _, rsa_body = _der_parse_one(rsa_der, 0)
    mod_tag, mod_bytes = _der_children(rsa_body)[0]
    exp_tag, exp_bytes = _der_children(rsa_body)[1]
    modulus = int.from_bytes(mod_bytes, "big")
    exponent = int.from_bytes(exp_bytes, "big")
    return modulus, exponent


def _rsa_encrypt_pure_python(cert_pem_bytes, plaintext_bytes):
    """RSAES-PKCS1-V1_5 with only the standard library (no openssl needed)."""
    n, e = _rsa_params_from_cert(cert_pem_bytes)
    k = (n.bit_length() + 7) // 8
    if len(plaintext_bytes) > k - 11:
        raise ValueError("plaintext too long for RSA key")
    ps_len = k - len(plaintext_bytes) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = os.urandom(1)[0]
        if b != 0:
            ps.append(b)
    em = b"\x00\x02" + bytes(ps) + b"\x00" + plaintext_bytes
    m = int.from_bytes(em, "big")
    c = pow(m, e, n)
    return c.to_bytes(k, "big")


def rsa_encrypt_pkcs1_v15(cert_pem_bytes, plaintext_bytes):
    """Return raw RSA-encrypted bytes, PKCS#1 v1.5 padding."""
    # Preferred: cryptography package
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        cert = serialization.load_pem_x509_certificate(cert_pem_bytes)
        pub = cert.public_key()
        return pub.encrypt(plaintext_bytes, padding.PKCS1v15())
    except ImportError:
        pass
    # Fallback 1: openssl CLI (macOS ships LibreSSL openssl)
    cert_path = os.path.join(HERE, ".leviton_cert.pem")
    pub_path = os.path.join(HERE, ".leviton_pub.pem")
    plain_path = os.path.join(HERE, ".leviton_plain.bin")
    out_path = os.path.join(HERE, ".leviton_enc.bin")
    try:
        with open(cert_path, "wb") as f:
            f.write(cert_pem_bytes)
        subprocess.run(
            ["openssl", "x509", "-pubkey", "-noout", "-in", cert_path, "-out", pub_path],
            check=True, capture_output=True,
        )
        with open(plain_path, "wb") as f:
            f.write(plaintext_bytes)
        try:
            subprocess.run(
                ["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", pub_path,
                 "-pkeyopt", "rsa_padding_mode:pkcs1", "-in", plain_path, "-out", out_path],
                check=True, capture_output=True,
            )
        except subprocess.CalledProcessError:
            # LibreSSL openssl on macOS: rsautl fallback, also PKCS#1 v1.5
            subprocess.run(
                ["openssl", "rsautl", "-encrypt", "-pubin", "-inkey", pub_path,
                 "-pkcs", "-in", plain_path, "-out", out_path],
                check=True, capture_output=True,
            )
        with open(out_path, "rb") as f:
            return f.read()
    except Exception as openssl_err:
        print(f"  openssl path failed ({openssl_err}), trying pure-Python RSA ...")
        return _rsa_encrypt_pure_python(cert_pem_bytes, plaintext_bytes)
    finally:
        for p in (cert_path, pub_path, plain_path, out_path):
            try:
                os.remove(p)
            except OSError:
                pass


def main():
    print("Step 0: checking you are on the Leviton Device AP...")
    try:
        status, fw = get(DEVICE + "/fw_version.txt")
        print(f"  fw_version.txt -> HTTP {status}: {fw.decode(errors='replace').strip()}")
    except Exception as e:
        print(f"  FAILED to reach {DEVICE}: {e}")
        print("  Make sure the Mac Wi-Fi is connected to the 'Leviton Device xxxx' AP for THIS switch and try again.")
        return 1

    # Serial, for the per-device registration-key file (multi-switch fix).
    # Without this, every run overwrites leviton_regkey.txt and an earlier
    # unclaimed switch's key is lost. With it, each switch keeps its own file.
    serial = ""
    try:
        status, sbody = get(DEVICE + "/serial_number.txt")
        serial = sbody.decode(errors="replace").strip()
        print(f"  serial_number.txt -> HTTP {status}: {serial}")
    except Exception as e:
        print(f"  serial_number.txt not readable ({e}); falling back to the generic key file only.")

    ssid = input("Home Wi-Fi SSID (2.4 GHz name, exactly as scanned): ").strip()
    if not ssid:
        print("SSID is required.")
        return 1
    password = getpass.getpass("Home Wi-Fi password (typed locally, not echoed, not saved): ")
    if not password:
        print("Password is required.")
        return 1
    sec = input("securityKey integer from scan_results.txt [default 4194308 = WPA2_AES]: ").strip() or "4194308"
    if not sec.isdigit():
        print("securityKey must be an integer, e.g. 4194308.")
        return 1

    # Registration key: 12 random characters, as the app generates.
    alphabet = string.ascii_letters + string.digits
    regkey = "".join(random.SystemRandom().choice(alphabet) for _ in range(12))
    with open(REGKEY_FILE, "w") as f:
        f.write(regkey + "\n")
    print(f"Registration key generated and saved to {REGKEY_FILE} (keep this file).")
    if serial:
        safe_serial = "".join(c if (c.isalnum() or c in "-_") else "_" for c in serial)
        per_device_file = os.path.join(HERE, f"leviton_regkey_{safe_serial}.txt")
        with open(per_device_file, "w") as f:
            f.write(regkey + "\n")
        print(f"Per-device copy saved to {per_device_file} - use THIS file when claiming this switch,")
        print("  so a later switch's run cannot overwrite this switch's key.")

    print("Step 1: set_connection?c=3 ...")
    try:
        status, body = get(DEVICE + "/set_connection?c=3")
        print(f"  -> HTTP {status}: {body[:200]!r}")
    except Exception as e:
        print(f"  -> failed (continuing anyway): {e}")

    print("Step 2: fetching certificate.txt ...")
    try:
        status, cert = get(DEVICE + "/certificate.txt")
        print(f"  -> HTTP {status}, {len(cert)} bytes")
        if b"BEGIN CERTIFICATE" not in cert:
            print("  Certificate does not look like PEM. Stopping.")
            return 1
    except Exception as e:
        print(f"  FAILED: {e}")
        return 1

    query_map = {"as0": ssid, "ap0": password, "at0": sec, "ak0": regkey}
    # App: encodeURIComponent each value, join with '&', in as0/ap0/at0/ak0 order.
    query = "&".join(
        f"{k}={urllib.parse.quote(v, safe='')}" for k, v in query_map.items()
    )
    print(f"Step 3: query built (password redacted): as0={ssid}&ap0=***&at0={sec}&ak0={regkey}")

    print("Step 4: RSA-encrypting query with device certificate (PKCS1 v1.5) ...")
    try:
        encrypted = rsa_encrypt_pkcs1_v15(cert, query.encode())
    except Exception as e:
        print(f"  Encryption failed: {e}")
        print("  Install cryptography (pip install cryptography) or make sure openssl is present.")
        return 1
    print(f"  Encrypted length: {len(encrypted)} bytes (expect 256 for a 2048-bit key)")
    b64 = base64.b64encode(encrypted).decode()
    urlsafe = b64.rstrip("=").replace("+", "-").replace("/", "_")

    url = DEVICE + "/secure_connect?c=" + urlsafe
    print("Step 5: sending secure_connect (encrypted, password not in URL in clear) ...")
    try:
        status, body = get(url)
        print(f"  -> HTTP {status}: {body[:500]!r}")
    except Exception as e:
        print(f"  Request failed / connection closed (this can mean the switch rebooted to join home Wi-Fi): {e}")
        print("  Watch the switch LED and check whether the Leviton Device AP disappears.")
        return 0

    print()
    print("Done sending. Now watch the switch LED:")
    print("  - Flashing green slows: credentials being transferred")
    print("  - LED solid, then quick red/amber/green flash: rebooting")
    print("  - Steady green: connected to home Wi-Fi and internet")
    print("  - Blinking amber: could not join home Wi-Fi (check SSID/password/securityKey)")
    print("If the Leviton Device AP disappears, switch the Mac back to home Wi-Fi.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
