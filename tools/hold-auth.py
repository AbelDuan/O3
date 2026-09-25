#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hold an ADB auth attempt open so the device's "Allow USB debugging?" dialog
stays on screen long enough to tap.

Why: `adb connect` gives up after the first AUTH exchange, and MIUI dismisses the
dialog when the socket closes -> the dialog "flashes". Here we complete the AUTH
exchange and then KEEP THE SOCKET OPEN, re-answering every AUTH the device sends,
so adbd keeps waiting for the user.

Usage: python3 hold-auth.py <host> <port> [seconds]
Exit codes: 0 = authorized (CNXN received), 2 = timed out still unauthorized
"""
import base64
import hashlib
import os
import socket
import struct
import sys
import time

KEYDIR = os.environ.get("ADBKEYDIR", "/root/.dsh/adbkeys")
KEY = os.path.join(KEYDIR, "adbkey")
KEYPUB = KEY + ".pub"

A_CNXN, A_AUTH, A_OPEN, A_OKAY, A_CLSE, A_WRTE = 0x4E584E43, 0x48545541, 0x4E45504F, 0x59414B4F, 0x45534C43, 0x45545257
A_VERSION = 0x01000000
AUTH_TOKEN, AUTH_SIGNATURE, AUTH_RSAPUBLICKEY = 1, 2, 3


def make_signer():
    """Return a callable(token_bytes) -> signature_bytes using the adb private key."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    priv = serialization.load_pem_private_key(open(KEY, "rb").read(), password=None)

    def sign(token: bytes) -> bytes:
        # adb uses PKCS#1 v1.5 with SHA-1 over the raw token
        return priv.sign(token, padding.PKCS1v15(), hashes.SHA1())

    return sign


def pubkey_blob() -> bytes:
    """adb public key as sent in A_AUTH(AUTH_RSAPUBLICKEY): base64 + '\\0' + 'host'."""
    raw = open(KEYPUB, "rb").read().strip()
    b64 = raw.split()[0] if b" " in raw else raw
    return b64 + b"\x00host\x00"


def send(sock, cmd, arg0, arg1, payload=b""):
    hdr = struct.pack("<6I", cmd, arg0, arg1, len(payload), sum(payload) & 0xFFFFFFFF, cmd ^ 0xFFFFFFFF)
    sock.sendall(hdr + payload)


def recv(sock):
    hdr = b""
    while len(hdr) < 24:
        c = sock.recv(24 - len(hdr))
        if not c:
            raise EOFError("socket closed by device")
        hdr += c
    cmd, arg0, arg1, length, _chk, _magic = struct.unpack("<6I", hdr)
    body = b""
    while len(body) < length:
        c = sock.recv(length - len(body))
        if not c:
            raise EOFError("socket closed during payload")
        body += c
    return cmd, arg0, arg1, body


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "<LAN-IP>"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5555
    hold = int(sys.argv[3]) if len(sys.argv) > 3 else 150

    sign = make_signer()
    pub = pubkey_blob()
    fp = hashlib.sha256(base64.b64decode(pub.split(b"\x00")[0])).hexdigest().upper()[:32]
    print(f"key sha256[:32] = {fp}", flush=True)

    deadline = time.time() + hold
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=10)
        except Exception as e:
            print(f"connect failed: {e}; retry in 3s", flush=True)
            time.sleep(3)
            continue
        s.settimeout(5)
        print(f"connected {host}:{port}; sending CNXN with our key", flush=True)
        send(s, A_CNXN, A_VERSION, 4096, b"host::features=shell_v2,cmd,stat_v2\x00")
        got_cnxn = False
        signed_once = False
        try:
            while time.time() < deadline:
                try:
                    cmd, a0, a1, body = recv(s)
                except socket.timeout:
                    continue
                except EOFError as e:
                    print(f"device closed: {e}", flush=True)
                    break
                if cmd == A_AUTH:
                    if a0 == AUTH_TOKEN:
                        # AOSP: sign the token ONCE; if the device keeps challenging,
                        # it does not know our key -> hand it the public key so adbd
                        # can raise the "Allow USB debugging?" dialog for THIS key.
                        if signed_once:
                            print("  <- AUTH token again -> sending RSAPUBLICKEY (dialog key)", flush=True)
                            send(s, A_AUTH, AUTH_RSAPUBLICKEY, 0, pub)
                        else:
                            print(f"  <- AUTH token ({len(body)}B) -> signing", flush=True)
                            send(s, A_AUTH, AUTH_SIGNATURE, 0, sign(body))
                            signed_once = True
                    elif a0 in (AUTH_SIGNATURE, AUTH_RSAPUBLICKEY):
                        print("  <- device wants the public key -> sending it", flush=True)
                        send(s, A_AUTH, AUTH_RSAPUBLICKEY, 0, pub)
                elif cmd == A_CNXN:
                    print("  ** AUTHORIZED ** (CNXN received)", flush=True)
                    got_cnxn = True
                    break
                else:
                    print(f"  <- cmd={cmd:#x} a0={a0} a1={a1} len={len(body)}", flush=True)
        finally:
            if got_cnxn:
                s.close()
                return 0
            s.close()
        time.sleep(2)
    print("TIMEOUT: still unauthorized (dialog not tapped in time)", flush=True)
    return 2


if __name__ == "__main__":
    sys.exit(main())
