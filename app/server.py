#!/usr/bin/env python3
"""
Server skeleton — plain TCP; no TLS.

Implements:
    1. Accept client connection
    2. Handle Hello exchange
    3. Handle Register/Login
    4. Diffie–Hellman key exchange
    5. Receive encrypted message
    6. Send acknowledgment
"""

import socket
import json
from app.common.protocol import (
    Hello,
    ServerHello,
    Register,
    Login,
    DHServer,
    Msg,
)
from app.common.utils import b64e, now_ms
from app.crypto.dh import DHKeyPair
from app.crypto.aes import decrypt
from app.storage.transcript import Transcript


HOST = "0.0.0.0"
PORT = 5000


# ---------------------------------------------------------------------
# Networking helpers
# ---------------------------------------------------------------------
def recv_json(sock: socket.socket) -> dict:
    """Receive one JSON message (newline-delimited)."""
    buf = b""
    while not buf.endswith(b"\n"):
        data = sock.recv(4096)
        if not data:
            raise ConnectionError("Client disconnected")
        buf += data
    return json.loads(buf.decode())


def send_json(sock: socket.socket, data: dict):
    """Send JSON message (newline-delimited)."""
    sock.sendall(json.dumps(data).encode() + b"\n")


# ---------------------------------------------------------------------
# Server main workflow
# ---------------------------------------------------------------------
def handle_client(conn: socket.socket, addr):
    print(f"[*] Connection from {addr}")
    transcript = Transcript(f"server_transcript_{addr[1]}.log")

    # 1️⃣ Expect Hello
    hello_msg = recv_json(conn)
    print("[←] Received hello:", hello_msg)
    transcript.append({"event": "hello", "data": hello_msg})

    # 2️⃣ Send ServerHello
    sh = ServerHello(server_cert="BASE64SERVERCERT", nonce="SERVERNONCE")
    send_json(conn, sh.model_dump())
    print("[→] Sent server_hello")

    # 3️⃣ Expect Register/Login
    auth_msg = recv_json(conn)
    print("[←] Auth:", auth_msg)
    transcript.append({"event": "auth", "data": auth_msg})

    if auth_msg["type"] == "register":
        reply = {"type": "ack", "status": "registered"}
    elif auth_msg["type"] == "login":
        reply = {"type": "ack", "status": "logged_in"}
    else:
        reply = {"type": "error", "error": "invalid_auth"}
    send_json(conn, reply)

    # 4️⃣ Diffie–Hellman key exchange
    dh_client = recv_json(conn)
    print("[←] DHClient:", dh_client)
    transcript.append({"event": "dh_client", "data": dh_client})

    g, p, A = dh_client["g"], dh_client["p"], int(dh_client["A"])
    dh = DHKeyPair(g=g, p=p)
    B = dh.public
    Ks = dh.compute_shared_key(A)
    print("[*] Shared secret derived.")
    transcript.append({"event": "dh_shared", "sha": Ks[:8].hex() + "..."})

    send_json(conn, DHServer(B=B).model_dump())
    print("[→] Sent DHServer (B)")

    # 5️⃣ Receive encrypted message
    msg = recv_json(conn)
    print("[←] Received encrypted Msg:", msg)
    transcript.append({"event": "msg_recv", "data": msg})

    # Decrypt message (optional, just to show functionality)
    try:
        from app.common.utils import b64d
        ct = b64d(msg["ct"])
        pt = decrypt(ct, Ks)
        print("[+] Decrypted:", pt.decode(errors="ignore"))
        transcript.append({"event": "decrypted", "plaintext": pt.decode(errors='ignore')})
    except Exception as e:
        print("[!] Decryption failed:", e)

    # 6️⃣ Send acknowledgment
    ack = {"type": "ack", "status": "ok", "ts": now_ms()}
    send_json(conn, ack)
    print("[→] Sent ack")

    # 7️⃣ Save transcript hash
    digest = transcript.save_hash(f"server_transcript_{addr[1]}.sha256")
    print(f"[✓] Session complete (SHA256={digest[:12]}...)")

    conn.close()


def main():
    print(f"[+] SecureChat Server listening on {HOST}:{PORT}")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)

    try:
        while True:
            conn, addr = srv.accept()
            handle_client(conn, addr)
    except KeyboardInterrupt:
        print("\n[!] Server shutting down.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
