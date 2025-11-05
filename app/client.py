#!/usr/bin/env python3
"""
Client skeleton — plain TCP; no TLS.
Implements workflow:
    1. Connect to server
    2. Exchange Hello
    3. Register/Login
    4. DH Key Exchange
    5. Secure message send/receive
"""

import socket
import json
from app.common.protocol import Hello, Login, Register, DHClient, Msg, parse_message
from app.common.utils import b64e, now_ms
from app.crypto.dh import DHKeyPair
from app.crypto.aes import encrypt, decrypt
from app.storage.transcript import Transcript


SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000


# ---------------------------------------------------------------------
# Networking helpers
# ---------------------------------------------------------------------
def send_json(sock: socket.socket, data: dict):
    """Send a JSON message with newline delimiter."""
    sock.sendall(json.dumps(data).encode() + b"\n")


def recv_json(sock: socket.socket) -> dict:
    """Receive a single JSON message (newline-terminated)."""
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Server closed connection")
        buf += chunk
    return json.loads(buf.decode())


# ---------------------------------------------------------------------
# Client workflow
# ---------------------------------------------------------------------
def main():
    print("[+] SecureChat Client starting...")
    transcript = Transcript("client_transcript.log")

    # 1️⃣ Connect to server
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        print(f"[*] Connected to {SERVER_HOST}:{SERVER_PORT}")

        # 2️⃣ Send Hello
        hello = Hello(client_cert="BASE64CLIENTCERT", nonce="RANDOMNONCE")
        send_json(sock, hello.model_dump())
        print("[→] Sent hello")

        # 3️⃣ Receive ServerHello
        server_hello = recv_json(sock)
        print("[←] Got server hello:", server_hello)

        # 4️⃣ Registration or login
        choice = input("Register (r) or Login (l)? ").strip().lower()
        if choice == "r":
            email = input("Email: ")
            username = input("Username: ")
            pwd = input("Password: ")
            reg = Register(email=email, username=username, pwd=b64e(pwd.encode()), salt="BASE64SALT")
            send_json(sock, reg.model_dump())
            print("[→] Sent registration request")
        else:
            email = input("Email: ")
            pwd = input("Password: ")
            login = Login(email=email, pwd=b64e(pwd.encode()), nonce="NONCE")
            send_json(sock, login.model_dump())
            print("[→] Sent login request")

        # 5️⃣ Diffie-Hellman Key Exchange
        dh = DHKeyPair()
        send_json(sock, DHClient(g=dh.g, p=dh.p, A=dh.public).model_dump())
        print("[→] Sent DH public value A")

        # Wait for server's DH response (ignore any other messages like ack)
        while True:
            dh_server = recv_json(sock)
            if dh_server.get("type") == "dh_server":
                break
            else:
                print(f"[←] Ignoring intermediate message: {dh_server}")
        Ks = dh.compute_shared_key(int(dh_server["B"]))
        print("[*] Shared secret established.")

        print("[*] Shared secret established.")

        transcript.append({"event": "dh", "shared_key_sha": Ks[:8].hex() + "..."})

        # 6️⃣ Send one encrypted message
        message = input("Enter secure message: ").encode()
        ct = encrypt(message, Ks)
        send_json(sock, Msg(seqno=1, ct=b64e(ct), sig="BASE64SIG").model_dump())
        print("[→] Sent encrypted message")

        transcript.append({"event": "msg_sent", "seqno": 1, "cipher": b64e(ct)})

        # 7️⃣ Wait for acknowledgment
        resp = recv_json(sock)
        print("[←] Server response:", resp)

        transcript.append({"event": "server_resp", "data": resp})
        digest = transcript.save_hash("client_transcript.sha256")
        print(f"[+] Transcript saved (SHA256={digest[:12]}...)")

    print("[✓] Client workflow complete.")


if __name__ == "__main__":
    main()
