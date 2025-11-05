#!/usr/bin/env python3
"""
Pydantic message models for the Secure Chat Protocol.

Includes:
    - Hello / ServerHello
    - Register / Login
    - DHClient / DHServer
    - Msg
    - Receipt
"""

from pydantic import BaseModel, Field
from typing import Optional
from app.common.utils import now_ms


# ---------------------------------------------------------------
# 1️⃣ Control Plane Messages
# ---------------------------------------------------------------

class Hello(BaseModel):
    type: str = Field(default="hello")
    client_cert: str = Field(..., description="Base64-encoded PEM of client certificate")
    nonce: str = Field(..., description="Base64 random nonce for freshness")


class ServerHello(BaseModel):
    type: str = Field(default="server_hello")
    server_cert: str = Field(..., description="Base64-encoded PEM of server certificate")
    nonce: str = Field(..., description="Base64 random nonce for freshness")


class Register(BaseModel):
    type: str = Field(default="register")
    email: str
    username: str
    pwd: str = Field(..., description="base64(sha256(salt||pwd))")
    salt: str = Field(..., description="Base64 salt used for hashing")


class Login(BaseModel):
    type: str = Field(default="login")
    email: str
    pwd: str = Field(..., description="base64(sha256(salt||pwd))")
    nonce: str = Field(..., description="Base64 nonce for freshness")


# ---------------------------------------------------------------
# 2️⃣ Key Agreement Messages
# ---------------------------------------------------------------

class DHClient(BaseModel):
    type: str = Field(default="dh_client")
    g: int
    p: int
    A: int = Field(..., description="Client public value (g^a mod p)")


class DHServer(BaseModel):
    type: str = Field(default="dh_server")
    B: int = Field(..., description="Server public value (g^b mod p)")


# ---------------------------------------------------------------
# 3️⃣ Data Plane Message (Encrypted Chat)
# ---------------------------------------------------------------

class Msg(BaseModel):
    type: str = Field(default="msg")
    seqno: int
    ts: int = Field(default_factory=now_ms)
    ct: str = Field(..., description="Base64 ciphertext")
    sig: str = Field(..., description="Base64 RSA signature over SHA256(seqno||ts||ct)")


# ---------------------------------------------------------------
# 4️⃣ Non-Repudiation Receipt
# ---------------------------------------------------------------

class Receipt(BaseModel):
    type: str = Field(default="receipt")
    peer: str = Field(..., description="client|server")
    first_seq: int
    last_seq: int
    transcript_sha256: str = Field(..., description="Hex digest of transcript")
    sig: str = Field(..., description="Base64 RSA signature of transcript hash")


# ---------------------------------------------------------------
# Optional: helper registry
# ---------------------------------------------------------------

MESSAGE_TYPES = {
    "hello": Hello,
    "server_hello": ServerHello,
    "register": Register,
    "login": Login,
    "dh_client": DHClient,
    "dh_server": DHServer,
    "msg": Msg,
    "receipt": Receipt,
}


def parse_message(data: dict) -> BaseModel:
    """
    Automatically parse a message dict into the correct Pydantic model.
    """
    msg_type = data.get("type")
    model = MESSAGE_TYPES.get(msg_type)
    if not model:
        raise ValueError(f"Unknown message type: {msg_type}")
    return model(**data)


# --- CLI Testing Helper ---
if __name__ == "__main__":
    print("[+] Testing protocol models")

    hello = Hello(client_cert="BASE64CERT", nonce="RANDOMNONCE")
    msg = Msg(seqno=1, ct="abcd1234", sig="deadbeef")

    try:
        # Pydantic v2
        print(hello.model_dump_json(indent=2))
        print(msg.model_dump_json(indent=2))
    except AttributeError:
        # Fallback for Pydantic v1
        print(hello.json(indent=2))
        print(msg.json(indent=2))

