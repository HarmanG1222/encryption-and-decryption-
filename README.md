# encryption-and-decryption-
COSC3796_Assignment1_HarmanGrewal encryption and decryption 
#!/usr/bin/env python3
import socket
import argparse
import struct
import json
import threading
import os
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime

# Utility functions for length-prefixed JSON
def send_json(conn, obj):
    data = json.dumps(obj).encode()
    conn.sendall(struct.pack(">I", len(data)) + data)

def recv_json(conn):
    raw_len = recvall(conn, 4)
    if not raw_len:
        return None
    length = struct.unpack(">I", raw_len)[0]
    data = recvall(conn, length)
    if not data:
        return None
    return json.loads(data.decode())

def recvall(conn, n):
    data = b""
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# File helpers
def save_pem_private(key, filename):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, "wb") as f:
        f.write(pem)

def load_pem_private(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def save_pem_public(key, filename):
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, "wb") as f:
        f.write(pem)

def load_pem_public_data(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes)

class Client:
    def __init__(self, name, server_host, server_port):
        self.name = name
        self.server_addr = (server_host, server_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key_file = f"private_{name}.pem"
        self.public_key_file = f"public_{name}.pem"
        self.messages_file = f"messages_{name}.json"
        self.ensure_messages_file()
        self.session_keys = {}  # peername -> bytes (AES key)
        self.read_lock = threading.Lock()
        self.generate_or_load_keys()
        self.connect_and_register()
        # background listener
        t = threading.Thread(target=self.listen_loop, daemon=True)
        t.start()

    def ensure_messages_file(self):
        if not os.path.exists(self.messages_file):
            with open(self.messages_file, "w") as f:
                json.dump([], f, indent=2)

    def append_message_log(self, entry):
        with self.read_lock:
            with open(self.messages_file, "r+") as f:
                data = json.load(f)
                data.append(entry)
                f.seek(0)
                json.dump(data, f, indent=2)
                f.truncate()

    def generate_or_load_keys(self):
        if os.path.exists(self.private_key_file):
            self.priv = load_pem_private(self.private_key_file)
            with open(self.public_key_file, "rb") as f:
                self.pub_pem = f.read()
        else:
            # generate RSA 2048
            self.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.pub_pem = self.priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            save_pem_private(self.p
