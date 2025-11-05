#!/usr/bin/env python3
"""
Append-only transcript + TranscriptHash helpers.

Used for:
    - Securely storing chat message history (append-only)
    - Computing transcript hash for non-repudiation receipts
"""

import hashlib
import json
import os
from typing import List, Dict, Any


class Transcript:
    """
    Append-only transcript of chat messages.
    Stores all message dicts (already serialized via protocol layer).
    """

    def __init__(self, path: str = "transcript.log"):
        """
        Initialize transcript log.
        If file exists, load existing transcript.
        """
        self.path = path
        self.messages: List[Dict[str, Any]] = []

        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        self.messages.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue

    # -------------------------------------------------------------------------
    # Append-only interface
    # -------------------------------------------------------------------------
    def append(self, message: Dict[str, Any]):
        """
        Append a new message (dict) to the transcript.
        Auto-writes to disk as JSON line.
        """
        self.messages.append(message)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(message, ensure_ascii=False) + "\n")

    def all(self) -> List[Dict[str, Any]]:
        """Return all transcript messages."""
        return list(self.messages)

    def clear(self):
        """Clear transcript (useful for testing)."""
        self.messages.clear()
        if os.path.exists(self.path):
            os.remove(self.path)

    # -------------------------------------------------------------------------
    # Hashing helpers
    # -------------------------------------------------------------------------
    def compute_hash(self) -> str:
        """
        Compute SHA-256 hash of the transcript content (line order preserved).
        Returns hex digest (for receipt signing).
        """
        h = hashlib.sha256()
        for msg in self.messages:
            h.update(json.dumps(msg, sort_keys=True).encode())
        return h.hexdigest()

    def save_hash(self, hash_path: str = "transcript.sha256"):
        """
        Save current transcript hash to a file (for later verification).
        """
        digest = self.compute_hash()
        with open(hash_path, "w", encoding="utf-8") as f:
            f.write(digest)
        return digest


# --- CLI Testing Helper ---
if __name__ == "__main__":
    print("[+] Testing transcript layer")

    t = Transcript("test_transcript.log")
    t.clear()

    print("[*] Appending sample messages...")
    t.append({"type": "msg", "seqno": 1, "data": "Hello"})
    t.append({"type": "msg", "seqno": 2, "data": "World"})

    print("[*] All messages:", t.all())
    digest = t.compute_hash()
    print("[*] Transcript SHA-256:", digest)

    t.save_hash("test_transcript.sha256")
    print("[+] Saved hash to test_transcript.sha256")
