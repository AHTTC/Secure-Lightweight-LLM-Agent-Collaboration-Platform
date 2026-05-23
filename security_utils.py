import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
PROTOCOL_VERSION = 1
DEMO_SHARED_SECRET = b"ThisIsASecretKeyForAESGCM_32Byte"

PAYLOAD_REQUIRED_FIELDS = {
    "TASK_REQUEST": {"task", "instruction", "content", "conversation_id", "task_id"},
    "TASK_RESULT": {"status", "task", "task_id", "conversation_id", "processed_by", "result"},
}


@dataclass(frozen=True)
class AgentIdentity:
    name: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey


def _derive_seed(label: str) -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()


def make_identity(name: str, label: str) -> AgentIdentity:
    # Demo identity keys for the coursework. A real deployment would load
    # private keys from protected storage or certificates.
    private_key = Ed25519PrivateKey.from_private_bytes(_derive_seed(label))
    return AgentIdentity(name=name, private_key=private_key, public_key=private_key.public_key())


PLANNER_IDENTITY = make_identity("Planner-A", "FIT5163 Planner Agent")
EXECUTOR_IDENTITY = make_identity("Executor-A", "FIT5163 Executor Agent")


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_message_header(msg_type: str, sender: str, receiver: str, conversation_id: str, task_id: str) -> dict:
    return {
        "version": PROTOCOL_VERSION,
        "msg_type": msg_type,
        "sender": sender,
        "receiver": receiver,
        "conversation_id": conversation_id,
        "task_id": task_id,
    }


class SecureChannel:
    def __init__(self, shared_key: bytes, local_identity: AgentIdentity, peer_identity: AgentIdentity):
        self.aesgcm = AESGCM(shared_key)
        self.local_identity = local_identity
        self.peer_identity = peer_identity

    def _validate_header(self, header: dict) -> None:
        required_fields = {"version", "msg_type", "sender", "receiver", "conversation_id", "task_id"}
        if not isinstance(header, dict):
            raise ValueError("Header must be a JSON object")
        missing_fields = required_fields.difference(header)
        if missing_fields:
            raise ValueError(f"Header missing fields: {sorted(missing_fields)}")
        if header["version"] != PROTOCOL_VERSION:
            raise ValueError(f"Unsupported protocol version: {header['version']}")

    def _validate_payload(self, payload: dict) -> None:
        if not isinstance(payload, dict):
            raise ValueError("Payload must be a JSON object")

    def _validate_payload_for_type(self, msg_type: str, payload: dict) -> None:
        self._validate_payload(payload)
        required_fields = PAYLOAD_REQUIRED_FIELDS.get(msg_type)
        if not required_fields:
            raise ValueError(f"Unsupported message type: {msg_type}")
        missing_fields = required_fields.difference(payload)
        if missing_fields:
            raise ValueError(f"Payload missing fields: {sorted(missing_fields)}")

    def encrypt_message(self, header: dict, payload: dict) -> bytes:
        self._validate_header(header)
        self._validate_payload_for_type(header["msg_type"], payload)
        if header["sender"] != self.local_identity.name:
            raise ValueError("Outgoing message sender must match local identity")
        if header["receiver"] != self.peer_identity.name:
            raise ValueError("Outgoing message receiver must match peer identity")

        payload_bytes = canonical_json(payload)
        header_bytes = canonical_json(header)
        nonce = os.urandom(NONCE_SIZE)

        # AES-GCM encrypts the payload for confidentiality and also authenticates
        # the header as associated data, so header tampering is detected.
        ciphertext = self.aesgcm.encrypt(nonce, payload_bytes, header_bytes)
        secure_data = (nonce + ciphertext).hex()

        envelope = {
            "version": PROTOCOL_VERSION,
            "header": header,
            "secure_data": secure_data,
            "signer": self.local_identity.name,
        }

        # Ed25519 signs every encrypted envelope. This authenticates the sender
        # and makes task results verifiable by the receiver.
        signature_input = canonical_json(envelope)
        signature = self.local_identity.private_key.sign(signature_input).hex()
        envelope["signature"] = signature
        return canonical_json(envelope)

    def decrypt_message(self, raw_data: bytes) -> tuple[dict, dict]:
        envelope = json.loads(raw_data.decode("utf-8"))
        if not isinstance(envelope, dict):
            raise ValueError("Envelope must be a JSON object")

        required_fields = {"version", "header", "secure_data", "signature", "signer"}
        missing_fields = required_fields.difference(envelope)
        if missing_fields:
            raise ValueError(f"Envelope missing fields: {sorted(missing_fields)}")
        if envelope["version"] != PROTOCOL_VERSION:
            raise ValueError(f"Unsupported protocol version: {envelope['version']}")
        if envelope["signer"] != self.peer_identity.name:
            raise ValueError(f"Unexpected signer: {envelope['signer']}")

        signature = bytes.fromhex(envelope["signature"])
        signed_envelope = {
            "version": envelope["version"],
            "header": envelope["header"],
            "secure_data": envelope["secure_data"],
            "signer": envelope["signer"],
        }
        self.peer_identity.public_key.verify(signature, canonical_json(signed_envelope))

        header = envelope["header"]
        self._validate_header(header)
        if header["sender"] != self.peer_identity.name:
            raise ValueError("Sender identity does not match signer")
        if header["receiver"] != self.local_identity.name:
            raise ValueError("Message is not addressed to this agent")

        secure_data_bytes = bytes.fromhex(envelope["secure_data"])
        nonce = secure_data_bytes[:NONCE_SIZE]
        ciphertext = secure_data_bytes[NONCE_SIZE:]
        payload_bytes = self.aesgcm.decrypt(nonce, ciphertext, canonical_json(header))
        payload = json.loads(payload_bytes.decode("utf-8"))
        self._validate_payload_for_type(header["msg_type"], payload)
        return header, payload
