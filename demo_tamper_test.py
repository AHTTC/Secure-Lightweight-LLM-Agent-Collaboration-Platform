import json
import uuid

from cryptography.exceptions import InvalidSignature

from security_utils import (
    DEMO_SHARED_SECRET,
    EXECUTOR_IDENTITY,
    PLANNER_IDENTITY,
    SecureChannel,
    build_message_header,
)


def main():
    task_id = uuid.uuid4().hex
    conversation_id = uuid.uuid4().hex

    planner_channel = SecureChannel(DEMO_SHARED_SECRET, PLANNER_IDENTITY, EXECUTOR_IDENTITY)
    executor_channel = SecureChannel(DEMO_SHARED_SECRET, EXECUTOR_IDENTITY, PLANNER_IDENTITY)

    header = build_message_header(
        "TASK_REQUEST",
        PLANNER_IDENTITY.name,
        EXECUTOR_IDENTITY.name,
        conversation_id,
        task_id,
    )
    payload = {
        "task": "summarize_text",
        "instruction": "Summarize the supplied text in one short paragraph.",
        "content": "This message is used to demonstrate tamper detection.",
        "conversation_id": conversation_id,
        "task_id": task_id,
    }

    secure_message = planner_channel.encrypt_message(header, payload)
    received_header, received_payload = executor_channel.decrypt_message(secure_message)
    print("[OK] Valid message decrypted successfully.")
    print(f"     Header: {received_header}")
    print(f"     Payload task: {received_payload['task']}")

    tampered_envelope = json.loads(secure_message.decode("utf-8"))
    tampered_envelope["header"]["task_id"] = "tampered-task-id"
    tampered_message = json.dumps(tampered_envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")

    try:
        executor_channel.decrypt_message(tampered_message)
    except InvalidSignature:
        print("[OK] Tampered message rejected by Ed25519 signature verification.")
    except Exception as e:
        print(f"[OK] Tampered message rejected: {type(e).__name__}: {e}")
    else:
        raise RuntimeError("Tampered message was accepted unexpectedly.")


if __name__ == "__main__":
    main()
