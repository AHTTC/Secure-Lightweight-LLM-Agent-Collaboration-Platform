import logging
import socket
import struct
import sys
import uuid

from security_utils import (
    DEMO_SHARED_SECRET,
    EXECUTOR_IDENTITY,
    PLANNER_IDENTITY,
    SecureChannel,
    build_message_header,
)

HOST = "127.0.0.1"
PORT = 65432


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("planner")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler("planner_audit.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(stream_handler)
    return logger


def recv_exact(conn, num_bytes):
    data = bytearray()
    while len(data) < num_bytes:
        packet = conn.recv(num_bytes - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)


def send_framed(conn, payload: bytes):
    conn.sendall(struct.pack(">I", len(payload)) + payload)


def receive_framed(conn):
    raw_msglen = recv_exact(conn, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack(">I", raw_msglen)[0]
    return recv_exact(conn, msglen)


def extract_tasks(user_query: str):
    normalized = user_query.lower()
    tasks = []
    if any(keyword in normalized for keyword in ["classify", "classification"]):
        tasks.append(("classify_text", "Classify the sentiment or category of the supplied text."))
    if any(keyword in normalized for keyword in ["summarize", "summarise", "summary"]):
        tasks.append(("summarize_text", "Summarize the supplied text in one short paragraph."))
    if any(keyword in normalized for keyword in ["key points", "extract"]):
        tasks.append(("extract_key_points", "Extract the key points from the supplied text."))
    if not tasks:
        tasks.append(("analyze_text", "Provide a concise analysis of the supplied text."))
    return tasks


def get_user_query():
    if len(sys.argv) > 1:
        return " ".join(sys.argv[1:]).strip()
    try:
        query = input("Enter the task description: ").strip()
        if query:
            return query
    except EOFError:
        pass
    return "Please classify and summarize the following text: I love Multi-Agent Systems!"


def start_client():
    logger = setup_logger()
    secure_channel = SecureChannel(DEMO_SHARED_SECRET, PLANNER_IDENTITY, EXECUTOR_IDENTITY)
    conversation_id = uuid.uuid4().hex
    user_query = get_user_query()
    tasks = extract_tasks(user_query)

    logger.info("Planner started conversation=%s tasks=%s", conversation_id, [task_name for task_name, _ in tasks])

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[*] Connected to Executor Agent")

        for task_name, task_instruction in tasks:
            task_id = uuid.uuid4().hex
            header = build_message_header(
                "TASK_REQUEST",
                PLANNER_IDENTITY.name,
                EXECUTOR_IDENTITY.name,
                conversation_id,
                task_id,
            )
            payload = {
                "task": task_name,
                "instruction": task_instruction,
                "content": user_query,
                "conversation_id": conversation_id,
                "task_id": task_id,
            }

            logger.info("Sending request conversation=%s task_id=%s task=%s", conversation_id, task_id, task_name)
            encrypted_data = secure_channel.encrypt_message(header, payload)
            send_framed(s, encrypted_data)

            encrypted_response = receive_framed(s)
            if not encrypted_response:
                raise RuntimeError("Executor disconnected before returning a result")

            resp_header, resp_payload = secure_channel.decrypt_message(encrypted_response)
            logger.info(
                "Received response conversation=%s task_id=%s status=%s",
                resp_header["conversation_id"],
                resp_header["task_id"],
                resp_payload.get("status"),
            )
            print(f"\n[+] Task: {task_name}")
            print(f"[+] Response Header: {resp_header}")
            print(f"[+] Response Payload: {resp_payload}")


if __name__ == "__main__":
    start_client()
