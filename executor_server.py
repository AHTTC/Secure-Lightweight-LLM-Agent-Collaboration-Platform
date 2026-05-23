import logging
import os
import socket
import struct

try:
    from google import genai
except ImportError:
    genai = None

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
    logger = logging.getLogger("executor")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler("executor_audit.log", encoding="utf-8")
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


def local_process(instruction: str, content: str) -> str:
    if "classify" in instruction.lower():
        lowered = content.lower()
        if any(word in lowered for word in ["love", "good", "great", "excellent", "happy"]):
            return "Positive text."
        if any(word in lowered for word in ["hate", "bad", "terrible", "sad"]):
            return "Negative text."
        return "Neutral text."
    if "summarize" in instruction.lower():
        return content[:180] + ("..." if len(content) > 180 else "")
    if "key points" in instruction.lower():
        parts = [part.strip() for part in content.replace("\n", " ").split(".") if part.strip()]
        return "; ".join(parts[:3]) if parts else "No clear key points found."
    return f"Analyzed content length: {len(content)} characters."


def llm_process(instruction: str, content: str) -> str:
    """Use Gemini when an API key is configured; otherwise use a local demo response."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or genai is None:
        return local_process(instruction, content)

    prompt = f"Instruction: {instruction}\n\nContent: {content}\n\nResult:"
    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        return response.text.strip()
    except Exception as e:
        return f"LLM Error: {str(e)}"


def process_task(payload: dict) -> dict:
    task_name = payload.get("task", "analyze_text")
    instruction = payload.get("instruction", "Analyze the text.")
    content = payload.get("content", "")

    result_text = llm_process(instruction, content)
    return {task_name: result_text}


def start_server():
    logger = setup_logger()
    secure_channel = SecureChannel(DEMO_SHARED_SECRET, EXECUTOR_IDENTITY, PLANNER_IDENTITY)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        logger.info("Executor listening on %s:%s", HOST, PORT)
        print(f"[*] Executor Agent listening on {HOST}:{PORT}")

        conn, addr = s.accept()
        with conn:
            logger.info("Accepted connection from %s", addr)
            print(f"[*] Connected by {addr}")
            while True:
                encrypted_data = receive_framed(conn)
                if not encrypted_data:
                    break

                try:
                    header, payload = secure_channel.decrypt_message(encrypted_data)
                    logger.info(
                        "Received request conversation=%s task_id=%s task=%s",
                        header["conversation_id"],
                        header["task_id"],
                        payload.get("task"),
                    )
                    print(f"\n[+] Decrypted Request Header: {header}")
                    print(f"[+] Decrypted Request Payload: {payload}")

                    result_body = process_task(payload)
                    result_payload = {
                        "status": "success",
                        "task": payload.get("task"),
                        "task_id": header["task_id"],
                        "conversation_id": header["conversation_id"],
                        "processed_by": EXECUTOR_IDENTITY.name,
                        "result": result_body,
                    }
                    result_header = build_message_header(
                        "TASK_RESULT",
                        EXECUTOR_IDENTITY.name,
                        PLANNER_IDENTITY.name,
                        header["conversation_id"],
                        header["task_id"],
                    )
                    logger.info(
                        "Sending response conversation=%s task_id=%s task=%s",
                        header["conversation_id"],
                        header["task_id"],
                        payload.get("task"),
                    )
                    response_data = secure_channel.encrypt_message(result_header, result_payload)
                    send_framed(conn, response_data)

                except Exception as e:
                    logger.exception("Security or processing failure: %s", e)
                    print(f"[-] Security Error or Decryption Failed: {e}")
                    break


if __name__ == "__main__":
    start_server()
