# Secure Lightweight LLM Agent Collaboration Platform

## 1. 项目简介

本项目是 **Introduction to Cryptography for Cybersecurity** 课程的代码作业，实现了一个安全的轻量级多 Agent 协作平台。系统包含一个 **Planner Agent** 和一个 **Executor Agent**，二者通过本地 TCP socket 通信，并在不可信本地信道上演示消息的机密性、完整性、身份认证和结果可验证性。

系统的核心目标是：

- Planner Agent 接收用户请求，并拆分成一个或多个任务消息。
- Executor Agent 接收任务，处理任务，并返回结构化结果。
- 所有 Agent 间消息都使用统一的 framing 和 JSON envelope 格式。
- 通信内容使用 AES-GCM 加密。
- 消息 envelope 使用 Ed25519 数字签名。
- 收发双方校验 sender、receiver、signer、message type 和 payload 字段。
- 所有通信过程写入审计日志，便于 debugging 和 auditing。

本项目重点展示密码学机制，而不是构建工业级生产系统。

## 2. 文件结构

```text
.
├── README.md              # 中文项目说明
├── security_utils.py      # 加密、签名、身份、消息校验等安全工具
├── planner_client.py      # Planner Agent 客户端
├── executor_server.py     # Executor Agent 服务端
├── demo_tamper_test.py    # 篡改检测演示脚本
├── planner_audit.log      # Planner 审计日志
└── executor_audit.log     # Executor 审计日志
```

## 3. 核心功能

### 3.1 Planner Agent

文件：`planner_client.py`

Planner Agent 负责：

- 读取用户输入的任务描述。
- 根据关键词拆分任务，例如：
	- `classify_text`
	- `summarize_text`
	- `extract_key_points`
	- `analyze_text`
- 为每个任务生成唯一的 `conversation_id` 和 `task_id`。
- 构造 `TASK_REQUEST` 消息。
- 使用安全通道加密和签名消息。
- 通过 localhost socket 将任务发送给 Executor。
- 接收并验证 Executor 返回的 `TASK_RESULT` 消息。

### 3.2 Executor Agent

文件：`executor_server.py`

Executor Agent 负责：

- 在 `127.0.0.1:65432` 监听连接。
- 接收 Planner 发来的 framed message。
- 验证签名、身份、消息字段和密文完整性。
- 解密任务 payload。
- 处理任务并生成结构化结果。
- 构造 `TASK_RESULT` 响应。
- 对结果进行加密和签名后返回给 Planner。

如果环境变量中设置了 `GEMINI_API_KEY`，Executor 会尝试调用 Gemini API。  
如果没有设置 API key 或没有安装 `google-genai`，程序会自动使用本地模拟处理逻辑，保证作业演示可以正常运行。

### 3.3 安全工具模块

文件：`security_utils.py`

该文件实现了主要密码学功能：

- `AESGCM`：对 payload 进行认证加密。
- `Ed25519`：对 envelope 进行数字签名和验签。
- `AgentIdentity`：表示 Agent 身份，包括名称、公钥和私钥。
- `build_message_header()`：统一构造消息 header。
- `SecureChannel.encrypt_message()`：校验、加密和签名消息。
- `SecureChannel.decrypt_message()`：验签、身份校验、解密和字段验证。

## 4. 消息格式

系统使用 4 字节长度前缀进行 framing，保证 socket 上能正确读取完整消息。

加密前的逻辑消息分为两部分：

```json
{
	"header": {
		"version": 1,
		"msg_type": "TASK_REQUEST",
		"sender": "Planner-A",
		"receiver": "Executor-A",
		"conversation_id": "...",
		"task_id": "..."
	},
	"payload": {
		"task": "summarize_text",
		"instruction": "Summarize the supplied text in one short paragraph.",
		"content": "...",
		"conversation_id": "...",
		"task_id": "..."
	}
}
```

发送时，payload 会被 AES-GCM 加密，最终传输的 envelope 结构如下：

```json
{
	"version": 1,
	"header": {
		"version": 1,
		"msg_type": "TASK_REQUEST",
		"sender": "Planner-A",
		"receiver": "Executor-A",
		"conversation_id": "...",
		"task_id": "..."
	},
	"secure_data": "nonce_and_ciphertext_in_hex",
	"signer": "Planner-A",
	"signature": "ed25519_signature_in_hex"
}
```

其中：

- `secure_data` 包含 nonce 和 ciphertext。
- `signature` 是对 envelope 主要字段的 Ed25519 签名。
- `header` 作为 AES-GCM associated data，因此 header 被篡改时也会被检测。

## 5. 密码学安全属性

### 5.1 机密性 Confidentiality

项目使用 **AES-GCM** 对 payload 进行加密。

也就是说，任务内容、指令和执行结果不会以明文形式在 socket 中传输。攻击者即使截获了网络消息，也无法直接读取 payload 内容。

### 5.2 完整性 Integrity

项目通过两层机制保护完整性：

- AES-GCM 自带 authentication tag，可以检测密文或 associated data 被修改。
- Ed25519 数字签名可以检测 envelope 的关键字段是否被篡改。

如果攻击者修改 `secure_data`、`header` 或其他签名字段，接收方会在验签或解密阶段拒绝消息。

### 5.3 身份认证 Authentication

每个 Agent 都有自己的 Ed25519 公私钥身份：

- Planner Agent：`Planner-A`
- Executor Agent：`Executor-A`

接收方会检查：

- envelope 中的 `signer` 是否等于预期 peer identity。
- header 中的 `sender` 是否等于 signer。
- header 中的 `receiver` 是否等于本地 Agent。
- Ed25519 签名是否能用对方公钥验证。

这些检查可以防止未授权 Agent 冒充合法发送方。

### 5.4 不可否认性 Non-repudiation

Executor 返回的 `TASK_RESULT` 同样会经过 Ed25519 签名。

因此 Planner 收到结果后，可以验证该结果确实由 Executor 的私钥签名生成。这为任务结果提供了可验证性和不可否认性演示。

### 5.5 统一封装和校验

所有消息都使用一致的 envelope、header 和 payload 结构。程序会校验：

- 协议版本 `version`
- 消息类型 `msg_type`
- 发送方 `sender`
- 接收方 `receiver`
- 会话 ID `conversation_id`
- 任务 ID `task_id`
- payload 必需字段

这满足作业中对 consistent framing and validation scheme 的要求。

## 6. 运行环境

建议使用 Python 3.10 或以上版本。

必需依赖：

```bash
pip install cryptography
```

可选依赖：

```bash
pip install google-genai
```

`google-genai` 不是必须安装。如果没有安装，Executor 会使用本地模拟处理逻辑。

如果想调用 Gemini API，可以在运行前设置环境变量：

Windows PowerShell：

```powershell
$env:GEMINI_API_KEY="your_api_key_here"
```

macOS / Linux：

```bash
export GEMINI_API_KEY="your_api_key_here"
```

本项目不会在代码中硬编码 API key。

## 7. 如何运行主程序

### 第一步：启动 Executor Agent

打开一个终端，运行：

```bash
python executor_server.py
```

成功后会看到类似输出：

```text
[*] Executor Agent listening on 127.0.0.1:65432
```

### 第二步：启动 Planner Agent

再打开另一个终端，运行：

```bash
python planner_client.py "Please classify and summarize the following text: I love Multi-Agent Systems because secure collaboration is useful."
```

Planner 会将请求拆分成多个任务，并发送给 Executor。

示例输出：

```text
[*] Connected to Executor Agent

[+] Task: classify_text
[+] Response Header: {...}
[+] Response Payload: {...}

[+] Task: summarize_text
[+] Response Header: {...}
[+] Response Payload: {...}
```

## 8. 篡改检测演示

运行：

```bash
python demo_tamper_test.py
```

该脚本会执行两步：

1. 生成一条合法加密签名消息，并成功解密。
2. 人为修改消息中的 `task_id`，再尝试解密。

预期输出类似：

```text
[OK] Valid message decrypted successfully.
[OK] Tampered message rejected by Ed25519 signature verification.
```

这说明系统可以检测消息篡改，满足完整性验证要求。

## 9. 审计日志

系统会生成两个日志文件：

- `planner_audit.log`
- `executor_audit.log`

日志中包含：

- Agent 启动信息
- connection 信息
- `conversation_id`
- `task_id`
- task 类型
- response status
- 安全验证或处理失败信息

这些日志用于 debugging 和 auditing，符合题目对 logging all communications 的要求。

## 10. 与作业要求的对应关系

| 作业要求 | 当前实现 |
|---|---|
| Planner agent decomposes user query | `planner_client.py` 中 `extract_tasks()` 根据用户请求拆分任务 |
| Executor agent processes tasks | `executor_server.py` 中 `process_task()` 和 `llm_process()` 处理任务 |
| Structured task/result messages | 使用 `TASK_REQUEST` 和 `TASK_RESULT` 两类结构化消息 |
| Consistent framing | 使用 4 字节 big-endian 长度前缀 |
| Consistent validation | 校验 header、payload、sender、receiver、version 和 msg_type |
| Communication logging | `planner_audit.log` 和 `executor_audit.log` |
| Confidentiality | AES-GCM 加密 payload |
| Integrity | AES-GCM tag + Ed25519 签名 |
| Authentication | Ed25519 公钥验签 + sender/receiver/signer 校验 |
| Non-repudiation | Executor 对 `TASK_RESULT` 签名 |
| Networking / IPC | localhost TCP socket |
| At least two agents | Planner-A 和 Executor-A |

## 11. 设计说明

本项目为了课程演示，采用了清晰、轻量的设计：

- 将安全逻辑集中在 `security_utils.py`，避免重复代码。
- 将 Planner 和 Executor 分成两个独立程序，便于展示 Agent 间通信。
- 使用 JSON 作为消息格式，便于阅读和调试。
- 使用 canonical JSON 进行签名，避免字段顺序不同导致验签失败。
- 使用 audit log 记录通信流程，方便展示运行结果。

## 12. 注意事项和限制

本项目是课程作业演示版本，不是生产级安全系统。

当前限制包括：

- `DEMO_SHARED_SECRET` 是课程演示用共享密钥，真实系统应使用安全密钥交换或密钥管理服务。
- Agent 私钥是为了演示而在代码中确定性生成，真实系统应从受保护的密钥文件、证书或硬件安全模块加载。
- Planner 使用关键词规则拆分任务，不是完整的 LLM planning system。
- header 未加密，但作为 AES-GCM associated data 和 Ed25519 签名内容受到完整性保护。
- 当前只演示一个 Planner 和一个 Executor，可扩展为多个 Executor。

这些限制不影响本项目展示课程要求中的主要密码学机制。

## 13. 快速检查命令

语法检查：

```bash
python -m py_compile security_utils.py planner_client.py executor_server.py demo_tamper_test.py
```

篡改检测：

```bash
python demo_tamper_test.py
```

主程序演示：

```bash
python executor_server.py
```

另一个终端运行：

```bash
python planner_client.py "Please classify and summarize the following text: I love Multi-Agent Systems!"
```

## 14. 总结

本项目实现了一个安全的轻量级 Agent 协作平台。Planner Agent 可以拆分任务，Executor Agent 可以处理任务并返回结果。二者之间的通信通过 AES-GCM 和 Ed25519 提供机密性、完整性、身份认证和结果可验证性，并通过 socket 和 audit log 展示完整通信过程。

该实现覆盖了作业要求中的核心功能和核心密码学安全属性。
