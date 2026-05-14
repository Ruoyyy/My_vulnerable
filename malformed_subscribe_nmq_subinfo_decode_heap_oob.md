# NanoMQ v0.24.10-14 Malformed `SUBSCRIBE`: Heap Buffer Overflow in `nmq_subinfo_decode`

## Describe the bug

A remote client can crash NanoMQ by sending a malformed MQTT `SUBSCRIBE` packet that ends immediately after the topic bytes and omits the required one-byte subscription options field.

The root issue is an off-by-one bounds check in `nmq_subinfo_decode()`. After consuming the topic body, the parser checks `if (bpos > remain)` and then immediately reads `*(payload_ptr + bpos)` as the subscription options byte. When the packet is truncated exactly at the end of the topic body, `bpos == remain`, so the check passes and the next read goes 1 byte past the end of the heap buffer.

With a carefully chosen `Remaining Length` of `1024`, `nni_msg_alloc()` takes the exact-allocation path with no extra tail room. Under ASan, this reproduces reliably as a `heap-buffer-overflow` and aborts the broker. This is a remote unauthenticated Denial-of-Service condition.

## Functional Background (NanoMQ `SUBSCRIBE` Parsing Path)

For each MQTT `SUBSCRIBE` topic entry, NanoMQ expects the payload to contain:

1. topic length (`uint16`)
2. topic bytes
3. one subscription options byte

Before the broker continues normal subscribe processing, NanoMQ extracts subscription metadata into `subinfol` by calling `nmq_subinfo_decode()`.

The parser must therefore verify that one byte is still available after the topic body before reading QoS / `no_local` / `rap` / `retain_handling`.

## Root Cause Analysis

### 1) TCP receive path allocates the MQTT body using the attacker-controlled Remaining Length

- file: `nng/src/sp/transport/mqtt/broker_tcp.c:791`
- function: `tcptran_pipe_recv_cb`
- behavior: `nni_msg_alloc(&p->rxmsg, (size_t) len)`

### 2) Exact 1024-byte bodies use exact heap allocation

- file: `nng/src/core/message.c:416-419`
- function: `nni_msg_alloc`
- behavior:
  - sizes `< 1024` or non-power-of-two sizes get extra head/tail room
  - power-of-two sizes `>= 1024` use `nni_chunk_grow(&m->m_body, sz, 0)`

This matters because a malformed `SUBSCRIBE` with `Remaining Length = 1024` leaves no extra tail bytes to absorb the off-by-one read.

### 3) Broker routes incoming `SUBSCRIBE` packets into `nmq_subinfo_decode`

- file: `nng/src/sp/transport/mqtt/broker_tcp.c:935-939`
- function: `tcptran_pipe_recv_cb`
- behavior: on `CMD_SUBSCRIBE`, the broker calls `nmq_subinfo_decode(msg, p->npipe->subinfol, ...)`

### 4) `nmq_subinfo_decode` performs the wrong boundary check for the final option byte

- file: `nng/src/sp/protocol/mqtt/mqtt_parser.c:1769-1779`
- function: `nmq_subinfo_decode`
- behavior:
  - after `bpos += len_of_topic`, the code checks:
    - `if (bpos > remain) return (-3);`
  - it then immediately reads:
    - `*(payload_ptr + bpos)`

This is off by one. At this point the code is about to read one byte, so it must reject `bpos == remain` as well. A packet that omits the final subscription-options byte reaches this exact state and triggers the OOB read.

### 5) ASan crash lands directly on the out-of-bounds read

On the current ASan build, the malformed packet produces:

- `READ of size 1`
- crash site: `nng/src/sp/protocol/mqtt/mqtt_parser.c:1776`
- call path: `tcptran_pipe_recv_cb -> nmq_subinfo_decode`
- allocated region: exactly `1024-byte region`

This demonstrates a real heap out-of-bounds read, not just a logical packet-length violation.

## Expected behavior

NanoMQ should reject the malformed `SUBSCRIBE` with a protocol error and keep the broker running.

## Actual Behavior

When the malformed packet is sent to the TCP listener:

1. the broker accepts a valid `CONNECT`
2. it receives the malformed `SUBSCRIBE`
3. `nmq_subinfo_decode()` reads one byte past the end of the message body
4. the ASan-instrumented broker aborts with `heap-buffer-overflow`

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

# Malformed SUBSCRIBE:
#   Remaining Length = 1024 (0x80 0x08)
#   packet id        = 0x0001
#   topic length     = 1020 (0x03fc)
#   topic body       = "A" * 1020
#   option byte      = intentionally omitted
body = b"\x00\x01" + b"\x03\xfc" + (b"A" * 1020)
sub = b"\x82\x80\x08" + body

with socket.create_connection((HOST, PORT), timeout=3) as s:
    s.sendall(connect)
    print("CONNACK:", s.recv(8).hex())
    time.sleep(0.2)
    s.sendall(sub)
    time.sleep(0.5)
```

### 3) Expected crash evidence

Expected ASan symptom:

- `heap-buffer-overflow`
- `READ of size 1`
- top frame in `nng/src/sp/protocol/mqtt/mqtt_parser.c:1776`

![image-20260401170006733](C:\Users\Administrator\Desktop\RuoyuZhou\bug_reports\assets\image-20260401170006733.png)

## Environment Details

- NanoMQ version:
  - `v0.24.10-14` (from `nanomq/include/version.h`)
  - current workspace commit: `0a3c709b2eafd23e05a837ea2e4ce87c6b7ad19d`
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
  - one malformed `SUBSCRIBE` with exact `Remaining Length = 1024`

## Client SDK

- No MQTT SDK is required.
- Reproduction uses a raw Python socket client that sends exact packet bytes.
- This keeps the trigger deterministic and avoids client-library normalization.

## Additional context

1. The malformed packet is valid up to the end of the topic body; the only missing field is the final one-byte subscription options value.
2. I confirmed this issue on the TCP path. The same shared parser is also referenced from MQTTS / WebSocket receive handling and should be reviewed as variant surfaces.
3. A second unsafe read pattern also exists later in `nanomq/sub_handler.c:123`, but the primary demonstrated crash occurs earlier in `nmq_subinfo_decode()`.
4. Security impact:
   - remote, unauthenticated DoS against the broker process.
5. Request to maintainers:
   - Please confirm and fix this issue as soon as possible so coordinated disclosure can proceed.
