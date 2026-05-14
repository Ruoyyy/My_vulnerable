# Eclipse Mosquitto 2.0.23 MQTT v5 AUTH Method Mismatch Use-After-Free Remote Denial of Service Report

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

Confirmed affected version: the current workspace build of `2.0.23`.

I have not yet bisected the introduction point, so I cannot accurately state the earliest affected version. Based on the affected code path, versions containing the current MQTT v5 extended authentication `AUTH` handling implementation may be affected.

It is important to note that reachability depends on the broker being configured with extended authentication support, i.e. an authentication plugin supporting extended authentication is loaded. However, the vulnerability itself is in broker core `src/` code, not in plugin code.

## Details of the issue

**CWE:** `CWE-416 (Use After Free)`

The broker-side MQTT v5 `AUTH` packet handling path contains a real heap use-after-free read. When a client is already inside an extended authentication flow and then sends an `AUTH` packet whose `AUTHENTICATION_METHOD` property does not match the method stored in `context->auth_method`, the broker frees the newly received `auth_method` string and immediately passes that freed pointer as a `%s` argument to the logging path.

Because the broker logging implementation eventually formats the message via `vsnprintf()`, the freed heap buffer is dereferenced and ASan reliably reports a heap-use-after-free.

The issue is located at `src/handle_auth.c:98-102`:

```c
if(!auth_method || strcmp(auth_method, context->auth_method)){
    /* No method, or non-matching method */
    mosquitto__free(auth_method);
    mosquitto_property_free_all(&properties);
    send__disconnect(context, MQTT_RC_PROTOCOL_ERROR, NULL);
    log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s: AUTH packet with non-matching auth-method property (%s:%s).",
            context->id, context->auth_method, auth_method);
    return MOSQ_ERR_PROTOCOL;
}
```

Relevant code paths:

- `src/handle_auth.c:96-102`
- `src/logging.c:313`
- `src/read_handle.c:85`

Impact:

- A remote client can trigger a broker memory-safety error using only MQTT packets.
- Under ASan, this manifests reliably as a heap-use-after-free abort.
- Even without ASan, this is still a real memory-safety issue because the broker reads a freed heap object on an error path.
- This is a broker core lifetime bug in `src/`, not merely plugin misuse.

## Steps to reproduce

I confirmed this issue on the current workspace build of Mosquitto `2.0.23`.

This vulnerability does not require `memory_limit`, `reload`, or any local signal. The attacker only needs to send MQTT packets.  
However, to make `handle__auth()` reachable in practice, the broker must be configured with an authentication plugin that supports MQTT v5 extended authentication.

For reproduction, one convenient choice is to use the in-tree extended auth test plugin, for example:

- `test/broker/c/auth_plugin_extended_multiple.c`

A minimal example configuration is:

```conf
listener 18883
allow_anonymous true
auth_plugin c/auth_plugin_extended_multiple.so
```

`allow_anonymous true` is not required for the vulnerability itself. It is only used here to simplify the proof of concept. Any client that can reach a listener with extended authentication enabled can trigger the issue.

1. Run the broker using an ASan-enabled build.
2. Start the broker:

```bash
./src/mosquitto -c <config-file> -v
```

3. Establish a valid extended-authentication session so that `context->auth_method` is set. For example, first authenticate successfully using the method `"mirror"`.

4. Once the session has entered the extended-authentication context, send another `AUTH` packet whose `AUTHENTICATION_METHOD` is different from the current one, for example `"badmethod"`.

There is already an in-tree test sequence that maps almost directly to this path:

- `test/broker/09-extended-auth-multistep-reauth.py`

The key triggering step is:

- initial successful authentication with method `"mirror"`
- followed by a reauth using `"badmethod"`

That is:

```python
props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "badmethod")
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "step1")
reauth3_packet = mosq_test.gen_auth(reason_code=mqtt5_rc.MQTT_RC_REAUTHENTICATE, properties=props)
```

5. In my test environment, the ASan backtrace lands directly on the free/use ordering bug in the `handle__auth()` mismatch branch, similar to:

![image-20260401165710817](C:\Users\Administrator\Desktop\RuoyuZhou\bug_reports\assets\image-20260401165710817.png)

The key stack evidence I confirmed is:

- the read occurs in:
  - `printf_common`
  - `log__vprintf` at `src/logging.c:313`
  - `handle__auth` at `src/handle_auth.c:101`
- the free occurs in:
  - `handle__auth` at `src/handle_auth.c:98`

This matches the source-level free-then-log bug exactly.

## Do you know any mitigations of the issue?

Before a patch is available, the following mitigations may help:

- If MQTT v5 extended authentication is not needed, avoid enabling the relevant authentication plugins on externally exposed brokers.
- Restrict listeners using extended authentication to trusted clients only.
- Disable anonymous access for untrusted clients and limit access to listeners exposing extended-authentication functionality.
- As a temporary risk reduction measure, avoid exposing reauthentication-capable `AUTH` flows to untrusted MQTT clients.

From a remediation perspective, the most direct fix is:

- in `src/handle_auth.c`, move the mismatch-path logging call to before `mosquitto__free(auth_method)`, or
- avoid logging the received `auth_method` string at all on that error path.

<!--
  Please, do not remove the line below. It will create a confidential issue that will be visible
  only to you and the members of this project. Confidential issues are used to keep security
  vulnerabilities private until they are sorted out.
  Eclipse Projects follow Responsible Disclosure best practices: the initial report is made privately,
  but with the full details being published once a patch has been made available (sometimes with
  a delay to allow more time for the patches to be installed).
-->

/confidential
