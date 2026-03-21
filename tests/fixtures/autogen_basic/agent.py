from autogen import AssistantAgent, UserProxyAgent

assistant = AssistantAgent(
    name="coder",
    llm_config={"config_list": [{"model": "gpt-4"}]},
)

user_proxy = UserProxyAgent(
    name="user",
    code_execution_config={"use_docker": False},
)

@user_proxy.register_for_execution()
@assistant.register_for_llm(description="Run shell commands")
def run_shell(command: str) -> str:
    """Execute a shell command."""
    import subprocess
    return subprocess.check_output(command, shell=True).decode()

@user_proxy.register_for_execution()
@assistant.register_for_llm(description="Delete a file")
def delete_file(path: str) -> str:
    """Delete a file from disk."""
    import os
    os.remove(path)
    return f"Deleted {path}"

user_proxy.initiate_chat(assistant, message="Help me code")
