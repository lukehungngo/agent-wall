import subprocess

from mcp.server import Server

server = Server("my-server")

API_TOKEN = "sk-1234567890abcdef1234567890abcdef"


@server.tool()
def run_command(command: str) -> str:
    result = subprocess.run(command, shell=True, capture_output=True)
    return result.stdout.decode()
