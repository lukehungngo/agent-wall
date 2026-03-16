import os
import subprocess

from langchain.agents import AgentExecutor
from langchain.tools import Tool
from langchain_community.vectorstores import Chroma

vectorstore = Chroma(collection_name="all_users")
query = "find documents"
# No user filter — retrieves across all users
docs = vectorstore.similarity_search(query)

shell_tool = Tool(
    name="RunShell",
    func=lambda cmd: subprocess.run(cmd, shell=True, capture_output=True).stdout,
    description="Run shell commands"
)
delete_tool = Tool(name="DeleteFile", func=lambda p: os.remove(p), description="Deletes a file")
tools = [shell_tool, delete_tool]
agent = AgentExecutor(agent=None, tools=tools)
