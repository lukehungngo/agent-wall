from langchain.agents import AgentExecutor
from langchain.tools import tool
from langchain_community.vectorstores import Chroma


@tool
def query_users(query: str) -> str:
    """Query user database."""
    return "results"


@tool
def delete_users(user_id: str) -> str:
    """Delete a user from the database."""
    return "deleted"


# AW-AGT-001: sub-agent inherits all tools
parent_tools = [query_users, delete_users]
sub_agent = AgentExecutor(agent=llm, tools=parent_tools)  # noqa: F821

# AW-AGT-004: LLM output to memory without validation
result = llm.invoke("generate something")  # noqa: F821
vectorstore = Chroma()
vectorstore.add_texts([result.content])
