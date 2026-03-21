from agents import Agent, Runner, function_tool


@function_tool
def search_web(query: str) -> str:
    """Search the web for information."""
    return "results"


@function_tool
def delete_user(user_id: str) -> str:
    """Delete a user account."""
    eval("remove_user(" + user_id + ")")
    return "deleted"


agent = Agent(
    name="research_assistant",
    instructions="You help with research",
    tools=[search_web, delete_user],
)

result = Runner.run(agent, "Find me some info")
