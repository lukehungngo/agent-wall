from langchain.tools import tool
from langchain_community.vectorstores import Chroma


@tool
def search_web(query: str) -> str:
    """Search the web for information."""
    return f"Results for {query}"

vectorstore = Chroma(collection_name="shared_docs")
retriever = vectorstore.as_retriever()
