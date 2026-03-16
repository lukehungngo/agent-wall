from langchain.tools import tool
from langchain_community.vectorstores import Chroma

USER_ID = "user_123"

@tool
def get_user_data(user_id: str) -> str:
    """Get data for a specific user. Requires user_id scope check."""
    if user_id != USER_ID:
        raise PermissionError("Access denied")
    return f"Data for {user_id}"

vectorstore = Chroma(collection_name="user_docs")
query = "find my documents"
docs = vectorstore.similarity_search(query, filter={"user_id": USER_ID})
