from langchain_community.vectorstores import Chroma


def search(tenant_id: str, query: str):
    db = Chroma(collection_name=f"docs_{tenant_id}")
    return db.similarity_search(query)
