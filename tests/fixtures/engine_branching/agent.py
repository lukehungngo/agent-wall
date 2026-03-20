from langchain_community.vectorstores import Chroma

db = Chroma(collection_name="docs")


def search(query, user_id=None):
    if user_id:
        return db.similarity_search(query, filter={"user_id": user_id})
    else:
        return db.similarity_search(query)  # NO FILTER on this path!
