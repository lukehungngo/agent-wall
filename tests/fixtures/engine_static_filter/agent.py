from langchain_community.vectorstores import Chroma

db = Chroma(collection_name="shared_docs")
db.add_texts(["hello"], metadata=[{"user_id": "u1", "source": "web"}])
results = db.similarity_search("query", filter={"source": "web"})
