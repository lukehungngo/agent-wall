from langchain_community.vectorstores import Chroma

db = Chroma(collection_name="shared_docs")
results = db.similarity_search("query")
