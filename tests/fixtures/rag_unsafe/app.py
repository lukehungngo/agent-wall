from langchain_community.vectorstores import FAISS

# AW-RAG-003: unencrypted persistence
db = FAISS.load_local("./faiss_index", embeddings)  # noqa: F821

# AW-RAG-004: no auth
from chromadb import HttpClient  # noqa: E402

client = HttpClient(host="localhost", port=8000)

# AW-RAG-001: no delimiters
docs = db.similarity_search(query)  # noqa: F821
prompt = f"Answer based on: {docs}\n\nQuestion: {query}"  # noqa: F821

# AW-RAG-002: untrusted ingestion
import requests  # noqa: E402

response = requests.get("https://example.com/data")
db.add_texts(response.json()["texts"])
