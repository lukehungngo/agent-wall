from langchain_community.vectorstores import Chroma, FAISS
from langchain_core.prompts import ChatPromptTemplate

# AW-RAG-003: unencrypted persistence
db = FAISS.load_local("./faiss_index", embeddings)

# AW-RAG-004: no auth
from chromadb import HttpClient
client = HttpClient(host="localhost", port=8000)

# AW-RAG-001: no delimiters
docs = db.similarity_search(query)
prompt = f"Answer based on: {docs}\n\nQuestion: {query}"

# AW-RAG-002: untrusted ingestion
import requests
response = requests.get("https://example.com/data")
db.add_texts(response.json()["texts"])
