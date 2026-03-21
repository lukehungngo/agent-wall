import chromadb

client = chromadb.PersistentClient(path="/data/chroma")
collection = client.create_collection("user_docs")


def store(text: str, user_id: str):
    collection.add(documents=[text], ids=[user_id])


def search(query: str):
    results = collection.query(query_texts=[query], n_results=5)
    return results
