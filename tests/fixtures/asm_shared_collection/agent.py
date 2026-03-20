"""Fixture: Static collection written by multiple endpoints, read without filter."""

from fastapi import FastAPI
from langchain_community.vectorstores import Chroma

app = FastAPI()
vectorstore = Chroma(collection_name="faq")


@app.post("/upload-a")
async def upload_a(data: dict):
    vectorstore.add_documents(data["docs"], metadata={"source": "a"})
    return {"ok": True}


@app.post("/upload-b")
async def upload_b(data: dict):
    vectorstore.add_documents(data["docs"], metadata={"source": "b"})
    return {"ok": True}


@app.get("/search")
async def search(query: str):
    results = vectorstore.similarity_search(query)
    return {"results": results}
