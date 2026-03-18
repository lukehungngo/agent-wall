"""Fixture: Public endpoint writes to vector store without auth."""
from fastapi import FastAPI
from langchain_community.vectorstores import Chroma

app = FastAPI()
vectorstore = Chroma(collection_name="docs")


@app.post("/upload")
async def upload(data: dict):
    """No auth — anyone can write to the shared store."""
    vectorstore.add_documents(data["docs"], metadata={"source": "upload"})
    return {"status": "ok"}
