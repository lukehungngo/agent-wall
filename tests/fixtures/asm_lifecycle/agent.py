"""Fixture: Full cross-tenant leakage — write without user metadata, read without filter, into LLM."""
from fastapi import FastAPI
from langchain_community.vectorstores import Chroma
from langchain_openai import ChatOpenAI

app = FastAPI()
vectorstore = Chroma(collection_name="shared")
llm = ChatOpenAI()


@app.post("/ingest")
async def ingest(data: dict):
    vectorstore.add_documents(data["docs"], metadata={"source": "api"})
    return {"ok": True}


@app.get("/ask")
async def ask(query: str):
    docs = vectorstore.similarity_search(query)
    context = "\n".join([d.page_content for d in docs])
    response = llm.invoke(f"Context: {context}\nQuestion: {query}")
    return {"answer": response}
