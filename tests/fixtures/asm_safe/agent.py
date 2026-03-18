"""Fixture: Properly isolated — auth on routes, user_id in metadata and filter."""
from fastapi import FastAPI, Depends
from langchain_community.vectorstores import Chroma
from langchain_openai import ChatOpenAI

app = FastAPI()
vectorstore = Chroma(collection_name="user_docs")
llm = ChatOpenAI()


def get_current_user():
    return {"id": "user123"}


@app.post("/ingest")
async def ingest(data: dict, user=Depends(get_current_user)):
    vectorstore.add_documents(data["docs"], metadata={"user_id": user["id"]})
    return {"ok": True}


@app.get("/ask")
async def ask(query: str, user=Depends(get_current_user)):
    docs = vectorstore.similarity_search(query, filter={"user_id": user["id"]})
    context = "\n".join([d.page_content for d in docs])
    response = llm.invoke(f"Context: {context}\nQuestion: {query}")
    return {"answer": response}
