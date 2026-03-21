from langchain.prompts import PromptTemplate
from langchain_community.vectorstores import Chroma
from langchain_openai import ChatOpenAI

db = Chroma(collection_name="docs")
retriever = db.as_retriever()
prompt = PromptTemplate.from_template("{context}")
llm = ChatOpenAI()
chain = prompt | llm | retriever
