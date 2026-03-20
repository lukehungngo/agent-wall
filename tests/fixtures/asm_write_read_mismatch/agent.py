# ruff: noqa: F821
"""Fixture: write metadata has 'source' but read filters on 'user_id' — key mismatch."""

from langchain_community.vectorstores import Chroma

vectorstore = Chroma(collection_name="docs")

# Write path: metadata has "source" only
vectorstore.add_documents(docs, metadata={"source": "web", "filename": "readme.md"})

# Read path: filter on "user_id" — but user_id was never written!
results = vectorstore.similarity_search("query", filter={"user_id": "u123"})
