"""Generic RAG builder with caching based on embedding model and source."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from llama_index.core import Settings, SimpleDirectoryReader, VectorStoreIndex, load_index_from_storage, StorageContext
from llama_index.core.retrievers import VectorIndexRetriever
from llama_index.embeddings.openai import OpenAIEmbedding

OPENROUTER_API_BASE = "https://openrouter.ai/api/v1"


@dataclass(frozen=True)
class RetrievedChunk:
    """Retrieved document chunk with metadata."""
    text: str
    score: Optional[float]
    source: Optional[str]


def _get_index_path(embed_model: str, name: str) -> Path:
    """Get index storage path: store/{model}/{name}/
    
    Args:
        embed_model: Embedding model name (e.g., "text-embedding-3-small")
        name: User-provided name for the RAG
    
    Returns:
        Path to index storage directory
    """
    # Use model name, replacing slashes for filesystem safety
    model_dir = embed_model.replace("/", "_")
    return Path("store") / model_dir / name


def build_rag_index(
    source_dir: Path,
    api_key: str,
    embed_model: str = "text-embedding-3-small",
    chunk_size: int = 1024,
    chunk_overlap: int = 200,
    force_rebuild: bool = False,
    name: str = "default",
) -> VectorStoreIndex:
    """
    Build or load a cached RAG index.
    
    Args:
        source_dir: Directory containing documents to index
        api_key: OpenRouter API key for embeddings
        embed_model: Embedding model name (default: text-embedding-3-small)
        chunk_size: Document chunk size
        chunk_overlap: Overlap between chunks
        force_rebuild: Rebuild index even if cached
        name: Name to distinguish multiple RAGs (stored in store/{model}/{name}/)
    
    Returns:
        VectorStoreIndex ready for retrieval
    """
    index_path = _get_index_path(embed_model, name)

    # Try loading from cache
    if not force_rebuild and index_path.exists():
        try:
            print(f"Already built. Loading RAG index from cache: {index_path}")
            storage_context = StorageContext.from_defaults(persist_dir=str(index_path))
            return load_index_from_storage(storage_context)
        except Exception:
            # Cache corrupted or incompatible, rebuild
            pass

    # Build fresh index
    embedder = OpenAIEmbedding(
        model=embed_model,
        api_key=api_key,
        api_base=OPENROUTER_API_BASE,
    )

    Settings.embed_model = embedder
    Settings.chunk_size = chunk_size
    Settings.chunk_overlap = chunk_overlap

    documents = SimpleDirectoryReader(str(source_dir)).load_data()
    index = VectorStoreIndex.from_documents(documents)

    # Cache the index
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index.storage_context.persist(persist_dir=str(index_path))

    return index


def retrieve_from_index(
    index: VectorStoreIndex,
    query: str,
    top_k: int = 4,
) -> List[RetrievedChunk]:
    """
    Retrieve top-k chunks relevant to the query.
    
    Args:
        index: VectorStoreIndex to query
        query: Search query
        top_k: Number of top results to return
    
    Returns:
        List of RetrievedChunk objects
    """
    retriever = VectorIndexRetriever(index=index, similarity_top_k=top_k)
    nodes = retriever.retrieve(query)

    results: List[RetrievedChunk] = []
    for node in nodes:
        metadata = node.metadata or {}
        source = metadata.get("file_name") or metadata.get("file_path")
        results.append(
            RetrievedChunk(
                text=node.get_content(),
                score=getattr(node, "score", None),
                source=source,
            )
        )
    return results


def format_chunks(chunks: List[RetrievedChunk]) -> str:
    """Format retrieved chunks for prompt injection."""
    if not chunks:
        return ""

    formatted: List[str] = []
    for i, chunk in enumerate(chunks, start=1):
        header = f"[Context {i}]"
        if chunk.source:
            header += f" Source: {chunk.source}"
        formatted.append(header)
        formatted.append(chunk.text)

    return "\n\n".join(formatted)
