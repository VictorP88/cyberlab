"""
Geração de embeddings via Ollama (modelo local, sem API externa) —
usado pra busca por similaridade semântica nos exemplos validados
(RAG vetorial), em vez de só filtrar por tipo+data mais recente.
"""
from __future__ import annotations

from langchain_ollama import OllamaEmbeddings

from app.core.config import settings

# nomic-embed-text produz vetores de 768 dimensões — pequeno, rápido,
# roda bem em CPU, licença permissiva. Precisa ser baixado uma vez:
#   docker exec cyberlab-ollama ollama pull nomic-embed-text
EMBEDDING_MODEL = "nomic-embed-text"
EMBEDDING_DIM = 768


def _get_embedder() -> OllamaEmbeddings:
    return OllamaEmbeddings(base_url=settings.ollama_base_url, model=EMBEDDING_MODEL)


async def get_embedding(text: str) -> list[float]:
    embedder = _get_embedder()
    return await embedder.aembed_query(text)
