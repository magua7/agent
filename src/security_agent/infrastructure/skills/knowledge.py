"""No-op knowledge provider used until an optional index is configured."""

from __future__ import annotations

from security_agent.contracts import KnowledgeDocument


class NullKnowledgeProvider:
    async def search(self, query: str, limit: int = 10) -> tuple[KnowledgeDocument, ...]:
        del query, limit
        return ()

    async def get(self, document_id: str) -> KnowledgeDocument | None:
        del document_id
        return None
