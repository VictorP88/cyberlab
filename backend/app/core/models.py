from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pgvector.sqlalchemy import Vector
from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.core.embeddings import EMBEDDING_DIM


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Scenario(Base):
    """O spec gerado pela LLM para um cenário. Um Scenario pode ter várias
    Instances ao longo do tempo (cada spawn é uma tentativa nova)."""

    __tablename__ = "scenarios"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(200))
    base_image: Mapped[str] = mapped_column(String(200))
    vulnerability_type: Mapped[str] = mapped_column(String(50))
    variant: Mapped[str] = mapped_column(String(50), default="default")
    difficulty: Mapped[str] = mapped_column(String(20))
    setup_commands: Mapped[list] = mapped_column(JSON)
    flag_location: Mapped[str] = mapped_column(String(500))
    hints: Mapped[list] = mapped_column(JSON)
    description: Mapped[str] = mapped_column(String(1000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    instances: Mapped[list["Instance"]] = relationship(back_populates="scenario")


class Instance(Base):
    """Um PAR target+attacker spawnado a partir de um Scenario. O id bate
    com o instance_id do orchestrator (label compartilhado pelos dois
    containers Docker)."""

    __tablename__ = "instances"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # = instance_id do orchestrator
    scenario_id: Mapped[str] = mapped_column(String(36), ForeignKey("scenarios.id"))
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    job_id: Mapped[str] = mapped_column(String(36), index=True)
    container_name: Mapped[str] = mapped_column(String(200))
    attacker_container_name: Mapped[str] = mapped_column(String(200))
    network_name: Mapped[str] = mapped_column(String(200))
    target_host_port: Mapped[int | None] = mapped_column(nullable=True)

    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|running|done|error|destroyed
    setup_success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    flag_placed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    flag_hash: Mapped[str] = mapped_column(String(64))  # sha256 hex, nunca a flag em claro
    solved: Mapped[bool] = mapped_column(Boolean, default=False)
    solved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    wrong_flag_attempts: Mapped[int] = mapped_column(default=0)
    # Fase 2 (escalonamento de privilégio) — nem todo cenário tem, por
    # isso fica nullable. Hoje SQLi (ambas variantes com privesc) e
    # Command Injection implementam essa fase.
    root_flag_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    root_solved: Mapped[bool] = mapped_column(Boolean, default=False)
    root_solved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    wrong_root_flag_attempts: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    destroyed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scenario: Mapped[Scenario] = relationship(back_populates="instances")


class KnowledgeExample(Base):
    """
    Um cenário que foi comprovadamente resolvido por um usuário de verdade
    (setup funcionou E a flag foi capturada via exploração real). Essa é
    a matéria-prima pro RAG: exemplos validados de setup_commands que
    funcionam, pra usar como referência na hora de gerar cenários novos.

    O campo `embedding` guarda o vetor semântico da descrição do usuário
    — permite buscar exemplos por SIMILARIDADE de significado, não só
    por tipo de vulnerabilidade + data mais recente.
    """

    __tablename__ = "knowledge_examples"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scenario_id: Mapped[str] = mapped_column(String(36), ForeignKey("scenarios.id"))
    instance_id: Mapped[str] = mapped_column(String(36), ForeignKey("instances.id"))
    description: Mapped[str] = mapped_column(String(1000))
    vulnerability_type: Mapped[str] = mapped_column(String(50))
    difficulty: Mapped[str] = mapped_column(String(20))
    setup_commands: Mapped[list] = mapped_column(JSON)
    hints: Mapped[list] = mapped_column(JSON)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(EMBEDDING_DIM), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
