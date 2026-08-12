from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timezone

from sqlalchemy import select

from app.core.db import async_session
from app.core.embeddings import get_embedding
from app.core.models import Instance, KnowledgeExample, Scenario, User
from app.core.security import hash_password

logger = logging.getLogger("cyberlab.db_ops")


async def get_user_by_username(username: str) -> User | None:
    async with async_session() as session:
        result = await session.execute(select(User).where(User.username == username))
        return result.scalar_one_or_none()


async def create_user(username: str, password_hash: str) -> None:
    async with async_session() as session:
        session.add(User(username=username, password_hash=password_hash))
        await session.commit()


async def seed_admin_user() -> None:
    """Cria o usuário admin na primeira vez que o backend sobe, com uma
    senha ALEATÓRIA — impressa nos logs uma única vez."""
    async with async_session() as session:
        result = await session.execute(select(User.id).limit(1))
        if result.scalar_one_or_none() is not None:
            return

    password = secrets.token_urlsafe(9)
    await create_user("admin", hash_password(password))
    logger.warning("=" * 60)
    logger.warning("USUÁRIO ADMIN CRIADO — anote a senha, só aparece uma vez:")
    logger.warning("  usuário: admin")
    logger.warning("  senha:   %s", password)
    logger.warning("=" * 60)


async def create_scenario(scenario_id: str, description: str, spec_dict: dict, variant: str = "default") -> None:
    async with async_session() as session:
        session.add(
            Scenario(
                id=scenario_id,
                name=spec_dict["name"],
                base_image=spec_dict["base_image"],
                vulnerability_type=spec_dict["vulnerability_type"],
                variant=variant,
                difficulty=spec_dict["difficulty"],
                setup_commands=spec_dict["setup_commands"],
                flag_location=spec_dict["flag_location"],
                hints=spec_dict["hints"],
                description=description,
            )
        )
        await session.commit()


async def create_instance(
    instance_id: str,
    scenario_id: str,
    job_id: str,
    container_name: str,
    attacker_container_name: str,
    network_name: str,
    target_host_port: int | None,
    flag_hash: str,
    user_id: str | None = None,
    root_flag_hash: str | None = None,
) -> None:
    async with async_session() as session:
        session.add(
            Instance(
                id=instance_id,
                scenario_id=scenario_id,
                user_id=user_id,
                job_id=job_id,
                container_name=container_name,
                attacker_container_name=attacker_container_name,
                network_name=network_name,
                target_host_port=target_host_port,
                status="pending",
                flag_hash=flag_hash,
                root_flag_hash=root_flag_hash,
            )
        )
        await session.commit()


async def update_instance_result(
    instance_id: str, status: str, setup_success: bool | None = None,
    flag_placed: bool | None = None, error: str | None = None,
) -> None:
    async with async_session() as session:
        result = await session.execute(select(Instance).where(Instance.id == instance_id))
        instance = result.scalar_one_or_none()
        if instance is None:
            return
        instance.status = status
        if setup_success is not None:
            instance.setup_success = setup_success
        if flag_placed is not None:
            instance.flag_placed = flag_placed
        if error is not None:
            instance.error = error
        await session.commit()


async def update_instance_port(instance_id: str, target_host_port: int) -> None:
    async with async_session() as session:
        result = await session.execute(select(Instance).where(Instance.id == instance_id))
        instance = result.scalar_one_or_none()
        if instance is None:
            return
        instance.target_host_port = target_host_port
        await session.commit()


async def mark_instance_destroyed(instance_id: str) -> None:
    async with async_session() as session:
        result = await session.execute(select(Instance).where(Instance.id == instance_id))
        instance = result.scalar_one_or_none()
        if instance is None:
            return
        instance.status = "destroyed"
        instance.destroyed_at = datetime.now(timezone.utc)
        await session.commit()


async def mark_all_instances_destroyed() -> int:
    async with async_session() as session:
        result = await session.execute(select(Instance).where(Instance.status != "destroyed"))
        instances = result.scalars().all()
        now = datetime.now(timezone.utc)
        for inst in instances:
            inst.status = "destroyed"
            inst.destroyed_at = now
        await session.commit()
        return len(instances)


async def list_recent_instances(limit: int = 20, user_id: str | None = None) -> list[dict]:
    async with async_session() as session:
        query = select(Instance).order_by(Instance.created_at.desc()).limit(limit)
        if user_id is not None:
            query = query.where(Instance.user_id == user_id)
        result = await session.execute(query)
        instances = result.scalars().all()
        output = []
        for inst in instances:
            await session.refresh(inst, attribute_names=["scenario"])
            output.append(
                {
                    "instance_id": inst.id,
                    "job_id": inst.job_id,
                    "user_id": inst.user_id,
                    "scenario_name": inst.scenario.name,
                    "vulnerability_type": inst.scenario.vulnerability_type,
                    "difficulty": inst.scenario.difficulty,
                    "hints": inst.scenario.hints,
                    "status": inst.status,
                    "setup_success": inst.setup_success,
                    "flag_placed": inst.flag_placed,
                    "solved": inst.solved,
                    "solved_at": inst.solved_at.isoformat() if inst.solved_at else None,
                    "has_root_stage": inst.root_flag_hash is not None,
                    "root_solved": inst.root_solved,
                    "root_solved_at": inst.root_solved_at.isoformat() if inst.root_solved_at else None,
                    "target_host_port": inst.target_host_port,
                    "created_at": inst.created_at.isoformat(),
                    "destroyed_at": inst.destroyed_at.isoformat() if inst.destroyed_at else None,
                }
            )
        return output


async def get_similar_knowledge_examples(
    query_text: str, vulnerability_type: str | None = None, limit: int = 3
) -> list[dict]:
    """
    RAG vetorial: busca exemplos validados por SIMILARIDADE SEMÂNTICA
    com a descrição do usuário (via embedding + distância de cosseno no
    pgvector), não só por tipo+data mais recente. Se o embedding falhar
    (Ollama fora do ar, modelo não baixado ainda) cai pro fallback
    simples em vez de quebrar a geração do cenário inteira.
    """
    query_embedding: list[float] | None = None
    try:
        query_embedding = await get_embedding(query_text)
    except Exception:  # noqa: BLE001
        logger.warning("Falha ao gerar embedding — usando fallback sem busca vetorial", exc_info=True)

    async with async_session() as session:
        if query_embedding is not None:
            query = select(KnowledgeExample).where(KnowledgeExample.embedding.is_not(None))
            if vulnerability_type is not None:
                query = query.where(KnowledgeExample.vulnerability_type == vulnerability_type)
            query = query.order_by(KnowledgeExample.embedding.cosine_distance(query_embedding)).limit(limit)
        else:
            query = select(KnowledgeExample).order_by(KnowledgeExample.created_at.desc()).limit(limit)
            if vulnerability_type is not None:
                query = query.where(KnowledgeExample.vulnerability_type == vulnerability_type)

        result = await session.execute(query)
        examples = result.scalars().all()
        return [
            {"description": ex.description, "difficulty": ex.difficulty, "hints": ex.hints}
            for ex in examples
        ]


async def submit_flag(instance_id: str, submitted_flag: str) -> dict:
    """
    Compara a flag submetida com os hashes guardados — pode bater com a
    flag de USUÁRIO (fase 1) ou a de ROOT (fase 2). O KnowledgeExample
    (matéria-prima do RAG) só é capturado quando TODAS as fases
    disponíveis nesse cenário foram resolvidas, e já sai com o embedding
    calculado — pronto pra entrar na busca vetorial imediatamente.
    """
    submitted_hash = hashlib.sha256(submitted_flag.strip().encode()).hexdigest()

    async with async_session() as session:
        result = await session.execute(select(Instance).where(Instance.id == instance_id))
        instance = result.scalar_one_or_none()
        if instance is None:
            return {"correct": False, "already_solved": False, "error": "instância não encontrada"}

        stage: str | None = None
        already_solved = False

        if submitted_hash == instance.flag_hash:
            stage = "user"
            already_solved = instance.solved
            if not instance.solved:
                instance.solved = True
                instance.solved_at = datetime.now(timezone.utc)
        elif instance.root_flag_hash and submitted_hash == instance.root_flag_hash:
            stage = "root"
            already_solved = instance.root_solved
            if not instance.root_solved:
                instance.root_solved = True
                instance.root_solved_at = datetime.now(timezone.utc)
        else:
            # Errou — conta como tentativa errada na fase em que o
            # usuário está atualmente (sinal de "onde as pessoas
            # travam" pro painel de analytics).
            if not instance.solved:
                instance.wrong_flag_attempts += 1
            elif instance.root_flag_hash and not instance.root_solved:
                instance.wrong_root_flag_attempts += 1
            await session.commit()
            return {"correct": False, "already_solved": False}

        fully_complete = instance.solved and (not instance.root_flag_hash or instance.root_solved)

        if fully_complete and not already_solved:
            await session.refresh(instance, attribute_names=["scenario"])
            existing = await session.execute(
                select(KnowledgeExample.id).where(KnowledgeExample.instance_id == instance.id)
            )
            if existing.scalar_one_or_none() is None:
                try:
                    embedding = await get_embedding(instance.scenario.description)
                except Exception:  # noqa: BLE001
                    logger.warning("Falha ao gerar embedding pro novo KnowledgeExample", exc_info=True)
                    embedding = None

                session.add(
                    KnowledgeExample(
                        scenario_id=instance.scenario_id,
                        instance_id=instance.id,
                        description=instance.scenario.description,
                        vulnerability_type=instance.scenario.vulnerability_type,
                        difficulty=instance.scenario.difficulty,
                        setup_commands=instance.scenario.setup_commands,
                        hints=instance.scenario.hints,
                        embedding=embedding,
                    )
                )

        await session.commit()

    return {
        "correct": True,
        "already_solved": already_solved,
        "stage": stage,
        "fully_complete": fully_complete,
        "has_root_stage": instance.root_flag_hash is not None,
    }


async def get_analytics_summary() -> list[dict]:
    """
    Agrega estatísticas por (tipo de vulnerabilidade, variante,
    dificuldade): taxa de conclusão, tempo médio até resolver, e
    tentativas erradas de flag (sinal de "onde as pessoas travam" —
    separado de setup_success_rate, que é sinal de confiabilidade da
    infraestrutura, não de dificuldade do exercício).
    """
    async with async_session() as session:
        result = await session.execute(select(Instance))
        instances = result.scalars().all()

        groups: dict[tuple[str, str, str], list[Instance]] = {}
        for inst in instances:
            await session.refresh(inst, attribute_names=["scenario"])
            key = (inst.scenario.vulnerability_type, inst.scenario.variant, inst.scenario.difficulty)
            groups.setdefault(key, []).append(inst)

        summary = []
        for (vuln_type, variant, difficulty), group in groups.items():
            total = len(group)
            setup_success = sum(1 for i in group if i.setup_success)
            user_solved = sum(1 for i in group if i.solved)
            has_root_group = any(i.root_flag_hash is not None for i in group)
            root_eligible = sum(1 for i in group if i.root_flag_hash is not None)
            root_solved = sum(1 for i in group if i.root_solved)
            abandoned = sum(
                1
                for i in group
                if i.destroyed_at is not None
                and not (i.solved and (not i.root_flag_hash or i.root_solved))
            )

            user_times = [
                (i.solved_at - i.created_at).total_seconds() for i in group if i.solved and i.solved_at
            ]
            root_times_total = [
                (i.root_solved_at - i.created_at).total_seconds()
                for i in group
                if i.root_solved and i.root_solved_at
            ]
            root_times_phase_only = [
                (i.root_solved_at - i.solved_at).total_seconds()
                for i in group
                if i.root_solved and i.root_solved_at and i.solved_at
            ]

            wrong_user = [i.wrong_flag_attempts for i in group]
            wrong_root = [i.wrong_root_flag_attempts for i in group if i.solved]

            def _avg(values: list[float]) -> float | None:
                return round(sum(values) / len(values), 2) if values else None

            summary.append(
                {
                    "vulnerability_type": vuln_type,
                    "variant": variant,
                    "difficulty": difficulty,
                    "total_generated": total,
                    "setup_success_rate": round(setup_success / total, 3) if total else None,
                    "user_flag_solve_rate": round(user_solved / total, 3) if total else None,
                    "has_root_stage": has_root_group,
                    "root_flag_solve_rate": round(root_solved / root_eligible, 3) if root_eligible else None,
                    "abandoned_count": abandoned,
                    "avg_time_to_user_flag_seconds": _avg(user_times),
                    "avg_time_to_root_flag_seconds": _avg(root_times_total),
                    "avg_time_root_phase_only_seconds": _avg(root_times_phase_only),
                    "avg_wrong_attempts_user": _avg(wrong_user),
                    "avg_wrong_attempts_root": _avg(wrong_root),
                }
            )

        summary.sort(key=lambda s: (s["vulnerability_type"], s["variant"], s["difficulty"]))
        return summary
