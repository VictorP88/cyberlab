"""
Validação e reparo determinístico do ScenarioSpec gerado pela LLM.
"""
from __future__ import annotations

import logging
import re

logger = logging.getLogger("cyberlab.spec_validator")

_MYSQL_SINGLE_QUOTE_RE = re.compile(r"^mysql\s+-e\s+'(.*)'$", re.DOTALL)


def _fix_broken_mysql_quoting(commands: list[str]) -> tuple[list[str], list[str]]:
    fixed: list[str] = []
    notes: list[str] = []
    for cmd in commands:
        match = _MYSQL_SINGLE_QUOTE_RE.match(cmd.strip())
        if match and "'" in match.group(1):
            inner = match.group(1)
            escaped = (
                inner.replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("$", "\\$")
                .replace("`", "\\`")
            )
            fixed.append(f'mysql -e "{escaped}"')
            notes.append("aspas simples aninhadas quebradas em 'mysql -e' - corrigidas para aspas duplas")
            continue
        fixed.append(cmd)
    return fixed, notes


def _has(commands: list[str], substring: str) -> bool:
    substring = substring.lower()
    return any(substring in c.lower() for c in commands)


def _last_install_index(commands: list[str]) -> int:
    for i in range(len(commands) - 1, -1, -1):
        low = commands[i].lower()
        if "apt-get install" in low or "apt install" in low:
            return i
    return len(commands) - 1


def validate_and_repair(commands: list[str]) -> tuple[list[str], list[str]]:
    commands = list(commands)
    notes: list[str] = []

    commands, quote_notes = _fix_broken_mysql_quoting(commands)
    notes.extend(quote_notes)

    joined = " ".join(commands).lower()

    installs_apache = "apache2" in joined and (
        "apt-get install" in joined or "apt install" in joined
    )
    if installs_apache and not (
        _has(commands, "service apache2 start") or _has(commands, "service apache2 restart")
    ):
        idx = _last_install_index(commands)
        commands.insert(idx + 1, "service apache2 start")
        notes.append("service apache2 start ausente - adicionado automaticamente")

    installs_mysql = "mysql-server" in joined
    installs_mariadb = "mariadb-server" in joined
    service_name = "mariadb" if installs_mariadb and not installs_mysql else "mysql"
    if (installs_mysql or installs_mariadb) and not (
        _has(commands, f"service {service_name} start")
        or _has(commands, f"service {service_name} restart")
    ):
        idx = _last_install_index(commands)
        commands.insert(idx + 1, f"service {service_name} start")
        notes.append(f"service {service_name} start ausente - adicionado automaticamente")

    installs_phpmyadmin = "phpmyadmin" in joined and "apt-get install" in joined
    has_link = _has(commands, "phpmyadmin.conf") or _has(commands, "a2enconf phpmyadmin")
    if installs_phpmyadmin and installs_apache and not has_link:
        commands.append(
            "ln -sf /etc/phpmyadmin/apache.conf /etc/apache2/conf-available/phpmyadmin.conf"
        )
        commands.append("a2enconf phpmyadmin")
        commands.append("service apache2 reload")
        notes.append("link phpMyAdmin -> Apache ausente - adicionado automaticamente")

    if installs_apache and installs_phpmyadmin and "libapache2-mod-php" not in joined:
        idx = _last_install_index(commands)
        commands.insert(idx + 1, "apt-get install -y libapache2-mod-php")
        commands.insert(idx + 2, "service apache2 restart")
        notes.append("libapache2-mod-php ausente - adicionado automaticamente")

    if notes:
        logger.warning("Spec reparado automaticamente: %s", "; ".join(notes))

    return commands, notes
