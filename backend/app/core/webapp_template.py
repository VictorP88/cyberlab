"""
Templates determinísticos das aplicações vulneráveis — front (HTML/CSS),
back (PHP) e infraestrutura sempre entregues de forma fixa por tipo de
vulnerabilidade + variante + dificuldade, sem depender da LLM pra
escrever código de aplicação.

A dificuldade agora é um eixo TÉCNICO real, não só um rótulo narrativo:
  - easy:   erro/saída sempre visível — guia direta a exploração
  - medium: sem erro/saída, mas ainda com sinal (dado extraído ou tempo
            de resposta) — exige mais cuidado, sem "cola"
  - hard:   totalmente cego — só oráculo booleano (SQLi) ou execução
            assíncrona forçando exfiltração fora de banda (Command
            Injection)
"""
from __future__ import annotations


# ============================================================
# SQLi — site com múltiplas páginas (reconhecimento de verdade)
# + fase de escalonamento de privilégio via SSH
# ============================================================

def build_landing_php(company_name: str = "TechCorp Solutions") -> str:
    """Página inicial de uma 'empresa' fake — o login fica escondido
    atrás de um link, não é a primeira coisa que aparece."""
    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>{company_name}</title>
<style>
body{{font-family:sans-serif;background:#f4f4f4;color:#222;margin:0}}
header{{background:#1c2b3a;color:#fff;padding:1.5rem 2rem}}
nav a{{color:#9fd3ff;margin-right:1.5rem;text-decoration:none}}
.hero{{padding:3rem 2rem;max-width:700px}}
footer{{padding:1rem 2rem;color:#888;font-size:0.85rem}}
</style>
</head>
<body>
<header>
<h1>{company_name}</h1>
<nav>
<a href="/">Início</a>
<a href="/about.php">Sobre</a>
<a href="/login.php">Portal do Funcionário</a>
</nav>
</header>
<div class="hero">
<h2>Bem-vindo ao portal corporativo</h2>
<p>Soluções em tecnologia pra sua empresa. Acesse o portal do
funcionário pra consultar informações internas.</p>
</div>
<footer>&copy; {company_name}. Todos os direitos reservados.</footer>
</body>
</html>
"""


def build_about_php(company_name: str = "TechCorp Solutions") -> str:
    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"><title>Sobre - {company_name}</title>
<style>body{{font-family:sans-serif;background:#f4f4f4;color:#222;padding:2rem;max-width:700px;margin:0 auto}}
a{{color:#1c2b3a}}</style>
</head>
<body>
<h1>Sobre a {company_name}</h1>
<p>Fundada com o objetivo de entregar soluções corporativas robustas.</p>
<p><a href="/">&larr; Voltar</a></p>
</body>
</html>
"""


def build_robots_txt() -> str:
    return "User-agent: *\nDisallow: /login.php\n"


def build_login_php(db_password: str, difficulty: str = "easy") -> str:
    """
    A senha do banco vai direto no código PHP gerado (nunca via
    getenv()). O comportamento da resposta muda por dificuldade:
      - easy:   mostra erro de sintaxe SQL quando houver
      - medium: some com o erro, mas UNION ainda revela dado direto
      - hard:   oráculo booleano puro ("permitido"/"negado"), NUNCA
                revela dado — extração exige blind SQLi de verdade
                (sqlmap --technique=B é o caminho realista)
    """
    escaped = db_password.replace("\\", "\\\\").replace("'", "\\'")

    if difficulty == "hard":
        response_logic = """    if ($result && $result->num_rows > 0) {
        $message = "Acesso permitido.";
    } else {
        $message = "Acesso negado.";
    }
"""
    elif difficulty == "medium":
        response_logic = """    if ($result && $result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $message = "Login bem-sucedido! Bem-vindo, " . htmlspecialchars($row['username']) . ".";
        if ($row['username'] === 'admin') {
            $message .= "<br>Flag: " . htmlspecialchars($row['flag'] ?? '');
        }
    } else {
        $message = "Usuário ou senha inválidos.";
    }
"""
    else:
        response_logic = """    if ($result && $result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $message = "Login bem-sucedido! Bem-vindo, " . htmlspecialchars($row['username']) . ".";
        if ($row['username'] === 'admin') {
            $message .= "<br>Flag: " . htmlspecialchars($row['flag'] ?? '');
        }
    } else {
        $message = "Usuário ou senha inválidos.";
        if ($conn->error) {
            $message .= "<br><small>Erro SQL: " . htmlspecialchars($conn->error) . "</small>";
        }
    }
"""

    return f"""<?php
// Desde o PHP 8.1, mysqli lança exceção em QUALQUER erro de query por
// padrão — inclusive erros de sintaxe SQL, esperados ao testar SQLi.
mysqli_report(MYSQLI_REPORT_OFF);
$conn = new mysqli('127.0.0.1', 'root', '{escaped}', 'cyberlab');
$message = '';
if ($conn->connect_error) {{
    $message = "Erro de conexão com o banco de dados. Tente novamente em instantes.";
}} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {{
    $user = $_POST['username'] ?? '';
    $pass = $_POST['password'] ?? '';
    // Vulnerável de propósito: concatenação direta sem sanitização (SQLi).
    $sql = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
    $result = $conn->query($sql);
{response_logic}}}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Portal do Funcionário</title>
<style>
body{{font-family:sans-serif;background:#111;color:#eee;display:flex;justify-content:center;padding-top:80px}}
form{{background:#1c1c1c;padding:2rem;border-radius:8px;width:300px}}
input{{width:100%;padding:8px;margin:6px 0;border-radius:4px;border:1px solid #444;background:#222;color:#eee;box-sizing:border-box}}
button{{width:100%;padding:8px;background:#4f7cff;color:#fff;border:none;border-radius:4px;cursor:pointer}}
.msg{{max-width:400px;margin:0 auto 1rem;text-align:center}}
</style>
</head>
<body>
<div>
<div class="msg"><?= $message ?></div>
<form method="POST">
<h2>Login</h2>
<input type="text" name="username" placeholder="usuário" autocomplete="off">
<input type="password" name="password" placeholder="senha" autocomplete="off">
<button type="submit">Entrar</button>
</form>
</div>
</body>
</html>
"""


def build_sqli_pre_app_commands(db_password: str) -> list[str]:
    """Infraestrutura idêntica independente da dificuldade — só o PHP
    entregue muda. -o Acquire::Retries=3 protege contra soluços de rede."""
    return [
        "apt-get update",
        "apt-get install -y -o Acquire::Retries=3 apache2 libapache2-mod-php php-mysql mysql-server",
        "service mysql start",
        "sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf",
        "echo 'skip-name-resolve' >> /etc/mysql/mysql.conf.d/mysqld.cnf",
        "service mysql restart",
        f"mysql -e \"CREATE USER 'root'@'%' IDENTIFIED WITH mysql_native_password BY '{db_password}'; "
        f"GRANT ALL PRIVILEGES ON *.* TO 'root'@'%'; FLUSH PRIVILEGES;\"",
        f"mysql -e \"CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED WITH mysql_native_password BY '{db_password}'; "
        f"GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1'; FLUSH PRIVILEGES;\"",
        "mysql -e \"CREATE DATABASE IF NOT EXISTS cyberlab;\"",
        "mysql cyberlab -e \"CREATE TABLE IF NOT EXISTS users ("
        "id INT AUTO_INCREMENT PRIMARY KEY, "
        "username VARCHAR(50), password VARCHAR(50), flag VARCHAR(100));\"",
    ]


def build_sqli_post_app_commands(
    admin_password: str, flag_value: str, flag_location: str, webadmin_password: str, root_flag_value: str
) -> list[str]:
    """Fase 2: SSH com senha reutilizada + sudoers mal configurado
    (NOPASSWD em /usr/bin/find, GTFOBins). Igual em todas as dificuldades
    — a dificuldade afeta só a fase 1 (o PHP)."""
    return [
        f"mysql cyberlab -e \"INSERT INTO users (username, password, flag) "
        f"VALUES ('admin', '{admin_password}', '{flag_value}');\"",
        f"echo '{flag_value}' > {flag_location}",
        "rm -f /var/www/html/index.html",
        "service apache2 start",
        "apt-get install -y -o Acquire::Retries=3 openssh-server sudo",
        "useradd -m -s /bin/bash webadmin",
        f"echo 'webadmin:{webadmin_password}' | chpasswd",
        "service ssh start",
        "echo 'webadmin ALL=(ALL) NOPASSWD: /usr/bin/find' > /etc/sudoers.d/cyberlab",
        "chmod 440 /etc/sudoers.d/cyberlab",
        f"echo '{root_flag_value}' > /root/root_flag.txt",
        "chmod 600 /root/root_flag.txt",
    ]


# ============================================================
# SQLi — variante 2: busca de produtos (uma fase só, sem privesc)
# Injeção via parâmetro GET (URL), não formulário de login.
# ============================================================

def build_search_landing_php(company_name: str = "InventoryTrack") -> str:
    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>{company_name}</title>
<style>
body{{font-family:sans-serif;background:#f4f4f4;color:#222;margin:0}}
header{{background:#1c2b3a;color:#fff;padding:1.5rem 2rem}}
nav a{{color:#9fd3ff;margin-right:1.5rem;text-decoration:none}}
.hero{{padding:3rem 2rem;max-width:700px}}
</style>
</head>
<body>
<header>
<h1>{company_name}</h1>
<nav><a href="/">Início</a><a href="/search.php">Buscar Produtos</a></nav>
</header>
<div class="hero">
<h2>Sistema interno de inventário</h2>
<p>Use a busca de produtos pra consultar o catálogo.</p>
</div>
</body>
</html>
"""


def build_search_php(db_password: str, difficulty: str = "easy") -> str:
    """
    Busca de produtos vulnerável a SQLi via parâmetro GET.
      - easy:   mostra erro SQL, resultados visíveis
      - medium: sem erro SQL, resultados ainda visíveis (UNION funciona)
      - hard:   só diz "encontrado(s)"/"nenhum resultado" — oráculo
                booleano puro, nunca mostra dado
    """
    escaped = db_password.replace("\\", "\\\\").replace("'", "\\'")

    if difficulty == "hard":
        query_logic = """    $sql = "SELECT name, description FROM products WHERE name LIKE '%$search%'";
    $result = $conn->query($sql);
    if ($result && $result->num_rows > 0) {
        $error = "Resultado(s) encontrado(s).";
    } else {
        $error = "Nenhum resultado encontrado.";
    }
"""
    elif difficulty == "medium":
        query_logic = """    $sql = "SELECT name, description FROM products WHERE name LIKE '%$search%'";
    $result = $conn->query($sql);
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $results[] = $row;
        }
    }
"""
    else:
        query_logic = """    $sql = "SELECT name, description FROM products WHERE name LIKE '%$search%'";
    $result = $conn->query($sql);
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $results[] = $row;
        }
    } else {
        $error = "Erro SQL: " . htmlspecialchars($conn->error);
    }
"""

    return f"""<?php
mysqli_report(MYSQLI_REPORT_OFF);
$conn = new mysqli('127.0.0.1', 'root', '{escaped}', 'cyberlab');
$results = [];
$error = '';
$search = $_GET['search'] ?? '';
if ($conn->connect_error) {{
    $error = "Erro de conexão com o banco de dados.";
}} elseif ($search !== '') {{
    // Vulnerável de propósito: concatenação direta em query GET (SQLi
    // refletida via URL, sem sanitização nenhuma).
{query_logic}}}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Buscar Produtos</title>
<style>
body{{font-family:sans-serif;background:#111;color:#eee;padding:2rem}}
.box{{max-width:700px;margin:0 auto}}
input{{width:70%;padding:8px;border-radius:4px;border:1px solid #444;background:#222;color:#eee}}
button{{padding:8px 16px;background:#4f7cff;color:#fff;border:none;border-radius:4px;cursor:pointer}}
table{{width:100%;border-collapse:collapse;margin-top:1rem}}
td,th{{border:1px solid #444;padding:8px;text-align:left}}
.err{{color:#ff6b6b}}
</style>
</head>
<body>
<div class="box">
<h2>Buscar Produtos</h2>
<form method="GET">
<input type="text" name="search" placeholder="nome do produto" value="<?= htmlspecialchars($search) ?>">
<button type="submit">Buscar</button>
</form>
<?php if ($error): ?><p class="err"><?= $error ?></p><?php endif; ?>
<?php if ($results): ?>
<table>
<tr><th>Nome</th><th>Descrição</th></tr>
<?php foreach ($results as $row): ?>
<tr><td><?= htmlspecialchars($row['name']) ?></td><td><?= htmlspecialchars($row['description']) ?></td></tr>
<?php endforeach; ?>
</table>
<?php endif; ?>
</div>
</body>
</html>
"""


def build_search_pre_app_commands(db_password: str) -> list[str]:
    return [
        "apt-get update",
        "apt-get install -y -o Acquire::Retries=3 apache2 libapache2-mod-php php-mysql mysql-server",
        "service mysql start",
        "sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf",
        "echo 'skip-name-resolve' >> /etc/mysql/mysql.conf.d/mysqld.cnf",
        "service mysql restart",
        f"mysql -e \"CREATE USER 'root'@'%' IDENTIFIED WITH mysql_native_password BY '{db_password}'; "
        f"GRANT ALL PRIVILEGES ON *.* TO 'root'@'%'; FLUSH PRIVILEGES;\"",
        f"mysql -e \"CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED WITH mysql_native_password BY '{db_password}'; "
        f"GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1'; FLUSH PRIVILEGES;\"",
        "mysql -e \"CREATE DATABASE IF NOT EXISTS cyberlab;\"",
        "mysql cyberlab -e \"CREATE TABLE IF NOT EXISTS products ("
        "id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100), description VARCHAR(200));\"",
        "mysql cyberlab -e \"CREATE TABLE IF NOT EXISTS secrets ("
        "id INT AUTO_INCREMENT PRIMARY KEY, flag VARCHAR(100));\"",
        "mysql cyberlab -e \"INSERT INTO products (name, description) VALUES "
        "('Cabo HDMI', 'Cabo 2m'), ('Mouse sem fio', 'Bluetooth'), ('Teclado mecânico', 'Switch azul');\"",
    ]


def build_search_post_app_commands(flag_value: str, flag_location: str) -> list[str]:
    return [
        f"mysql cyberlab -e \"INSERT INTO secrets (flag) VALUES ('{flag_value}');\"",
        f"echo '{flag_value}' > {flag_location}",
        "rm -f /var/www/html/index.html",
        "service apache2 start",
    ]


# ============================================================
# Command Injection — variante 1: ferramenta de diagnóstico de rede
# ============================================================

def build_command_injection_php(difficulty: str = "easy") -> str:
    """
    Ferramenta de "diagnóstico de rede" — roda `ping` no host informado.
      - easy:   saída completa sempre visível
      - medium: nenhuma saída visível — só dá pra confirmar via TEMPO
                de resposta (injeta `; sleep 5` e mede o delay)
      - hard:   execução em segundo plano (assíncrona) — a resposta
                HTTP volta sempre rápido, então nem tempo serve de
                sinal. Só resta exfiltração FORA DE BANDA (o alvo manda
                dado de volta pro atacante via /dev/tcp).
    """
    if difficulty == "hard":
        exec_logic = """    // Executa em segundo plano (detached) — a resposta HTTP volta
    // sempre rápido, independente do que o comando injetado faça.
    // Isso invalida tanto leitura direta de saída quanto blind por
    // tempo — só sobra exfiltração fora de banda (OOB).
    exec('ping -c 2 ' . $host . ' > /dev/null 2>&1 &');
    $output = "Ping enviado em segundo plano.";
"""
    elif difficulty == "medium":
        exec_logic = """    // Saída nunca é mostrada — só o comando roda de verdade (mesmo
    // processo, então o tempo de execução ainda é observável).
    shell_exec('ping -c 2 ' . $host . ' > /dev/null 2>&1');
    $output = "Ping enviado.";
"""
    else:
        exec_logic = """    // Vulnerável de propósito: shell_exec com entrada do usuário sem
    // sanitização nenhuma (Command Injection / OS Command Injection).
    $output = shell_exec('ping -c 2 ' . $host . ' 2>&1');
"""

    return f"""<?php
$output = '';
$host = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {{
    $host = $_POST['host'] ?? '';
{exec_logic}}}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>CyberLab - Diagnóstico de Rede</title>
<style>
body{{font-family:sans-serif;background:#111;color:#eee;padding:2rem}}
.box{{max-width:600px;margin:0 auto;background:#1c1c1c;padding:2rem;border-radius:8px}}
input{{width:100%;padding:8px;margin:6px 0;border-radius:4px;border:1px solid #444;background:#222;color:#eee;box-sizing:border-box}}
button{{padding:8px 16px;background:#4f7cff;color:#fff;border:none;border-radius:4px;cursor:pointer}}
pre{{background:#000;padding:1rem;overflow-x:auto;white-space:pre-wrap;border-radius:4px;margin-top:1rem}}
</style>
</head>
<body>
<div class="box">
<h2>Diagnóstico de Rede</h2>
<p>Testa conectividade com um host (ping).</p>
<form method="POST">
<input type="text" name="host" placeholder="ex: 8.8.8.8" value="<?= htmlspecialchars($host) ?>">
<button type="submit">Testar conexão</button>
</form>
<?php if ($output !== ''): ?>
<pre><?= htmlspecialchars($output) ?></pre>
<?php endif; ?>
</div>
</body>
</html>
"""


def build_command_injection_pre_app_commands() -> list[str]:
    return [
        "apt-get update",
        "apt-get install -y -o Acquire::Retries=3 apache2 libapache2-mod-php iputils-ping",
    ]


def build_command_injection_post_app_commands(
    flag_value: str, flag_location: str, root_flag_value: str
) -> list[str]:
    """Flag em /opt (não /root!) — /root tem permissão 700. Fase 2:
    sudoers mal configurado, NOPASSWD em /usr/bin/awk (GTFOBins)."""
    return [
        "rm -f /var/www/html/index.html",
        f"mkdir -p $(dirname {flag_location}) && echo '{flag_value}' > {flag_location}",
        f"chmod 644 {flag_location}",
        "service apache2 start",
        "apt-get install -y -o Acquire::Retries=3 sudo",
        "echo 'www-data ALL=(ALL) NOPASSWD: /usr/bin/awk' > /etc/sudoers.d/cyberlab",
        "chmod 440 /etc/sudoers.d/cyberlab",
        f"echo '{root_flag_value}' > /root/root_flag.txt",
        "chmod 600 /root/root_flag.txt",
    ]


# ============================================================
# Command Injection — variante 2: visualizador de logs (GET)
# Fase 2 usa SUID em vez de sudoers — mecanismo diferente da variante 1.
# ============================================================

def build_log_viewer_php(difficulty: str = "easy") -> str:
    """
    Visualizador de logs — mesmo espectro de dificuldade da variante 1
    (saída visível → blind por tempo → assíncrono/OOB), mas via
    parâmetro GET em vez de formulário POST.
    """
    if difficulty == "hard":
        exec_logic = """    // Execução assíncrona — resposta sempre rápida, força exfiltração
    // fora de banda.
    exec('cat /var/log/app/' . $logfile . ' > /dev/null 2>&1 &');
    $output = "Consulta de log enfileirada.";
"""
    elif difficulty == "medium":
        exec_logic = """    // Saída nunca mostrada — só o tempo de execução é observável.
    shell_exec('cat /var/log/app/' . $logfile . ' > /dev/null 2>&1');
    $output = "Log consultado.";
"""
    else:
        exec_logic = """    // Vulnerável de propósito: nome de arquivo vai direto pro comando
    // de sistema, sem sanitização (Command Injection via parâmetro GET).
    $output = shell_exec('cat /var/log/app/' . $logfile . ' 2>&1');
"""

    return f"""<?php
$output = '';
$logfile = $_GET['logfile'] ?? '';
if ($logfile !== '') {{
{exec_logic}}}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>CyberLab - Visualizador de Logs</title>
<style>
body{{font-family:sans-serif;background:#111;color:#eee;padding:2rem}}
.box{{max-width:600px;margin:0 auto;background:#1c1c1c;padding:2rem;border-radius:8px}}
input{{width:100%;padding:8px;margin:6px 0;border-radius:4px;border:1px solid #444;background:#222;color:#eee;box-sizing:border-box}}
button{{padding:8px 16px;background:#4f7cff;color:#fff;border:none;border-radius:4px;cursor:pointer}}
pre{{background:#000;padding:1rem;overflow-x:auto;white-space:pre-wrap;border-radius:4px;margin-top:1rem}}
</style>
</head>
<body>
<div class="box">
<h2>Visualizador de Logs</h2>
<p>Consulta arquivos de log da aplicação.</p>
<form method="GET">
<input type="text" name="logfile" placeholder="ex: access.log" value="<?= htmlspecialchars($logfile) ?>">
<button type="submit">Ver log</button>
</form>
<?php if ($output !== ''): ?>
<pre><?= htmlspecialchars($output) ?></pre>
<?php endif; ?>
</div>
</body>
</html>
"""


def build_log_viewer_pre_app_commands() -> list[str]:
    return [
        "apt-get update",
        "apt-get install -y -o Acquire::Retries=3 apache2 libapache2-mod-php",
    ]


def build_log_viewer_post_app_commands(
    flag_value: str, flag_location: str, root_flag_value: str
) -> list[str]:
    """Fase 2: bit SUID em /usr/bin/find (não sudoers) — mecanismo
    diferente da variante 1, descoberto via enumeração de SUID."""
    return [
        "mkdir -p /var/log/app",
        "echo '192.168.1.10 - - [10/Aug/2026] GET /index.php 200' > /var/log/app/access.log",
        "rm -f /var/www/html/index.html",
        f"mkdir -p $(dirname {flag_location}) && echo '{flag_value}' > {flag_location}",
        f"chmod 644 {flag_location}",
        "service apache2 start",
        "chmod u+s /usr/bin/find",
        f"echo '{root_flag_value}' > /root/root_flag.txt",
        "chmod 600 /root/root_flag.txt",
    ]
