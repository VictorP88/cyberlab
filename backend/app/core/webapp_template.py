"""
Templates determinísticos das aplicações vulneráveis — front (HTML/CSS),
back (PHP) e infraestrutura sempre entregues de forma fixa por tipo de
vulnerabilidade, sem depender da LLM pra escrever código de aplicação.
"""
from __future__ import annotations


# ============================================================
# SQLi — site com múltiplas páginas (reconhecimento de verdade)
# + fase de escalonamento de privilégio via SSH
# ============================================================

def build_landing_php(company_name: str = "TechCorp Solutions") -> str:
    """Página inicial de uma 'empresa' fake — o login fica escondido
    atrás de um link, não é a primeira coisa que aparece. Reconhecimento
    de verdade em vez de já cair direto na vulnerabilidade."""
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
    """Dica de reconhecimento: ferramentas como gobuster/dirb encontram
    isso rápido, e ele aponta pra rota do login sem revelar a
    vulnerabilidade em si."""
    return "User-agent: *\nDisallow: /login.php\n"


def build_login_php(db_password: str) -> str:
    """
    A senha do banco vai direto no código PHP gerado, em vez de depender
    de getenv(). db_password vem de secrets.token_hex(), nunca tem
    aspas — mas escapamos mesmo assim por robustez.
    """
    escaped = db_password.replace("\\", "\\\\").replace("'", "\\'")
    return f"""<?php
// Desde o PHP 8.1, mysqli lança exceção em QUALQUER erro de query por
// padrão (não só erro de conexão) — inclusive erros de sintaxe SQL, que
// são esperados quando alguém está literalmente testando payloads de
// SQL Injection. Sem isso, testar um payload que quebra a sintaxe
// derruba a página inteira (500) em vez de mostrar o erro SQL de forma
// tratada, que é o comportamento clássico e o que faz sentido aqui.
mysqli_report(MYSQLI_REPORT_OFF);
$conn = new mysqli('127.0.0.1', 'root', '{escaped}', 'cyberlab');
$message = '';
if ($conn->connect_error) {{
    // Conexão com o banco falhou de verdade (não é erro de sintaxe SQL,
    // é o banco mesmo inacessível) — mostra isso claramente em vez de
    // deixar o resto do script tentar usar uma conexão morta e quebrar
    // com um erro ainda mais confuso.
    $message = "Erro de conexão com o banco de dados. Tente novamente em instantes.";
}} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {{
    $user = $_POST['username'] ?? '';
    $pass = $_POST['password'] ?? '';
    // Vulnerável de propósito: concatenação direta sem sanitização (SQLi).
    $sql = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
    $result = $conn->query($sql);
    if ($result && $result->num_rows > 0) {{
        $row = $result->fetch_assoc();
        $message = "Login bem-sucedido! Bem-vindo, " . htmlspecialchars($row['username']) . ".";
        if ($row['username'] === 'admin') {{
            $message .= "<br>Flag: " . htmlspecialchars($row['flag'] ?? '');
        }}
    }} else {{
        $message = "Usuário ou senha inválidos.";
        if ($conn->error) {{
            $message .= "<br><small>Erro SQL: " . htmlspecialchars($conn->error) . "</small>";
        }}
    }}
}}
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
    """Comandos que rodam ANTES de injetar os arquivos: instala e
    configura Apache + PHP + MySQL, cria o banco e o usuário remoto.
    -o Acquire::Retries=3 protege contra soluços de rede transitórios
    durante o download de pacotes."""
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
    """
    Depois dos arquivos já colocados: semeia o banco, sobe o Apache, e
    monta a FASE 2 (escalonamento de privilégio):
      - usuário Linux 'webadmin' com SSH, senha = a MESMA senha do
        usuário admin do banco (reuso de senha — erro clássico e
        realista que a exploração da fase 1 revela)
      - sudoers mal configurado: NOPASSWD em /usr/bin/find, um vetor de
        escalonamento clássico (GTFOBins)
      - segunda flag em /root/, só legível depois do escalonamento
    """
    return [
        f"mysql cyberlab -e \"INSERT INTO users (username, password, flag) "
        f"VALUES ('admin', '{admin_password}', '{flag_value}');\"",
        f"echo '{flag_value}' > {flag_location}",
        # O Apache prioriza index.html sobre index.php por padrão — sem
        # remover o index.html de fábrica do pacote, nossa landing page
        # (index.php) nunca aparece, e o site continua mostrando a
        # página "It works!" genérica do Ubuntu.
        "rm -f /var/www/html/index.html",
        "service apache2 start",
        # --- fase 2: acesso SSH com a senha reutilizada ---
        "apt-get install -y -o Acquire::Retries=3 openssh-server sudo",
        "useradd -m -s /bin/bash webadmin",
        f"echo 'webadmin:{webadmin_password}' | chpasswd",
        "service ssh start",
        # --- fase 2: sudoers mal configurado (vetor de privesc) ---
        "echo 'webadmin ALL=(ALL) NOPASSWD: /usr/bin/find' > /etc/sudoers.d/cyberlab",
        "chmod 440 /etc/sudoers.d/cyberlab",
        f"echo '{root_flag_value}' > /root/root_flag.txt",
        "chmod 600 /root/root_flag.txt",
    ]


# ============================================================
# SQLi — variante 2: busca de produtos (uma fase só, sem privesc)
# Padrão diferente de propósito: injeção via parâmetro GET (URL), não
# formulário de login. Mais simples, mais rápida, e também mais
# confiável (não mexe com SSH/sudo — menos peças pra falhar).
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


def build_search_php(db_password: str) -> str:
    """
    Busca de produtos vulnerável a SQLi refletida via parâmetro GET —
    um dos padrões mais comuns de SQLi no mundo real (caixas de busca,
    filtros de catálogo). Sem login, sem sessão — a exploração é direto
    na URL.
    """
    escaped = db_password.replace("\\", "\\\\").replace("'", "\\'")
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
    $sql = "SELECT name, description FROM products WHERE name LIKE '%$search%'";
    $result = $conn->query($sql);
    if ($result) {{
        while ($row = $result->fetch_assoc()) {{
            $results[] = $row;
        }}
    }} else {{
        $error = "Erro SQL: " . htmlspecialchars($conn->error);
    }}
}}
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
    """Mesma base MySQL+Apache das outras variantes de SQLi, mas sem
    nenhuma etapa de SSH/sudo — o cenário é de uma fase só."""
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
# Command Injection — ferramenta de diagnóstico de rede
# ============================================================

def build_command_injection_php() -> str:
    """
    Ferramenta de "diagnóstico de rede" — pede um host e roda `ping`
    nele. Vulnerável de propósito: o input do usuário vai direto pro
    shell_exec sem nenhuma sanitização.
    """
    return """<?php
$output = '';
$host = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $host = $_POST['host'] ?? '';
    // Vulnerável de propósito: shell_exec com entrada do usuário sem
    // sanitização nenhuma (Command Injection / OS Command Injection).
    $output = shell_exec('ping -c 2 ' . $host . ' 2>&1');
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>CyberLab - Diagnóstico de Rede</title>
<style>
body{font-family:sans-serif;background:#111;color:#eee;padding:2rem}
.box{max-width:600px;margin:0 auto;background:#1c1c1c;padding:2rem;border-radius:8px}
input{width:100%;padding:8px;margin:6px 0;border-radius:4px;border:1px solid #444;background:#222;color:#eee;box-sizing:border-box}
button{padding:8px 16px;background:#4f7cff;color:#fff;border:none;border-radius:4px;cursor:pointer}
pre{background:#000;padding:1rem;overflow-x:auto;white-space:pre-wrap;border-radius:4px;margin-top:1rem}
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
    """
    Flag em /opt (não /root!) — o PHP roda como www-data, e /root tem
    permissão 700, então nem um comando injetado alcançaria um arquivo
    lá dentro. /opt é world-readable por padrão.

    Fase 2: diferente do SQLi (SSH + reuso de senha), aqui a porta de
    entrada é a PRÓPRIA injeção de comando — www-data já tem execução
    de código, só falta escalar. Vetor: sudoers mal configurado,
    NOPASSWD em /usr/bin/awk (GTFOBins), explorável via reverse shell
    aberta pela mesma injeção.
    """
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
