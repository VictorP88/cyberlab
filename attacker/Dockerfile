FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    netcat-openbsd \
    nmap \
    sqlmap \
    gobuster \
    hydra \
    dirb \
    python3 \
    python3-pip \
    dnsutils \
    iputils-ping \
    default-mysql-client \
    openssh-client \
    vim \
    nano \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Prompt colorido (estilo Kali/Parrot) + banner de boas-vindas ao
# conectar, listando as ferramentas disponíveis. Wordlists prontas vêm
# junto do pacote "dirb" (não precisamos baixar SecLists inteiro).
RUN { \
    echo "export PS1='\[\033[1;32m\]┌──(\[\033[1;36m\]cyberlab\[\033[1;32m\]㉿\[\033[1;36m\]attacker\[\033[1;32m\])-[\[\033[0m\]\w\[\033[1;32m\]]\[\033[0m\]\n\[\033[1;32m\]└─\[\033[1;36m\]\$\[\033[0m\] '"; \
    echo "echo '  Ferramentas: nmap sqlmap gobuster hydra dirb curl netcat mysql-client ssh vim git'"; \
    echo "echo '  Wordlists:   /usr/share/dirb/wordlists/'"; \
    } >> /root/.bashrc

WORKDIR /root
