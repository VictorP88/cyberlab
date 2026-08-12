# Proxy de cache de pacotes APT. Primeira instalação de um pacote baixa da
# internet normalmente; instalações seguintes do MESMO pacote (mesma
# versão) pegam do cache local, dentro da rede Docker — muito mais rápido
# que rebaixar da internet toda vez que um cenário novo é spawnado.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends apt-cacher-ng \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 3142

CMD ["apt-cacher-ng", "-c", "/etc/apt-cacher-ng", "ForeGround=1"]
