from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://cyberlab:cyberlab_dev_password@postgres:5432/cyberlab"
    valkey_url: str = "redis://valkey:6379/0"
    ollama_base_url: str = "http://ollama:11434"
    ollama_model: str = "mistral"

    # Rede Docker onde as máquinas de desafio serão spawnadas
    challenge_network: str = "cyberlab-mvp_cyberlab_challenges"

    # Rede compartilhada onde o proxy de cache de pacotes APT vive — o
    # container target se conecta aqui ADEMAIS da sua rede isolada por
    # instância, só pra falar com o cache.
    apt_cache_network: str = "cyberlab-mvp_cyberlab_core"
    apt_cache_host: str = "cyberlab-apt-cache"
    apt_cache_port: int = 3142

    # MVP: segredo fixo no código, ok pra ambiente de desenvolvimento
    # local. Antes de qualquer deploy real, isso precisa vir de uma
    # variável de ambiente/secret de verdade.
    jwt_secret: str = "cyberlab-dev-secret-troque-em-producao"
    jwt_expire_minutes: int = 480  # 8h de sessão

    class Config:
        env_file = ".env"


settings = Settings()
