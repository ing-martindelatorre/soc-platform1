from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    APP_NAME: str = 'soc-platform'
    APP_ENV: str = 'dev'

    DB_HOST: str = 'localhost'
    DB_PORT: int = 5432
    DB_NAME: str = 'soc'
    DB_USER: str = 'soc_user'
    DB_PASSWORD: str = 'soc_pass'

    S1_BASE_URL: str | None = None
    S1_API_TOKEN: str | None = None

    SNYK_API_TOKEN: str | None = None
    SNYK_ORG_ID: str | None = None

    FORTI_BASE_URL: str | None = None
    FORTI_API_TOKEN: str | None = None

    NMAP_DEFAULT_TARGETS: str | None = None
    ZEEK_LOG_DIR: str | None = None


settings = Settings()