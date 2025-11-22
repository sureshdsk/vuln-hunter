"""
Shared configuration for the CVE Vulnerability Analysis System.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    """Application settings"""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )
    
    # Database
    database_url: str = "postgresql://vuln_hunter:vulnhunter_dev@localhost:5432/vuln_hunter"
    
    # Prefect
    prefect_api_url: str = "http://localhost:4201/api"
    
    # AI/LLM
    gemini_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    
    # Repository settings
    repo_cache_dir: str = "/tmp/vuln_hunter_repos"
    max_repo_size_mb: int = 500
    
    # Vulnerability DB
    osv_api_url: str = "https://api.osv.dev/v1"
    vulners_api_key: Optional[str] = None
    
    # Django
    django_secret_key: str = "dev-secret-key-change-in-production"
    django_debug: bool = True
    django_allowed_hosts: str = "localhost,127.0.0.1"
    
    # CORS
    cors_allowed_origins: str = "http://localhost:3000"


# Global settings instance
settings = Settings()
