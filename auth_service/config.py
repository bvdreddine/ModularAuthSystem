import os
from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=8000)
    DEBUG: bool = Field(default=False)
    
    # Keycloak settings
    KEYCLOAK_SERVER_URL: str = Field(default="http://localhost:8080/auth")
    KEYCLOAK_REALM: str = Field(default="master")
    KEYCLOAK_CLIENT_ID: str = Field(default="auth-service")
    KEYCLOAK_CLIENT_SECRET: str = Field(default="your-client-secret")
    KEYCLOAK_ADMIN_USERNAME: str = Field(default="admin")
    KEYCLOAK_ADMIN_PASSWORD: str = Field(default="admin")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
