import os
from pydantic import BaseSettings, Field

class Settings(BaseSettings):
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=8000)
    DEBUG: bool = Field(default=False)
    
    # Keycloak settings
    KEYCLOAK_SERVER_URL: str = Field(default="http://localhost:8080/auth")
    KEYCLOAK_REALM: str = Field(default="master")
    KEYCLOAK_CLIENT_ID: str = Field(default="user-service")
    KEYCLOAK_CLIENT_SECRET: str = Field(default="your-client-secret")
    
    # Cassandra settings
    CASSANDRA_CONTACT_POINTS: str = Field(default="localhost")
    CASSANDRA_PORT: int = Field(default=9042)
    CASSANDRA_KEYSPACE: str = Field(default="user_management")
    CASSANDRA_USERNAME: str = Field(default=None)
    CASSANDRA_PASSWORD: str = Field(default=None)
    
    # Auth service
    AUTH_SERVICE_URL: str = Field(default="http://localhost:8000")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
