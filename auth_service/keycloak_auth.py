import json
import logging
from typing import Optional, Dict, Any
import httpx
from jose import jwt
from fastapi import HTTPException, status

from config import settings

logger = logging.getLogger(__name__)

class KeycloakAuth:
    """Keycloak authentication manager."""
    
    def __init__(self):
        self.server_url = settings.KEYCLOAK_SERVER_URL
        self.realm = settings.KEYCLOAK_REALM
        self.client_id = settings.KEYCLOAK_CLIENT_ID
        self.client_secret = settings.KEYCLOAK_CLIENT_SECRET
        self.realm_url = f"{self.server_url}/realms/{self.realm}"
        self.admin_username = settings.KEYCLOAK_ADMIN_USERNAME
        self.admin_password = settings.KEYCLOAK_ADMIN_PASSWORD
        self._certs = None
        self._admin_token = None
    
    async def get_certs(self) -> Dict[str, Any]:
        """Get the public certs from Keycloak."""
        if self._certs:
            return self._certs
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.realm_url}/protocol/openid-connect/certs")
                response.raise_for_status()
                self._certs = response.json()
                return self._certs
        except httpx.HTTPError as e:
            logger.error(f"Failed to retrieve Keycloak certs: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service is unavailable"
            )
    
    async def get_token(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate user with Keycloak and get token."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.realm_url}/protocol/openid-connect/token",
                    data={
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "grant_type": "password",
                        "username": username,
                        "password": password,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                
                if response.status_code == 401:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid credentials",
                    )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Keycloak authentication error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service is unavailable"
            )

    async def get_admin_token(self) -> str:
        """Get an admin token for Keycloak API operations."""
        if self._admin_token:
            return self._admin_token
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.realm_url}/protocol/openid-connect/token",
                    data={
                        "client_id": "admin-cli",
                        "grant_type": "password",
                        "username": self.admin_username,
                        "password": self.admin_password,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                response.raise_for_status()
                token_data = response.json()
                self._admin_token = token_data["access_token"]
                return self._admin_token
        except httpx.HTTPError as e:
            logger.error(f"Failed to get admin token from Keycloak: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service is unavailable"
            )
    
    async def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate a JWT token against Keycloak public key."""
        try:
            certs = await self.get_certs()
            jwk_set = certs.get("keys", [])
            
            # Decode token header to get the key id (kid)
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            
            # Find the matching key
            rsa_key = {}
            for key in jwk_set:
                if key.get("kid") == kid:
                    rsa_key = {
                        "kty": key["kty"],
                        "kid": key["kid"],
                        "use": key["use"],
                        "n": key["n"],
                        "e": key["e"],
                    }
            
            if not rsa_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token signature"
                )
            
            # Validate the token
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=f"{self.realm_url}",
            )
            
            return payload
            
        except jwt.JWTError as e:
            logger.error(f"JWT validation error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token validation failed"
            )

    async def introspect_token(self, token: str) -> Dict[str, Any]:
        """Introspect token against Keycloak server."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.realm_url}/protocol/openid-connect/token/introspect",
                    data={
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "token": token,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Token introspection error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token validation failed"
            )

# Initialize Keycloak client
keycloak_client = KeycloakAuth()
