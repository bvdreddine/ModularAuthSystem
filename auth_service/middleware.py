import logging
from typing import Optional
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response, JSONResponse

from keycloak_auth import keycloak_client

logger = logging.getLogger(__name__)

class JWTBearerMiddleware(BaseHTTPMiddleware):
    """Middleware for JWT token validation."""
    
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip authentication for certain endpoints
        if request.url.path in ["/docs", "/redoc", "/openapi.json", "/health"] or \
           request.url.path.startswith("/auth"):
            return await call_next(request)
        
        # Get token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Missing authorization header"}
            )
        
        scheme, token = auth_header.split()
        if scheme.lower() != "bearer":
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid authentication scheme"}
            )
        
        try:
            # Validate token
            payload = await keycloak_client.validate_token(token)
            
            # Add user info to request state
            request.state.user = payload
            
            # Continue processing the request
            return await call_next(request)
            
        except HTTPException as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"detail": e.detail}
            )
        except Exception as e:
            logger.error(f"Unexpected error in JWT middleware: {str(e)}")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error during authentication"}
            )
