import logging
import httpx
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response, JSONResponse

from config import settings

logger = logging.getLogger(__name__)

class JWTBearerMiddleware(BaseHTTPMiddleware):
    """Middleware for JWT token validation through the Auth service."""
    
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip authentication for certain endpoints
        if request.url.path in ["/docs", "/redoc", "/openapi.json", "/health"]:
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
            # Validate token through the Auth service
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{settings.AUTH_SERVICE_URL}/auth/validate",
                    json={"token": token}
                )
                
                if response.status_code != 200:
                    return JSONResponse(
                        status_code=response.status_code,
                        content=response.json()
                    )
                
                # Add user info to request state
                request.state.user = response.json()
                
                # Check for required roles if role is specified in the request
                if hasattr(request, "scope") and "role" in request.scope:
                    required_role = request.scope["role"]
                    user_roles = request.state.user.get("realm_access", {}).get("roles", [])
                    
                    if required_role not in user_roles:
                        return JSONResponse(
                            status_code=status.HTTP_403_FORBIDDEN,
                            content={"detail": f"User lacks required role: {required_role}"}
                        )
                
                # Continue processing the request
                return await call_next(request)
                
        except httpx.HTTPError as e:
            logger.error(f"HTTP error during token validation: {str(e)}")
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"detail": "Authentication service unavailable"}
            )
        except Exception as e:
            logger.error(f"Unexpected error in JWT middleware: {str(e)}")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error during authentication"}
            )

async def admin_required(request: Request):
    """Dependency function that ensures user has admin role."""
    if not hasattr(request.state, "user"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    user_roles = request.state.user.get("realm_access", {}).get("roles", [])
    if "admin" not in user_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    return request.state.user
