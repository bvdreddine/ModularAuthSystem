from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from keycloak_auth import keycloak_client

router = APIRouter(prefix="/auth")

@router.post("/token", response_model=Dict[str, Any])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 compatible token login, get an access token for future requests
    """
    token_data = await keycloak_client.get_token(form_data.username, form_data.password)
    return token_data

@router.post("/validate", response_model=Dict[str, Any])
async def validate_token(token: str):
    """
    Validate a JWT token and return its payload
    """
    payload = await keycloak_client.validate_token(token)
    return payload

@router.post("/introspect", response_model=Dict[str, Any])
async def introspect_token(token: str):
    """
    Introspect a token against Keycloak server
    """
    result = await keycloak_client.introspect_token(token)
    return result
