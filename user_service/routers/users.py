import logging
import httpx
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query

from models import UserCreate, UserUpdate, UserResponse, UserListResponse, KeycloakUser
from db import (
    create_user, 
    get_user_by_id, 
    get_user_by_email,
    get_user_by_keycloak_id,
    list_users, 
    update_user, 
    delete_user
)
from middleware import admin_required
from config import settings

router = APIRouter(prefix="/users")
logger = logging.getLogger(__name__)

async def create_keycloak_user(user_data: UserCreate, admin_token: str) -> str:
    """Create a user in Keycloak and return the user ID."""
    try:
        # Prepare user data for Keycloak
        keycloak_user = KeycloakUser(
            username=user_data.email,
            email=user_data.email,
            firstName=user_data.first_name,
            lastName=user_data.last_name,
            enabled=user_data.active,
            emailVerified=True,
            credentials=[{
                "type": "password",
                "value": user_data.password,
                "temporary": False
            }],
            attributes={
                "phone": user_data.phone or "",
                "department": user_data.department or ""
            },
            realmRoles=[user_data.role.value]
        )
        
        # Create user in Keycloak
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{settings.KEYCLOAK_SERVER_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users",
                json=keycloak_user.dict(),
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/json"
                }
            )
            
            if response.status_code == 409:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="User with this email already exists"
                )
            response.raise_for_status()
            
            # Get user ID from Location header
            location = response.headers.get("Location")
            if not location:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to get user ID from Keycloak"
                )
            
            user_id = location.split("/")[-1]
            
            # Assign role to user
            role_response = await client.get(
                f"{settings.KEYCLOAK_SERVER_URL}/admin/realms/{settings.KEYCLOAK_REALM}/roles/{user_data.role.value}",
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            role_response.raise_for_status()
            role = role_response.json()
            
            role_assign_response = await client.post(
                f"{settings.KEYCLOAK_SERVER_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}/role-mappings/realm",
                json=[role],
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/json"
                }
            )
            role_assign_response.raise_for_status()
            
            return user_id
            
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error during Keycloak user creation: {str(e)}")
        if e.response.status_code == 409:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email already exists"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user in Keycloak: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Error creating Keycloak user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user in Keycloak: {str(e)}"
        )


async def get_admin_token() -> str:
    """Get admin token from Auth service."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{settings.AUTH_SERVICE_URL}/auth/token",
                data={
                    "username": settings.KEYCLOAK_ADMIN_USERNAME,
                    "password": settings.KEYCLOAK_ADMIN_PASSWORD,
                    "grant_type": "password",
                    "client_id": "admin-cli"
                }
            )
            response.raise_for_status()
            return response.json()["access_token"]
    except Exception as e:
        logger.error(f"Failed to get admin token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to authenticate with Keycloak"
        )


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_new_user(
    user_data: UserCreate,
    current_user: dict = Depends(admin_required)
):
    """
    Create a new user (admin only).
    """
    # Check if user already exists
    existing_user = await get_user_by_email(user_data.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists"
        )
    
    # Get admin token for Keycloak operations
    admin_token = await get_admin_token()
    
    # Create user in Keycloak
    keycloak_id = await create_keycloak_user(user_data, admin_token)
    
    # Create user in Cassandra
    user = await create_user(user_data, keycloak_id)
    
    return UserResponse(**user.dict())


@router.get("/", response_model=UserListResponse)
async def get_users(
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=100),
    current_user: dict = Depends(admin_required)
):
    """
    Get a list of users (admin only).
    """
    result = await list_users(page, size)
    return UserListResponse(**result)


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    current_user: dict = Depends(admin_required)
):
    """
    Get a specific user by ID (admin only).
    """
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(**user.dict())


@router.put("/{user_id}", response_model=UserResponse)
async def update_existing_user(
    user_id: UUID,
    user_data: UserUpdate,
    current_user: dict = Depends(admin_required)
):
    """
    Update an existing user (admin only).
    """
    # Check if user exists
    existing_user = await get_user_by_id(user_id)
    if not existing_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # TODO: Update user in Keycloak if needed
    # This would require additional code to update the user in Keycloak
    
    # Update user in Cassandra
    updated_user = await update_user(user_id, user_data)
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user"
        )
    
    return UserResponse(**updated_user.dict())


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_existing_user(
    user_id: UUID,
    current_user: dict = Depends(admin_required)
):
    """
    Delete a user (admin only).
    """
    # Check if user exists
    existing_user = await get_user_by_id(user_id)
    if not existing_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # TODO: Delete user in Keycloak
    # This would require additional code to delete the user in Keycloak
    
    # Delete user in Cassandra
    result = await delete_user(user_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )
    
    return None


@router.get("/me", response_model=UserResponse)
async def get_current_user(request: Request):
    """
    Get the current authenticated user's profile.
    """
    if not hasattr(request.state, "user"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    # Get user from database using Keycloak ID
    keycloak_id = request.state.user.get("sub")
    user = await get_user_by_keycloak_id(keycloak_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in database"
        )
    
    return UserResponse(**user.dict())
