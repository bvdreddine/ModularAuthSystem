import logging
import asyncio
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
from datetime import datetime

from cassandra.cluster import Cluster, Session
from cassandra.auth import PlainTextAuthProvider
from cassandra.cqlengine import connection
from cassandra.cqlengine.management import sync_table, create_keyspace_simple
from cassandra.cqlengine.models import Model
from cassandra.cqlengine import columns

from models import UserCreate, UserUpdate, UserInDB, UserRole
from config import settings

logger = logging.getLogger(__name__)

# Global session variable
session: Optional[Session] = None


class UserModel(Model):
    """Cassandra model for User entity."""
    __keyspace__ = settings.CASSANDRA_KEYSPACE
    __table_name__ = 'users'
    
    id = columns.UUID(primary_key=True, default=uuid4)
    keycloak_id = columns.Text(index=True)
    first_name = columns.Text()
    last_name = columns.Text()
    email = columns.Text(index=True)
    role = columns.Text()  # 'student', 'teacher', 'admin'
    phone = columns.Text()
    department = columns.Text()
    active = columns.Boolean(default=True)
    created_at = columns.DateTime(default=datetime.utcnow)
    updated_at = columns.DateTime()


async def initialize_cassandra():
    """Initialize Cassandra connection and setup keyspace and tables."""
    global session
    
    try:
        # Set up authentication if credentials are provided
        auth_provider = None
        if settings.CASSANDRA_USERNAME and settings.CASSANDRA_PASSWORD:
            auth_provider = PlainTextAuthProvider(
                username=settings.CASSANDRA_USERNAME, 
                password=settings.CASSANDRA_PASSWORD
            )
        
        # Create cluster and connect
        cluster = Cluster(
            contact_points=settings.CASSANDRA_CONTACT_POINTS.split(','),
            port=settings.CASSANDRA_PORT,
            auth_provider=auth_provider
        )
        
        session = cluster.connect()
        
        # Create keyspace if it doesn't exist
        keyspace_query = f"""
        CREATE KEYSPACE IF NOT EXISTS {settings.CASSANDRA_KEYSPACE}
        WITH replication = {{'class': 'SimpleStrategy', 'replication_factor': '1'}}
        """
        session.execute(keyspace_query)
        
        # Set up connection for ORM
        connection.setup(
            [host for host in settings.CASSANDRA_CONTACT_POINTS.split(',')],
            settings.CASSANDRA_KEYSPACE,
            auth_provider=auth_provider
        )
        
        # Sync tables
        sync_table(UserModel)
        
        logger.info(f"Cassandra initialized with keyspace {settings.CASSANDRA_KEYSPACE}")
        
    except Exception as e:
        logger.error(f"Failed to initialize Cassandra: {str(e)}")
        raise


async def create_user(user_data: UserCreate, keycloak_id: str) -> UserInDB:
    """Create a new user in the database."""
    try:
        user = UserModel.create(
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            email=user_data.email,
            role=user_data.role.value,
            phone=user_data.phone,
            department=user_data.department,
            active=user_data.active,
            keycloak_id=keycloak_id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        return UserInDB(
            id=user.id,
            keycloak_id=user.keycloak_id,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            role=UserRole(user.role),
            phone=user.phone,
            department=user.department,
            active=user.active,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        raise


async def get_user_by_id(user_id: UUID) -> Optional[UserInDB]:
    """Get a user by their UUID."""
    try:
        user = UserModel.objects.filter(id=user_id).first()
        if not user:
            return None
        
        return UserInDB(
            id=user.id,
            keycloak_id=user.keycloak_id,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            role=UserRole(user.role),
            phone=user.phone,
            department=user.department,
            active=user.active,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
    except Exception as e:
        logger.error(f"Error getting user by ID: {str(e)}")
        raise


async def get_user_by_email(email: str) -> Optional[UserInDB]:
    """Get a user by their email."""
    try:
        # Allow filtering since email is indexed
        user = UserModel.objects.filter(email=email).allow_filtering().first()
        if not user:
            return None
        
        return UserInDB(
            id=user.id,
            keycloak_id=user.keycloak_id,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            role=UserRole(user.role),
            phone=user.phone,
            department=user.department,
            active=user.active,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
    except Exception as e:
        logger.error(f"Error getting user by email: {str(e)}")
        raise


async def get_user_by_keycloak_id(keycloak_id: str) -> Optional[UserInDB]:
    """Get a user by their Keycloak ID."""
    try:
        # Allow filtering since keycloak_id is indexed
        user = UserModel.objects.filter(keycloak_id=keycloak_id).allow_filtering().first()
        if not user:
            return None
        
        return UserInDB(
            id=user.id,
            keycloak_id=user.keycloak_id,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            role=UserRole(user.role),
            phone=user.phone,
            department=user.department,
            active=user.active,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
    except Exception as e:
        logger.error(f"Error getting user by Keycloak ID: {str(e)}")
        raise


async def list_users(page: int = 1, size: int = 10) -> Dict[str, Any]:
    """List users with pagination."""
    try:
        # Note: Cassandra doesn't have built-in pagination like SQL databases
        # This is a simple implementation that might not scale well for large datasets
        all_users = list(UserModel.objects.all())
        
        start_idx = (page - 1) * size
        end_idx = start_idx + size
        
        users_page = all_users[start_idx:end_idx]
        
        users = []
        for user in users_page:
            users.append(UserInDB(
                id=user.id,
                keycloak_id=user.keycloak_id,
                first_name=user.first_name,
                last_name=user.last_name,
                email=user.email,
                role=UserRole(user.role),
                phone=user.phone,
                department=user.department,
                active=user.active,
                created_at=user.created_at,
                updated_at=user.updated_at
            ))
        
        return {
            "users": users,
            "total": len(all_users),
            "page": page,
            "size": size
        }
    except Exception as e:
        logger.error(f"Error listing users: {str(e)}")
        raise


async def update_user(user_id: UUID, user_data: UserUpdate) -> Optional[UserInDB]:
    """Update an existing user."""
    try:
        user = UserModel.objects.filter(id=user_id).first()
        if not user:
            return None
        
        # Update only provided fields
        update_data = user_data.dict(exclude_unset=True)
        if "role" in update_data and update_data["role"]:
            update_data["role"] = update_data["role"].value
        
        update_data["updated_at"] = datetime.utcnow()
        
        # Update user
        user.update(**update_data)
        
        # Get updated user
        updated_user = UserModel.objects.filter(id=user_id).first()
        
        return UserInDB(
            id=updated_user.id,
            keycloak_id=updated_user.keycloak_id,
            first_name=updated_user.first_name,
            last_name=updated_user.last_name,
            email=updated_user.email,
            role=UserRole(updated_user.role),
            phone=updated_user.phone,
            department=updated_user.department,
            active=updated_user.active,
            created_at=updated_user.created_at,
            updated_at=updated_user.updated_at
        )
    except Exception as e:
        logger.error(f"Error updating user: {str(e)}")
        raise


async def delete_user(user_id: UUID) -> bool:
    """Delete a user from the database."""
    try:
        user = UserModel.objects.filter(id=user_id).first()
        if not user:
            return False
        
        user.delete()
        return True
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        raise
