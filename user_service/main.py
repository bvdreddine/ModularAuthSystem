import logging
import uvicorn
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from middleware import JWTBearerMiddleware
from db import initialize_cassandra
from routers import users

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="User Management Microservice",
    description="User management microservice with Cassandra backend",
    version="0.1.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add JWT middleware
app.add_middleware(JWTBearerMiddleware)

# Include routers
app.include_router(users.router, tags=["Users"])

@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "user-management"}

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    logger.info("Initializing Cassandra connection...")
    await initialize_cassandra()

if __name__ == "__main__":
    logger.info(f"Starting User Management service on {settings.HOST}:{settings.PORT}")
    uvicorn.run(
        "main:app",
        host=settings.HOST, 
        port=settings.PORT,
        reload=settings.DEBUG
    )
