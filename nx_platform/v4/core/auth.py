from fastapi import Header, HTTPException, Depends, Security
from fastapi.security import APIKeyHeader
from typing import Optional
import os

# Security definitions
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Simple RBAC: admin has full access, user has read-only
# In production, these should be in environment variables or a secure vault
API_KEYS = {
    os.getenv("NX_ADMIN_KEY", "admin-secret-key"): "admin",
    os.getenv("NX_USER_KEY", "user-secret-key"): "user"
}

async def get_current_user(api_key: Optional[str] = Security(api_key_header)):
    if not api_key:
        # Check if we are in development mode to allow bypass
        if os.getenv("NX_MODE") == "development":
            return "admin"
        raise HTTPException(status_code=403, detail="API Key missing")
    
    if api_key not in API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    
    return API_KEYS[api_key]

def admin_only(user: str = Depends(get_current_user)):
    if user != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

def user_or_admin(user: str = Depends(get_current_user)):
    if user not in ["admin", "user"]:
        raise HTTPException(status_code=403, detail="Access denied")
    return user
