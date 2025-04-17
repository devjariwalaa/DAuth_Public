from fastapi import APIRouter, Request, HTTPException
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from starlette.responses import RedirectResponse
from config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI
from auth.auth import create_access_token, create_refresh_token
from auth.models import User
from common.db import SessionLocal

router = APIRouter()

# OAuth client config
config = Config(environ={
    "GOOGLE_CLIENT_ID": GOOGLE_CLIENT_ID,
    "GOOGLE_CLIENT_SECRET": GOOGLE_CLIENT_SECRET
})

oauth = OAuth(config)
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# 🔗 Step 1: Redirect user to Google
@router.get("/auth/google/login")
async def login_via_google(request: Request):
    redirect_uri = GOOGLE_REDIRECT_URI
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get("/auth/google/callback")
async def google_auth_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)

        # Try getting user info from the token directly
        user_info = token.get("userinfo")
        if not user_info:
            # Fallback: decode ID token manually
            user_info = await oauth.google.parse_id_token(request, token)

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"OAuth flow failed: {str(e)}")

    if not user_info or "email" not in user_info:
        raise HTTPException(status_code=400, detail="Failed to fetch user info from Google")

    email = user_info["email"]

    # Get or create user in the database
    db = SessionLocal()
    db_user = db.query(User).filter(User.email == email).first()
    if not db_user:
        new_user = User(email=email, hashed_password="GOOGLE_OAUTH_USER")
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

    # Generate access and refresh tokens
    access_token = create_access_token({"sub": email})
    refresh_token = create_refresh_token({"sub": email})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }