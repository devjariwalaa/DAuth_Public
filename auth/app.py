from fastapi import FastAPI
from auth.routes import router as auth_router
from auth.google_oauth import router as google_router
from starlette.middleware.sessions import SessionMiddleware
import os

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY"))
app.include_router(auth_router)
app.include_router(google_router)

@app.get("/")
def hello():
    return {"message": "DAuth is initialized"}