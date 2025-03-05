from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from auth.schemas import ChangePasswordRequest, UserCreate, UserLogin
from auth.utils import hash_password, verify_password
from common.db import SessionLocal
from auth.models import User
from auth import auth

router = APIRouter(prefix="/auth", tags=["Authentication"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
@router.post("/signup")
def signup(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created successfully"}

@router.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = auth.create_access_token({"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/protected")
def protected_route(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token missing or invalid")
    token = auth_header.split("Bearer ") [1]
    payload = auth.verify_access_token(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return {'message': "You have access!", "user": payload}

@router.delete('/delete')
def delete_account(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token missing or invalid")
    
    token = auth_header.split("Bearer ") [1]
    payload = auth.verify_access_token(token)

    user_email = payload.get("sub")
    db_user = db_user = db.query(User).filter(User.email == user_email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(db_user)
    db.commit()

    return {'message': 'Sucessfully deleted account'}

@router.put("/change-password")
def change_password(request: Request, password_data: ChangePasswordRequest, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token missing or invalid")

    token = auth_header.split("Bearer ")[1]
    payload = auth.verify_access_token(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_email = payload.get("sub")
    user = db.query(User).filter(User.email == user_email).first()

    if not user or not verify_password(password_data.old_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Old password is incorrect")

    user.hashed_password = hash_password(password_data.new_password)
    db.commit()
    db.refresh(user) 
    return {"message": "Password changed successfully"}