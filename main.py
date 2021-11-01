from fastapi import FastAPI, Depends, status, Response, HTTPException
from sqlalchemy.orm import Session
from datetime import timedelta, datetime
from typing import Optional
from jose import JWTError, jwt
import database
import schemas
import models
from database import engine, SessionLocal
from passlib.context import CryptContext

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt




app = FastAPI()

models.Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_cxt.verify(plain_password, hashed_password)

@app.post('/signup', response_model=schemas.ShowUser)
def create_user(request: schemas.User, db: Session = Depends(get_db)):
    hashedPassword = pwd_cxt.hash(request.password)
    new_user = models.User(name=request.name, email=request.email, password=hashedPassword)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post('/login/')
def login(request: schemas.Login, db: Session = Depends(get_db)):
    hashedPassword = pwd_cxt.hash(request.password)
    #if not verify_password(login.password, request.password):
        #raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            #detail=f"Incorrect password")
    user = db.query(models.User).filter(models.User.email==request.email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Invalid Credentials")

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}



@app.get('/me', response_model=schemas.ShowUser)
def get_user(access_token, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email==access_token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"User with the email is not available")
    return user


