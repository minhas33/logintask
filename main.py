from fastapi import FastAPI, Depends, status, Response, HTTPException
from sqlalchemy.orm import Session

import database
import schemas
import models
from database import engine, SessionLocal
from passlib.context import CryptContext




app = FastAPI()

models.Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")

@app.post('/signup', response_model=schemas.ShowUser)
def create_user(name: str, email: str, password: str, request: schemas.User, db: Session = Depends(get_db)):
    hashedPassword = pwd_cxt.hash(request.password)
    new_user = models.User(name=request.name, email=request.email, password=hashedPassword)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.get('/me', response_model=schemas.ShowUser)
def get_user(email:str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email==email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"User with the email {email} is not available")
    return user


