import os
from datetime import datetime, timedelta

import jwt
import bcrypt
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session

from . import models, schemas
from .db import engine, SessionLocal

PROD = os.getenv('PROD', default=False)

if not PROD:
    models.Base.metadata.drop_all(bind=engine)

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

JWT_SECRET = os.getenv('JWT_SECRET', default='secret')


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def gen_token(payload, exp):
    _payload = payload.copy()
    _payload['exp'] = datetime.now() + exp
    return jwt.encode(_payload, JWT_SECRET)


@app.post('/sign-up', response_model=schemas.JWT)
def sign_up(user: schemas.UserSignUp, db: Session = Depends(get_db)):
    db_user = db.query(
        models.User).filter(
        models.User.email == user.email).first()

    if db_user:
        raise HTTPException(status_code=400, detail='Email already registered')

    hashed_password = bcrypt.hashpw(
        user.password.encode(),
        bcrypt.gensalt())
    db_user = models.User(
        email=user.email,
        name=user.name,
        password=hashed_password.decode('utf-8'))

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    access_token = gen_token(
        {'id': db_user.id}, timedelta(minutes=30))
    refresh_token = gen_token({'id': db_user.id}, timedelta(days=30))

    return {'accessToken': access_token, 'refreshToken': refresh_token}


@app.post('/login', response_model=schemas.JWT)
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(
        models.User).filter(
        models.User.email == user.email).first()

    if db_user is None:
        raise HTTPException(status_code=400, detail='User doesn\'t exist')

    if bcrypt.checkpw(user.password.encode(), db_user.password.encode()):
        access_token = gen_token(
            {'id': db_user.id}, timedelta(minutes=30))
        refresh_token = gen_token({'id': db_user.id}, timedelta(days=30))

        return {'accessToken': access_token, 'refreshToken': refresh_token}

    raise HTTPException(status_code=401, detail='Wrong password')
