from pydantic import BaseModel


class UserLogin(BaseModel):
    email: str
    password: str


class UserSignUp(UserLogin):
    name: str


class JWT(BaseModel):
    accessToken: str
    refreshToken: str


class RefreshToken(BaseModel):
    refreshToken: str
