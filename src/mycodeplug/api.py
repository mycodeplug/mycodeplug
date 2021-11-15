import importlib.metadata
import os
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

from .db import session
from .logging import getLogger
from .mail import otp_delivery
from .user import (
    AuthenticationError,
    EditableUser,
    get_current_active,
    Token,
    UnknownUser,
    User,
)

APP_NAME = "mycodeplug"

app = FastAPI()
logger = getLogger(APP_NAME)


class RootData(BaseModel):
    """
    Information returned from the top level GET request.
    """

    application: str = APP_NAME
    version: str = importlib.metadata.metadata(APP_NAME)["version"]


@app.get("/", response_model=RootData)
async def root() -> RootData:
    """
    :return: Information about the application and version
    """
    return RootData()


@app.post("/login")
def login(
    email: str,
    request: Request,
    deliver=Depends(otp_delivery),
    session=Depends(session),
):
    """
    Trigger a login request for the given email address.

    Generate a one time password for login via magic link or standard
    username/password oauth via /token endpoint.

    In production mode, the otp would be emailed to the given address.

    In development mode, the otp is printed to the console.

    Either way, the client POSTing /token must be the same client
    that POSTed /login.

    :param email: the user to login
    :param request: the request, used to fetch the login IP.
    :return: None -- the token is emailed (or printed, in dev mode).
    """
    try:
        user = User.from_email(email, session=session)
    except UnknownUser:
        user = User(email=email, created_ip=request.client.host)
        session.add(user)
        session.commit()
        session.refresh(user)
        logger.info("Created a new user for {}".format(email))
    return deliver(user, user.login(ip=request.client.host, session=session))


def _token(email: str, otp: str, request: Request) -> Token:
    """
    Authenticate an OTP.

    :param email: the user to login
    :param otp: the one-time password from a /login request
    :param request: the request, must match the IP that requested /login
    :return: oauth Token
    """
    token_data = User.from_email(email).authenticate(ip=request.client.host, otp=otp)
    return Token(
        access_token=token_data.to_jwt(),
        token_type="bearer",
    )


@app.post("/token", response_model=Token)
def token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
    """
    Standard OAuth2 Password endpoint

    :param request: the request IP must match the IP that requested /login
    :param form_data: username/password
    :return: oauth Token
    """
    return _token(form_data.username, form_data.password, request)


@app.get("/magic/{email}/{otp}", response_model=Token)
def magic(email: str, otp: str, request: Request) -> Token:
    """
    Magic link login: XXX: Needs to be a JS application to save
    the token client side.

    :param email:
    :param otp:
    :param request:
    :return:
    """
    return _token(email, otp, request)


@app.get("/users/me", response_model=User)
async def get_users_me(current_user: User = Depends(get_current_active)) -> User:
    """
    Get information about the authenticated user.

    :param current_user: active user from oAuth/database
    :return: User information
    """
    return current_user


@app.post("/users/me")
def post_users_me(
    data: EditableUser,
    request: Request,
    otp: Optional[str] = None,
    current_user: User = Depends(get_current_active),
    deliver=Depends(otp_delivery),
    session=Depends(session),
):
    updated_settings = data.dict(
        exclude_none=True, exclude_unset=True, exclude_defaults=True
    )
    if "email" in updated_settings:
        if otp is not None:
            current_user.authenticate(ip=request.client.host, otp=otp, session=session)
        else:
            # handle email updates specially, to validate the new address
            current_user.email = data.email
            otp = current_user.login(ip=request.client.host, session=session)
            deliver(current_user, otp)
            return {"detail": "Resubmit request with updated OTP"}
    for k, v in updated_settings.items():
        setattr(current_user, k, v)
    session.add(current_user)
    session.commit()
