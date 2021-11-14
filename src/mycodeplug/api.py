import importlib.metadata
import logging
import os

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

from .user import get_current_active, Token, User

APP_NAME = "mycodeplug"

app = FastAPI()

# set logging based on MYCODEPLUG_LOGLEVEL
app_loglevel = getattr(logging, os.environ.get("MYCODEPLUG_LOGLEVEL", "INFO").upper())
uvicorn_logger = logging.getLogger("uvicorn")
logger = logging.getLogger(APP_NAME)
logger.setLevel(app_loglevel)
logger.handlers = uvicorn_logger.handlers


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
async def login(email: str, request: Request):
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
        user = User(email=email).lookup()
    except KeyError:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    # XXX: send s.otp via email!
    print("{} magic token is: {}".format(user.name, user.login(request.client.host)))
    return


def _token(email: str, otp: str, request: Request) -> Token:
    """
    Authenticate an OTP.

    :param email: the user to login
    :param otp: the one-time password from a /login request
    :param request: the request, must match the IP that requested /login
    :return: oauth Token
    """
    try:
        token_data = (
            User(email=email).lookup().authenticate(ip=request.client.host, otp=otp)
        )
        return Token(
            access_token=token_data.to_jwt(),
            token_type="bearer",
        )
    except (KeyError, ValueError):
        pass
    raise HTTPException(status_code=400, detail="Incorrect username or password")


@app.post("/token", response_model=Token)
async def token(
    request: Request, form_data: OAuth2PasswordRequestForm = Depends()
) -> Token:
    """
    Standard OAuth2 Password endpoint

    :param request: the request IP must match the IP that requested /login
    :param form_data: username/password
    :return: oauth Token
    """
    return _token(form_data.username, form_data.password, request)


@app.get("/magic/{email}/{otp}", response_model=Token)
async def magic(email: str, otp: str, request: Request) -> Token:
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
