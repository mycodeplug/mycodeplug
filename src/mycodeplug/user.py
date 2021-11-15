"""
User, Authentication and Session management.
"""
import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
import json
import os
import random
from typing import Any, Dict, Optional, Union
import uuid

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
import psycopg2.extensions
import psycopg2.extras
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, JSON
from sqlalchemy.exc import NoResultFound
from sqlalchemy.sql import func, text
from sqlmodel import SQLModel, Field, select, Session
from sqlmodel.sql.expression import Select

from . import db


SECRET_KEY = os.environ["SECRET_KEY"]
ALGORITHM = "HS256"
DEFAULT_EXPIRY = datetime.timedelta(days=14)
OTP_VALIDITY_PERIOD = datetime.timedelta(minutes=5)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthenticationError(HTTPException):
    DEFAULT_STATUS_CODE = 401  # Unauthorized
    DEFAULT_DETAIL = "Incorrect email or password"
    """The response seen by the user, NO SENSITIVE DATA!"""

    def __init__(self, ctx: str = "", **kwargs):
        self.ctx = ctx
        super().__init__(
            status_code=kwargs.pop("status_code", self.DEFAULT_STATUS_CODE),
            detail=kwargs.pop("detail", self.DEFAULT_DETAIL),
            **kwargs,
        )


class InactiveUser(AuthenticationError):
    DEFAULT_STATUS_CODE = 400
    DEFAULT_DETAIL = "User is disabled or inactive. Contact admin."


class UnknownUser(AuthenticationError, KeyError):
    """The requested user was not found."""


class ExpiredToken(AuthenticationError):
    """The JWT presented is expired or the signature cannot be verified."""


class InvalidToken(AuthenticationError):
    """The token is otherwise valid but malformed -- maybe from a previous version."""


class ExpiredOTP(AuthenticationError):
    """The OTP for this user/ip combination is not valid or nonexistant."""


class IncorrectOTP(AuthenticationError):
    """Valid OTP for this user/ip was found, but the provided value does not match."""


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    user_id: int
    session_id: int

    def to_jwt(self, expires: Optional[datetime.timedelta] = None) -> str:
        """
        Encode data as JSON Web Token

        :param expires: expiration date for the token (DEFAULT_EXPIRY)
        :return: Signed and encoded payload.
        """
        to_encode = self.dict()
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        to_encode.update(
            dict(
                exp=now + (expires or DEFAULT_EXPIRY),
                sub="{}:{}".format(self.user_id, self.session_id),
            ),
        )
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    @classmethod
    def from_jwt(cls, token: str) -> "TokenData":
        """
        Decode payload and validate token signature.

        :param token: Signed and encoded payload
        :return: TokenData instance
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            sub: str = payload["sub"]
            return cls(user_id=payload["user_id"], session_id=payload["session_id"])
        except JWTError:
            raise ExpiredToken("Expired Token or signature mismatch")
        except KeyError:
            raise InvalidToken("Invalid Token format: {}".format(payload))


class User(SQLModel, table=True):
    """
    A database-backed user account
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    created: datetime.datetime = Field(
        default=None,
        sa_column=Column(
            "created",
            DateTime(timezone=True),
            server_default=func.now(),
        ),
    )
    created_ip: str
    email: str
    enabled: bool = True
    admin: bool = False
    name: Optional[str] = None
    data: dict = Field(
        default_factory=dict,
        sa_column=Column("data", JSON),
    )

    @classmethod
    def from_query(cls, query: Select, session: Optional[Session] = None) -> "User":
        with db.get_session(session) as s:
            result = s.exec(query)
            return result.one()

    @classmethod
    def from_email(cls, email: str, session: Optional[Session] = None) -> "User":
        try:
            return cls.from_query(
                select(cls).where(cls.email == email), session=session
            )
        except NoResultFound:
            raise UnknownUser(email)

    @classmethod
    def from_id(cls, id: int, session: Optional[Session] = None) -> "User":
        try:
            return cls.from_query(select(cls).where(cls.id == id), session=session)
        except NoResultFound:
            raise UnknownUser(id)

    @classmethod
    def from_token(cls, token: TokenData, session: Optional[Session] = None) -> "User":
        return cls.from_id(token.user_id, session=session)

    def _find_token(self, ip: str, session: Optional[Session] = None) -> "Otp":
        query = (
            select(Otp)
            .where(Otp.user_id == self.id)
            .where(Otp.ip == ip)
            .where(Otp.expires > func.now())
        )
        with db.get_session(session) as s:
            result = s.exec(query)
            try:
                return result.one()
            except NoResultFound:
                raise ExpiredOTP("Expired token for {}".format(ip))

    def login(self, ip: str, session: Optional[Session] = None) -> str:
        """
        Request login for the given user.

        A given user can only have one active OTP at any given time.

        :param ip: IP address of the request (auth must match!)
        :return: otp used to authenticate the session
        :raise: IncorrectOTP if the given (user, ip) pair already has
            an active token (must wait before granting another).
        """
        with db.get_session(session) as s:
            try:
                old_token_data = self._find_token(ip, session=s)
                if old_token_data:
                    raise IncorrectOTP(detail="Previous token still active")
            except ExpiredOTP:
                old_token_data = None
            new_otp = "{:06}".format(random.randint(0, 999999))
            hashed_otp = pwd_context.hash(new_otp)
            s.add(Otp(user_id=self.id, ip=ip, otp=hashed_otp))
            s.commit()
        return new_otp

    def authenticate(
        self, ip: str, otp: str, session: Optional[Session] = None
    ) -> TokenData:
        """
        Validate OTP and generate a session token.

        :param ip: IP requesting authentication must match IP passed to login()
        :param otp: One time password
        :return: TokenData
        :raise: ExpiredOTP if the OTP doesn't exist or is expired
        :raise: IncorrectOTP if OTP is found, but doesn't match
        """
        with db.get_session(session) as s:
            token = self._find_token(ip=ip, session=s)

            if not pwd_context.verify(otp, token.otp):
                raise IncorrectOTP("Bad token")

            token.expires = func.now()
            s.add(token)
            s.commit()
            return TokenData(user_id=self.id, session_id=token.id)


class Otp(SQLModel, table=True):
    """
    One-time password for email / magic login.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    ts: datetime.datetime = Field(
        default=None,
        sa_column=Column(
            "ts",
            DateTime(timezone=True),
            server_default=func.now(),
        ),
    )
    ip: str
    expires: datetime.datetime = Field(
        default=None,
        sa_column=Column(
            "expires",
            DateTime(timezone=True),
            server_default=text("(now() + '5 minutes'::interval)"),
        ),
    )
    otp: str


class EditableUser(BaseModel):
    """Components of the User that the User can edit"""

    email: Optional[str] = None
    name: Optional[str] = None
    data: Dict[str, Any] = None


class AdminEditableUser(EditableUser):
    """Components of the User that an admin can edit"""

    enabled: Optional[bool] = True


async def get_token(jwt_raw: str = Depends(oauth2_scheme)) -> TokenData:
    """
    Depends returns a decoded TokenData (or raises Exception).

    :param jwt_raw: auth token from oauth2 bearer
    :return: TokenData instance
    """
    return TokenData.from_jwt(jwt_raw)


def get_current(token_data: TokenData = Depends(get_token)) -> User:
    """
    Fetch the User from the oauth session token.

    :param token_data: TokenData from `get_token`
    :return: User
    """
    return User.from_token(token_data)


def get_current_active(current: User = Depends(get_current)) -> User:
    """
    Provide an enabled User from the oauth session token (or raise HTTP 400).

    :param current: User from `get_current`
    :return: User
    """
    if not current.enabled:
        raise InactiveUser()
    return current


def local_otp_delivery():
    """
    :return: callable accepting a User and otp string, arranging for it to be sent to the user
    """

    def deliver(user: User, otp: str):
        # XXX: send s.otp via email!
        print(
            "{} magic token is: {}".format(
                user.name or user.email,
                otp,
            ),
        )
        return {"detail": "new OTP sent"}

    return deliver
