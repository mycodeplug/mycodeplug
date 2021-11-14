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

from .db import DBModel


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


class User(BaseModel, DBModel):
    """
    id SERIAL PRIMARY KEY,
    created timestamp with time zone NOT NULL DEFAULT now(),
    created_ip inet NOT NULL,
    email text UNIQUE NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    admin boolean NOT NULL DEFAULT false,
    name text,
    data jsonb
    """

    id: Optional[int] = None
    created: datetime.datetime = datetime.datetime.now(tz=datetime.timezone.utc)
    created_ip: Optional[Union[IPv4Address, IPv6Address]] = None
    email: str
    enabled: bool = True
    admin: bool = False
    name: Optional[str] = None
    data: Dict[str, Any] = {}

    @classmethod
    def from_token(cls, token: TokenData) -> "User":
        return cls.by_id(id=token.user_id)

    @classmethod
    def by_id(cls, id: int) -> "User":
        return cls(id=id, email="").lookup()

    def lookup(self) -> "User":
        """
        Refresh this instance from database.

        Prefer lookup by id, if specified. Otherwise lookup by email address.

        :return: User instance if email is found
        :raise: UnknownUser if id or email is not found
        """
        param = self.email
        condition = "email = %s"
        if self.id is not None:
            param = self.id
            condition = "id = %s"
        query = """
            SELECT id, created, created_ip, email, enabled, admin, name, data
            FROM users
            WHERE {}
            LIMIT 1
        """.format(
            condition
        )
        with self.conn() as conn:
            c: psycopg2.extensions.cursor = conn.cursor()
            c.execute(query, (param,))
            if c.rowcount < 1:
                raise UnknownUser(condition % param)
            row = c.fetchone()
            (
                self.id,
                self.created,
                created_ip,
                self.email,
                self.enabled,
                self.admin,
                self.name,
                data,
            ) = row
            self.created_ip = ip_address(created_ip)
            self.data = data or {}
        return self

    def save(self):
        """
        Persist data from this instance to the database.

        :return: self
        """
        params = [
            self.created,
            str(self.created_ip),
            self.email,
            self.enabled,
            self.admin,
            self.name,
            json.dumps(self.data) if self.data else None,
        ]
        if self.id is None:
            query = """
                INSERT INTO users (created, created_ip, email, enabled, admin, name, data)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """
        else:
            query = """
                UPDATE users
                SET created = %s,
                    created_ip = %s,
                    email = %s,
                    enabled = %s,
                    admin = %s,
                    name = %s,
                    data = %s
                WHERE id = %s
            """
            params.append(self.id)
        with self.conn() as conn:
            c: psycopg2.extensions.cursor = conn.cursor()
            c.execute(query, params)
            if self.id is None:
                self.id = c.fetchone()[0]
            conn.commit()
        return self

    def _find_token(self, ip) -> (int, str):
        get_query = """
            SELECT id, otp
            FROM otp
            WHERE
                user_id = %s AND
                ip = %s AND
                NOW() < expires
        """
        with self.conn() as conn:
            c: psycopg2.extensions.cursor = conn.cursor()
            c.execute(get_query, (self.id, ip))
            if c.rowcount != 1:
                raise ExpiredOTP("Expired token for {}".format(ip))
            return c.fetchone()

    def login(self, ip) -> str:
        """
        Request login for the given user.

        A given user can only have one active OTP at any given time.

        :param ip: IP address of the request (auth must match!)
        :return: otp used to authenticate the session
        :raise: IncorrectOTP if the given (user, ip) pair already has
            an active token (must wait before granting another).
        """
        try:
            old_token_data = self._find_token(ip)
            if old_token_data:
                raise IncorrectOTP(detail="Previous token still active")
        except ExpiredOTP:
            old_token_data = None
        new_otp = "{:06}".format(random.randint(0, 999999))
        hashed_otp = pwd_context.hash(new_otp)
        create_params = [
            self.id,
            str(ip),
            hashed_otp,
        ]
        create_query = """
            INSERT INTO otp (user_id, ip, otp)
            VALUES (%s, %s, %s);
        """
        with self.conn() as conn:
            c: psycopg2.extensions.cursor = conn.cursor()
            c.execute(create_query, create_params)
            conn.commit()
        return new_otp

    def authenticate(self, ip, otp) -> TokenData:
        """
        Validate OTP and generate a session token.

        :param ip: IP requesting authentication must match IP passed to login()
        :param otp: One time password
        :return: TokenData
        :raise: ExpiredOTP if the OTP doesn't exist or is expired
        :raise: IncorrectOTP if OTP is found, but doesn't match
        """
        token_id, hashed_otp = self._find_token(ip=ip)

        if not pwd_context.verify(otp, hashed_otp):
            raise IncorrectOTP("Bad token")

        update_query = """
            UPDATE otp
            SET expires = NOW()
            WHERE 
                id = %s
        """
        with self.conn() as conn:
            c: psycopg2.extensions.cursor = conn.cursor()
            c.execute(update_query, (token_id,))
            conn.commit()
        return TokenData(user_id=self.id, session_id=token_id)


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
