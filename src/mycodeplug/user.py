"""
User and Session management.
"""
import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
import json
import os
from typing import Any, Dict, Optional, Union
import uuid

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
import psycopg2.extensions
import psycopg2.extras
from pydantic import BaseModel

from .db import DBModel


SECRET_KEY = os.environ["SECRET_KEY"]
ALGORITHM = "HS256"
DEFAULT_EXPIRY = datetime.timedelta(days=14)
OTP_VALIDITY_PERIOD = datetime.timedelta(minutes=30)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


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
        except (JWTError, KeyError):
            raise ValueError("Invalid Token")


class User(BaseModel, DBModel):
    """
    id SERIAL PRIMARY KEY,
    created timestamp with time zone NOT NULL DEFAULT now(),
    created_ip inet NOT NULL,
    email text UNIQUE NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    name text,
    data jsonb
    """

    id: Optional[int] = None
    created: datetime.datetime = datetime.datetime.now(tz=datetime.timezone.utc)
    created_ip: Optional[Union[IPv4Address, IPv6Address]] = None
    email: str
    enabled: bool = True
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
        :raise: KeyError if id or email is not found
        """
        param = self.email
        condition = "email = %s"
        if self.id is not None:
            param = self.id
            condition = "id = %s"
        query = """
            SELECT id, created, created_ip, email, enabled, name, data
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
                raise KeyError("User not found")
            row = c.fetchone()
            (
                self.id,
                self.created,
                created_ip,
                self.email,
                self.enabled,
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
            self.name,
            json.dumps(self.data) if self.data else None,
        ]
        if self.id is None:
            query = """
                INSERT INTO users (created, created_ip, email, enabled, name, data)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            """
        else:
            query = """
                UPDATE users
                SET created = %s,
                    created_ip = %s,
                    email = %s,
                    enabled = %s,
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

    def login(self, ip) -> str:
        """
        Request login for the given user.

        A given user can only have one active OTP at any given time. Subsequent
        logins will invalidate previously issued OTPs.

        :param ip: IP address of the request (auth must match!)
        :return: otp used to authenticate the session
        """
        invalidate_query = """
            UPDATE otp
            SET expires = NOW()
            WHERE user_id = %s AND
                  NOW() < expires;
        """
        create_params = [
            self.id,
            str(ip),
        ]
        create_query = """
            INSERT INTO otp (user_id, ip)
            VALUES (%s, %s)
            RETURNING otp;
        """
        with self.conn() as conn:
            c: psycopg2.extensions.cursor = conn.cursor()
            c.execute(invalidate_query, (self.id,))
            c.execute(create_query, create_params)
            otp = c.fetchone()[0]
            conn.commit()
        return otp

    def authenticate(self, ip, otp) -> TokenData:
        """
        Validate OTP and generate a session token.

        :param ip: IP requesting authentication must match IP passed to login()
        :param otp: One time password
        :return: TokenData
        :raise: ValueError if OTP doesn't match or is expired
        """
        query = """
            UPDATE otp
            SET expires = NOW()
            WHERE
                user_id = %s AND
                ip = %s AND
                otp = %s AND
                NOW() < expires
            RETURNING id
        """
        with self.conn() as conn:
            c: psycopg2.extensions.cursor = conn.cursor()
            c.execute(query, (self.id, ip, otp))
            if c.rowcount < 1:
                raise ValueError("Invalid OTP")
            valid_id = c.fetchone()[0]
            conn.commit()
        return TokenData(user_id=self.id, session_id=valid_id)


async def get_token(jwt_raw: str = Depends(oauth2_scheme)) -> TokenData:
    """
    Depends returns a decoded TokenData (or raises Exception).

    :param jwt_raw: auth token from oauth2 bearer
    :return: TokenData instance
    """
    return TokenData.from_jwt(jwt_raw)


async def get_current(token_data: TokenData = Depends(get_token)) -> User:
    """
    Fetch the User from the oauth session token.

    :param token_data: TokenData from `get_token`
    :return: User
    """
    return User.from_token(token_data)


async def get_current_active(current: User = Depends(get_current)) -> User:
    """
    Provide an enabled User from the oauth session token (or raise HTTP 400).

    :param current: User from `get_current`
    :return: User
    """
    if not current.enabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current
