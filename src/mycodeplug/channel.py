import datetime
import enum
from typing import Any, Dict, List, Optional
import uuid

import psycopg2.extras
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Enum, JSON
from sqlalchemy.sql import func, text
from sqlmodel import Field, Relationship, Session, SQLModel, create_engine

from . import db
from .user import User


class Channel(SQLModel, table=True):
    """
    A channel entry. Actual channel data is versioned in ChannelRevision
    """

    channel_uuid: Optional[uuid.UUID] = Field(
        default_factory=uuid.uuid4,
        primary_key=True,
    )
    owner_id: Optional[int] = Field(nullable=False, foreign_key="user.id")
    group_id: Optional[int]
    source: Optional[str]
    source_id: Optional[str]
    parent_channel: Optional[uuid.UUID] = Field(foreign_key="channel.channel_uuid")

    revisions: List["ChannelRevision"] = Relationship(back_populates="channel")
    owner: User = Relationship()


class Name(SQLModel, table=True):
    """
    The name of a channel, zone, scanlist, contact, etc.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    alt_name_16: Optional[str] = Field(default=None, max_length=16)
    alt_name_6: Optional[str] = Field(default=None, max_length=6)
    alt_name_5: Optional[str] = Field(default=None, max_length=5)


class Power(enum.Enum):
    LOW = "low"
    MID = "mid"
    HIGH = "high"
    TURBO = "turbo"


class ChannelRevision(SQLModel, table=True):
    """
    Channel settings.

    Typicaly would be the result of aggregating revisions for a given
    channel up to a certain point.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(foreign_key="user.id")
    channel_uuid: Optional[uuid.UUID] = Field(foreign_key="channel.channel_uuid")
    ts: datetime.datetime = Field(
        default=None,
        sa_column=Column(
            "ts",
            DateTime(timezone=True),
            server_default=func.now(),
        ),
    )
    parent_revision: Optional[int] = Field(foreign_key="channelrevision.id")
    name_id: Optional[int] = Field(foreign_key="name.id")
    description: Optional[dict] = Field(
        default_factory=dict,
        sa_column=Column("description", JSON),
    )
    frequency: Optional[float]
    f_offset: Optional[float]
    power: Optional[Power] = Field(sa_column=Column(Enum(Power)))
    rx_only: Optional[bool]
    mode: Optional[str]
    mode_settings: Optional[dict] = Field(
        default_factory=dict,
        sa_column=Column("mode_settings", JSON),
    )
    vendor_settings: Optional[dict] = Field(
        default_factory=dict,
        sa_column=Column("vendor_settings", JSON),
    )

    channel: Channel = Relationship(back_populates="revisions")
    name: Name = Relationship()
    user: User = Relationship()


def make_sample_channels(email, session=None):
    with db.get_session(session) as s:
        u = User.from_email(email)
        ch = Channel(
            owner=u,
            revisions=[
                ChannelRevision(
                    user=u,
                    name=Name(name="Foo Channel"),
                    frequency=146.520,
                    f_offset=0,
                    power=Power.LOW,
                    rx_only=False,
                    mode="FM",
                    mode_settings=dict(
                        bandwidth="12.5",
                    ),
                )
            ],
        )
        s.add(ch)
        s.commit()
