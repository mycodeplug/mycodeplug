from contextlib import contextmanager
from typing import cast, Iterator

from sqlmodel import create_engine, Session, SQLModel


# psycopg2.extras.register_default_json(globally=True)
# psycopg2.extras.register_default_jsonb(globally=True)


global_engine = create_engine("postgresql:///", echo=True)


def initialize_metadata():
    from . import channel
    from . import user

    SQLModel.metadata.create_all(global_engine)


def session(session=None, engine=None):
    if session is None:
        if engine is None:
            engine = global_engine
        with Session(engine) as session:
            yield session
    else:
        yield session


get_session = contextmanager(session)
