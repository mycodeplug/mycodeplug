from contextlib import contextmanager

import psycopg2
import psycopg2.extras
import psycopg2.extensions
import psycopg2.pool


psycopg2.extras.register_default_json(globally=True)
psycopg2.extras.register_default_jsonb(globally=True)


class DBModel:
    pool = None

    @classmethod
    @contextmanager
    def conn(cls) -> psycopg2.extensions.connection:
        if cls.pool is None:
            cls.pool = psycopg2.pool.SimpleConnectionPool(minconn=1, maxconn=10)
        try:
            c = cls.pool.getconn()
            yield c
        finally:
            cls.pool.putconn(c)
