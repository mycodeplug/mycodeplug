FROM python:3.10-alpine3.14

COPY . /app
WORKDIR /app
RUN \
 apk add --no-cache postgresql-libs && \
 apk add --no-cache --virtual .build-deps gcc musl-dev openssl-dev libffi-dev postgresql-dev && \
 python3 -m pip install --no-cache-dir poetry==1.1.11 && \
 poetry install && \
 apk --purge del .build-deps
CMD ["poetry", "run", \
         "uvicorn", \
         "mycodeplug.api:app", "--reload", \
         "--host", "0.0.0.0", "--port", "8009" \
]
