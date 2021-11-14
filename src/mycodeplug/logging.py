import os
import logging

# set logging based on MYCODEPLUG_LOGLEVEL
app_loglevel = getattr(logging, os.environ.get("MYCODEPLUG_LOGLEVEL", "INFO").upper())
uvicorn_logger = logging.getLogger("uvicorn")


def getLogger(*args, **kwargs) -> logging.Logger:
    logger = logging.getLogger(*args, **kwargs)
    logger.setLevel(app_loglevel)
    logger.handlers = uvicorn_logger.handlers
    return logger
