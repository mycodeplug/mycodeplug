"""
Handle email in and out of the application
"""
import os
from urllib.parse import urljoin

import httpx

from .logging import getLogger
from .user import User


BASE_URL = os.environ.get("BASE_URL")
DOMAIN = os.environ.get("MG_DOMAIN")
TOKEN = os.environ.get("MG_TOKEN")
MG_API = f"https://api.mailgun.net/v3/{DOMAIN}/messages"
FROM = "MyCodeplug.com <service@mycodeplug.com>"
OTP_MESSAGE = {
    "from": FROM,
    "subject": "Click this link to login",
    "text": """{user},
Your one-time password is {otp}. This password expires in 5 minutes.

Use the following link to login: {link}

-MyCodeplug
""",
}

logger = getLogger(__name__)


def otp_delivery():
    """
    :return: callable accepting a User and otp string, arranging for it to be sent to the user
    """

    def deliver(user: User, otp: str):
        data = OTP_MESSAGE.copy()
        data["to"] = user.email
        data["text"] = data["text"].format(
            user=user.name or user.email,
            otp=otp,
            link=urljoin(BASE_URL, "/magic/{}/{}".format(user.email, otp)),
        )
        httpx.post(MG_API, data=data, auth=("api", TOKEN)).raise_for_status()
        return {"detail": "new OTP sent"}

    return deliver


if None in (TOKEN, DOMAIN):
    logger.warning(
        "Mailgun token and/or domain not available in environment. "
        "Falling back to local/weak OTP delivery",
    )
    from .user import local_otp_delivery as otp_delivery
