#FastAPI Server
from base64 import b64encode, b64decode
import binascii
import hashlib
import hmac
import json
from lib2to3.pgen2.token import OP
from typing import Optional
from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = "9a06e52584d18cabc4706de33a118e7e7d3403ebf06ff43bdda4f7d40276c86e"
PASSWORD_SALT = "59c9846ed1d591f4b1d60b791056906d73278eeb0d0a0b3ede6cab999ed7bd2c"


def sign_data(data: str) -> str:
    """Возвращает подписанные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    if username_signed.count('.') != 1:
        return None
    username_base64, sign = username_signed.split('.')
    try:
        username = b64decode(username_base64.encode(), validate=True).decode()
    except binascii.Error:
        return None
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    hash_password = hashlib.sha256(
        (password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password = users[username]["password"].lower()
    return hash_password == stored_password


users = {
    "denis@user.com": {
        "name": "Денис",
        "password": "632a78ec46e43f56f5a3dc3ddd4491131716a0b0015ad2ec51ec20aa4e7be376",
        "balance": 100_000_000_000
    },
    "petr@user.com": {
        "name": "Пётр",
        "password": "7aa15bd0c294789770c2527e584aaba86c7c6bb049f4418babd63c9065617cf1",
        "balance": 555_555
    }
}


@app.get("/login")
@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(f"Привет {user['name']}<br> Ваш баланс: {user['balance']}<br>", media_type="text/html")


@app.post("/login")
# def process_login_page(username: str = Form(...), password: str = Form(...)):
def process_login_page(data: dict = Body(...)):
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(json.dumps({
            "success": False,
            "message": 'Я вас не знаю'
        }),
            media_type="application/json")
    response = Response(json.dumps({
        "success": True,
        "message": f"Привет {user['name']}<br> Ваш баланс: {user['balance']}<br>"
    }),
        media_type="application/json")
    username_signed = b64encode(username.encode()).decode() + '.' + \
        sign_data(username)
    response.set_cookie(
        key='username', value=username_signed, expires=60*60*24*365)
    return response
