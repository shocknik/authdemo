from tokenize import cookie_re
from urllib import response
from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response
from typing import Optional
import hmac
import hashlib
import base64
import json


app = FastAPI()

SECRET_KEY = "fc0ddfa66da61a265079e86cabadc2aee8dfddfbe48afc6ee7d2453b5ead9517"
PASSWORD_SALT = "9dcac779470489c0f915596efb3f5cbf26ef078d6e495b770b662b6f895ab9fa"




def sign_data(data: str) -> str:
    """Возвращает подписаннные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signet_strings(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username



def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return password_hash == stored_password_hash


    return hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest.lower() \
        == password_hash.lower()


users = {
    "alexey@user.com": {
        "name" : "Alexey",
        "password": "a17ef176744bd5b77add388546068689e0d4a7ca8e42d4f8c65271c81023629e",
        "balance": 100_000
    },
    "peter@user.com": {
        "name" : "Petr",
        "password": "480a08acaf23f4e461c545facd4e684efb7a424422118b1d9471a18c676fd69a",
        "balance": 333_333,
    },

}

@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()

    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signet_strings(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Hello, {users[valid_username]['name']}!<br />"
        f"Баланс: {users[valid_username]['balance']}"
        
        , media_type='text/html')
    
    

@app.post("/login")
def process_login_page(data: dict = Body(...)):
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю"
            }),
            media_type="application/json")

    response = Response(
        json.dumps({
            "success": True,
            "message": f"Hello {user['name']}</br> Balance: {user['balance']}"
        }),
        media_type="application/json")

    username_signed = base64.b64encode(username.encode()).decode()+"."+sign_data(username)
    response.set_cookie(key='username', value=username_signed)
    return response
