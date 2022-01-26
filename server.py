# FastAPI Server
import base64
import hmac
import hashlib
import json

from typing import Optional

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = "ca651fb39089d533da281c2503a9ef77f4aa110b3a567158e0736a64d1a6a2d7"
PASSWORD_SALT = "4efb7008fbf24a98e9bf60727caca8aea8ad6d6011e7c637395720ab2431c8eb"


def sign_data(data: str) -> str:
    """Returns signed data 'data'. """
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
        ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256( (password + PASSWORD_SALT).encode() ).hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    return  password_hash == stored_password_hash


users = {
    'sam@user.com': {
        'name': 'Sam',
        #  some_pass_1
        'password': 'cb4e272791544a122cd0d2c83dada163f863cf0978b89908c683518efcd588ea',
        'balance': 100_000
    },
    'john@user.com': {
        'name': 'John',
        #  some_pass_2
        'password': '45165591cefbbdcc491aab917f0f30019eaf324e2fdab55ea6428b3142fe61ca',
        'balance': 50_000
    }
}

@app.get('/')
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()

    if not username:
        return Response(login_page, media_type='text/html')

    valid_username = get_username_from_signed_string(username)

    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key="username")
        return response

    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Hi, {users[valid_username]['name']}!<br />"
        f"Your balance: {users[valid_username]['balance']}", 
        media_type='text/html')


@app.post('/login')
def process_login_page(data: dict = Body(...)):
    username = data["username"]
    password = data["password"]

    user = users.get(username)
    
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": 'unknown user!'
            }),
            media_type='application/json')

    response = Response(
         json.dumps({
                "success": True,
                "message": f"Hi: {user['name']}!<br />Your balance: {user['balance']}"
            }),
        media_type="application/json")
    
    username_signed = base64.b64encode(username.encode()).decode() + "." + \
        sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response
    
