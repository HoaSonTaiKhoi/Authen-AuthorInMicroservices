import os, requests
from flask import render_template
import hashlib

def token_check(request, token):
    if not "Authorization" in request.headers:
        return None, ("missing credentials", 401)

    if not token:
        return None, ("missing credentials", 401)

    response = requests.post(
        f"http://127.0.0.1:5000/validate",
        headers={"Authorization": token},
    )

    if response.status_code == 200:
        return response.text, None
    else:
        return None, (response.text, response.status_code)

def login(request):
    auth = request.authorization
    if not auth:
        return None, ("missing credentials", 401)

    #hash the password
    sha = hashlib.sha3_256()
    sha.update(bytes(auth.password, "utf-8"))
    hash_pass = sha.hexdigest()

    properties = (auth.username, hash_pass)

    response = requests.post(
        f"http://127.0.0.1:5000/login", auth=properties
    )

    

    if response.status_code == 200:
        return response.text, None
    else:
        return None, (response.text, response.status_code)
    
def register(request):
    auth = request.authorization
    if not auth:
        return None, ("missing information", 401)

    #hash the passowrd
    sha = hashlib.sha3_256()
    sha.update(bytes(auth.password, "utf-8"))
    hash_pass = sha.hexdigest()

    properties = (auth.username, hash_pass)

    #request for register auth _ server
    response = requests.post(
        f"http://127.0.0.1:5000/register", auth=properties
    )

    if response.status_code == 200:
        return response.text, None
    else:
        return None, (response.text, response.status_code)
