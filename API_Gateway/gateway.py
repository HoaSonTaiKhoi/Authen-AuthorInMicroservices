import os, json
from flask import Flask, request, jsonify, render_template
import auth_gateway
import task_gateway
from flask_mysqldb import MySQL
import hashlib

gateway = Flask(__name__)


# load database configuration
def load_mysql_config(filename="./db_config.json"):
    with open(filename) as config_file:
        config = json.load(config_file)
    return config

#Load config database
mysql_config=load_mysql_config()

print(mysql_config["host"])
# config
gateway.config["MYSQL_HOST"] = mysql_config["host"]
gateway.config["MYSQL_USER"] = mysql_config["user"]
gateway.config["MYSQL_PASSWORD"] = mysql_config["password"]
gateway.config["MYSQL_DB"] = mysql_config["database"]

# Initialize Data
mysql = MySQL(gateway)

@gateway.route('/')
def hello():
    return 'Hello'

@gateway.route("/signup")
def register_show():
    return render_template('signup.html')

@gateway.route("/signup", methods=["POST"])
def register():
    print(request)
    res, err = auth_gateway.register(request)
    if not err:
        return res
    else:
        return err

@gateway.route("/login")
def login_show():
    return render_template('login.html')

@gateway.route("/login", methods=["POST"])
def login():
    token, err = auth_gateway.login(request)
    print(f"Token: {token}")
    if not err:
        #hash the token
        sha = hashlib.sha3_256()
        sha.update(bytes(token, "utf-8"))
        opaque = sha.hexdigest()

        #insert into database
        cur = mysql.connection.cursor()
        res = cur.execute(
            "INSERT INTO opaque (auth_key, opaque_key) VALUES (%s, %s)", (token, opaque,)
        )
        mysql.connection.commit()
        return opaque
    else:
        return err


@gateway.route("/create", methods=["POST"])
def create():
    opaque = request.headers["Authorization"]

    print(f"Opaque: {opaque}")
    cursor = mysql.connection.cursor()
    # Check if the task exists
    query = "SELECT auth_key FROM opaque WHERE opaque_key = %s"
    cursor.execute(query, (opaque,))
    token = cursor.fetchone()
    print(token)
    token = token[0]

    access, err = auth_gateway.token_check(request, token)
    if err:
        return err

    access = json.loads(access)

    if access["admin"]:
        task.create(request, access["id"])

        return "success!", 200
    else:
        return "not authorized", 401
    
@gateway.route("/delete/<int:task_id>", methods=["DELETE"])
def delete(task_id):
    opaque = request.headers["Authorization"]
    cursor = mysql.connection.cursor()
    # Check if the task exists
    query = "SELECT auth_key FROM opaque WHERE opaque_key = %s "
    cursor.execute(query, (opaque,))
    token = cursor.fetchone()
    token = token[0]

    access, err = auth_gateway.token_check(request, token)
    if err:
        return err

    access = json.loads(access)

    if access["admin"]:
        task.remove(request, access["id"], task_id)

        return "success!", 200
    else:
        return "not authorized", 401

@gateway.route("/retrival", methods=["GET"])
def retrieval():
    opaque = request.headers["Authorization"]
    cursor = mysql.connection.cursor()
    # Check if the task exists
    query = "SELECT auth_key FROM opaque WHERE opaque_key = %s "
    cursor.execute(query, (opaque,))
    token = cursor.fetchone()
    token = token[0]

    access, err = auth_gateway.token_check(request, token)

    if err:
        return err

    access = json.loads(access)

    if access["admin"]:
        data = task.get(request, access["id"])
        print(data)
        return jsonify(data), 200
    else:
        return "not authorized", 401


@gateway.route("/logout", methods=["GET"])
def logout():
    opaque = request.headers["Authorization"]
    cursor = mysql.connection.cursor()
    # Check if the task exists
    query = "SELECT auth_key FROM opaque WHERE opaque_key = %s "
    cursor.execute(query, (opaque,))
    token = cursor.fetchone()
    token = token[0]

    access, err = auth_gateway.token_check(request, token)

    if err:
        return err

    access = json.loads(access)

    if access["admin"]:
        query = "DELETE FROM opaque WHERE opaque_key = %s "
        cursor.execute(query, (opaque,))
        mysql.connection.commit()
        cursor.close()
        return "Success for deleting", 200
    return "failure", 500

context = ('./certificate.crt', './private_key.key')

if __name__ == "__main__":
    gateway.run(host="0.0.0.0", port=8000, debug=True)
