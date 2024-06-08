import jwt, datetime, os, json
from flask import Flask, request
from flask_mysqldb import MySQL 

auth_server = Flask(__name__)
jwt_secret = '7b8c6ef87a5d4e3e2b1a0d9c8b7a6f5e'

#function loadconfig
def load_mysql_config(filename="./db_config.json"):
    with open(filename) as config_file:
        config = json.load(config_file)
    return config

#Load config database
mysql_config=load_mysql_config()

# config
auth_server.config["MYSQL_HOST"] = mysql_config["host"]
auth_server.config["MYSQL_USER"] = mysql_config["user"]
auth_server.config["MYSQL_PASSWORD"] = mysql_config["password"]
auth_server.config["MYSQL_DB"] = mysql_config["database"]

# Initialize mysql
mysql = MySQL(auth_server)
@auth_server.route("/")
def index():
    return "Welcome!"

# Routes
@auth_server.route("/register", methods=['POST'])
def register():
    auth = request.authorization
    print(request)
    if not auth:
        return "missing information", 400
    
    #insert into database
    cur = mysql.connection.cursor()
    res = cur.execute(
        "insert into users (username, password) values (%s, %s)", (auth.username,auth.password,)
    )
    mysql.connection.commit()

    if res > 0:
        return "Register successfully!", 201
    return "Failed to Register", 500

@auth_server.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return "missing credentials", 401

    # check db for username and password
    cur = mysql.connection.cursor()
    res = cur.execute(
        "SELECT * FROM users WHERE username=%s", (auth.username,)
    )

    if res > 0:
        user_row = cur.fetchone()
        id =  user_row[0]
        username = user_row[1]
        password = user_row[2]

        if auth.username != username or auth.password != password:
            return "invalid credentials", 401
        else:
            return createJWT(id, jwt_secret, True)
    else:
        return "invalide credentials", 401


@auth_server.route("/validate", methods=["POST"])
def validate():
    encoded_jwt = request.headers["Authorization"]

    print(encoded_jwt)

    if not encoded_jwt:
        return "missing credentials", 401

    try:
        decoded = jwt.decode(
            encoded_jwt, jwt_secret, algorithms=["HS256"]
        )
    except:
        return "not authorized", 403
        
    print(f"Decoded: {decoded}")
    return decoded, 200


def createJWT(id, secret, authz):

    payload =         {
            "id": id,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(days=1),
            "iat": datetime.datetime.utcnow(),
            "admin": authz,
        }

    return jwt.encode(
        payload,
        secret,
        algorithm="HS256",
    )

context = ('./certificate.crt', './private_key.key')

if __name__ == "__main__":
    auth_server.run(host="0.0.0.0", port=5000, debug=True)
