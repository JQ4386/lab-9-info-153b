from flask import Flask, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

import secrets

from db import db
from passlib.hash import pbkdf2_sha256 as sha256

class UserModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    quote = db.Column(db.String(80), nullable=True)


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"

app.config["JWT_SECRET_KEY"] = "205114350365825736757272630144817054044"
jwt = JWTManager(app)

# Add JWT register endpoint
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    quote = data.get("quote")

    if UserModel.query.filter(UserModel.username == username).first():
        return {"message": "User already exists"}, 409
    
    user = UserModel(username=username, password=sha256.hash(password), quote=quote)
    
    db.session.add(user)
    db.session.commit()

    return {"message": "User created successfully"}, 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = UserModel.query.filter_by(username=username).first()

    if user and sha256.verify(password, user.password):
        access_token = create_access_token(identity=user.id)
        return {"access_token": access_token}, 200

    return {"message": "Invalid login details"}, 401

@app.route("/protected")
@jwt_required()
def protected():
    user_id = get_jwt_identity()
    user = UserModel.query.get(user_id)

    if user:
        return {"username": user.username, "favorite_quote": user.quote}, 200

    return {"message": "User not found"}, 404

with app.app_context():
    db.init_app(app)
    db.create_all()
    debug = True