from flask import Flask,request,jsonify
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
from flask_jwt_extended import(
    create_access_token,
    get_jwt_identity,
    create_refresh_token,
    unset_jwt_cookies,
    set_access_cookies,
    set_refresh_cookies,
    JWTManager,
    jwt_required
)
from datetime import timedelta
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
load_dotenv()
app=Flask(__name__)
#database url
app.config['SQLALCHEMY_DATABASE_URI']=os.getenv("DB_URL")
#SECRET_KEY for signing JWT 
app.config['SECRET_KEY']=os.getenv("SECRET_KEY")
#csrf key
app.config['CSRF_KEY']=os.getenv("CSRF_KEY")
#where to find JWT 
#store in the cookie
app.config['JWT_TOKEN_LOCATION']=["cookies"]
#name for JWT cookie
app.config['JWT_ACCESS_COOKIE_NAME']="access_token"
#refresh token name
app.config['JWT_REFRESH_COOKIE_NAME']="refresh_token"
#sent cookies over HTTPS only
app.config['JWT_COOKIE_SECURE']=False #set True in production
#enable CSRF Protection
app.config['JWT_COOKIE_CSRF_PROTECT']=False #set True in production
#prevent JS access
app.config['JWT_COOKIE_HTTPONLY']=False #set True in production
#prevent cross origin requests
app.config['JWT_SAMESITE']='Lax' #set Strict in production
#jwt access token expiration
app.config['JWT_ACCESS_TOKEN_EXPIRES']=timedelta(minutes=5)
#refresh token expiration
app.config['JWT_REFRESH_TOKEN_EXPIRES']=timedelta(minutes=5)
db=SQLAlchemy(app)
#initialize app with JWT auth
jwt=JWTManager()
jwt.init_app(app)
#initialize app with bcrypt
bcrypt=Bcrypt()
bcrypt.init_app(app)
migrate=Migrate()
migrate.init_app(app,db)
# @app.route("/")
# def hello():
#     return 'Hello world'
#register user
@app.post("/api/v1/auth/register")
def register():
    #get data
    data=request.get_json(silent=True)
    print("Data: ",data)
    #check if json body is not provided
    if not data:
        return jsonify({
            "error":"JSON body required"
        }),400
    #username
    username=data.get("username")
    #email
    email=data.get("email")
    #password
    password=data.get("password")
    if not username or not password:
        return jsonify({
            "error":"username and password required"
        }),400
    #check if username already exists
    username_exists=User.query.filter_by(username=username).first()
    email_exists=User.query.filter_by(email=email).first()
    if username_exists or email_exists:
        return jsonify({
            "error":"Invalid username or email"
        }),400
    #hash password
    hashed_password=bcrypt.generate_password_hash(password).decode("utf-8")
    #save changes to the database
    user=User(username=username,email=email,password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return jsonify({
        "message":"User created successfully",
        "user":{
            "username":username,
            "email":email
        }
    }),200


#login user
@app.post("/api/v1/auth/login")
def login():
    #get JWT identity
    # user_id=get_jwt_identity()
    #get data
    data=request.get_json(silent=True)
    if not data:
        return jsonify({
            "error":"JSON body required"
        }),400
    #username
    username=data.get("username")
    #password
    password=data.get("password")
    #check username in the database
    user=User.query.filter_by(username=username).first()
    if user is None:
        return jsonify({
            "error":"Username not found"
        }),404

    if not username or not bcrypt.check_password_hash(user.password,password):
        return jsonify({
            "error":"Invalid credentials"
        }),401
    #create access token
    access_token=create_access_token(identity=str(user.id))
    #create refresh_token
    refresh_token=create_refresh_token(identity=str(user.id))
    response=jsonify({
        "message":"Login successful",
        "username":user.username
    })
    #put JWT inside cookies
    set_access_cookies(response,access_token)
    set_refresh_cookies(response,refresh_token)
    return response,200


#logout user
@app.post("/api/v1/auth/logout")
@jwt_required()
def logout():
    response=jsonify({
        "message":"You have been logged out"
    })
    #reset JWT
    unset_jwt_cookies(response)
    return response,200


#refresh JWT 
@app.post("/api/v1/auth/refresh")
@jwt_required(refresh=True)
def refresh_token():
    user_id=get_jwt_identity()
    new_access_token=create_access_token(identity=str(user_id))
    response=jsonify({
        "message":"Access token refreshed"
    })
    set_access_cookies(response,new_access_token)
    return response,200


#handle jwt errors
@jwt.invalid_token_loader
def invalid_token_loader(error):
    return json({
        "error":"Invalid token"
    }),401


@jwt.expired_token_loader
def expired_token_loader(jwt_header,jwt_payload):
    token_type=jwt_payload["type"]
    return jsonify({
        "error":f"{token_type} Token expired"
    }),401


@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        "error":"Authentication required"
    }),401


#create note
@app.post("/api/v1/notes")
@jwt_required()
def create_note():
    user_id=get_jwt_identity()
    data=request.get_json(silent=True)
    if not data:
        return jsonify({
            "error":"JSON body required"
        }),400
    #title
    title=data.get("title")
    if not title:
        return jsonify({
            "error":"Title required"
        }),400
    #description
    description=data.get("description")
    if not description:
        return jsonify({
            "error":"Description required"
        }),400
    #save changes to the database
    notes=Notes(title=title,description=description,user_id=user_id)
    db.session.add(notes)
    db.session.commit()
    return jsonify({
        "message":"Note created successfully",
        "Note":{
            "id":notes.id,
            "title":notes.title,
            "description":notes.description,
            "user_id":notes.user_id
        }
    }),200
#view notes
@app.get("/api/v1/notes/<id>")
@jwt_required()
def view_notes(id):
    user_id=get_jwt_identity()
    if id:
        try:
            id=int(id)
        except ValueError:
            return jsonify({
                "error":"Invalid id"
            }),400
    #fetch notes from the database
    notes=Notes.query.filter_by(id=id,user_id=user_id).first()
    if notes is None:
        return jsonify({
            "error":"Note not found"
        }),404
    return jsonify({
        "message":"Saved notes",
        "id":notes.id,
        "title":notes.title,
        "description":notes.description,
        "user_id":notes.user_id
    }),200
#update note
@app.patch("/api/v1/notes/<id>")
@jwt_required()
def update_note(id):
    user_id=get_jwt_identity()
    if id:
        try:
            id=int(id)
        except ValueError:
            return jsonify({
                "error":"Invalid id"
            }),400
    #data
    data=request.get_json(silent=True) 
    if not data:
        return jsonify({
            "error":"JSON body required"
        }),400
    title=data.get("title")
    description=data.get("description")
    note_to_update=Notes.query.filter_by(id=id,user_id=user_id).first()
    if note_to_update is None:
        return jsonify({
            "error":"Note not found"
        }),404
    if title:
        note_to_update.title=title
    if description:
        note_to_update.description=description
    #save changes to the database
    db.session.commit()
    return jsonify({
        "message":"Note updated successfully",
        "id":note_to_update.id,
        "title":note_to_update.title,
        "description":note_to_update.description
    }),200

#delete note
@app.delete("/api/v1/notes/<id>")
@jwt_required()
def delete_note(id):
    user_id=get_jwt_identity()
    if id:
        try:
            id=int(id)
        except ValueError:
            return jsonify({
                "error":"Invalid id"
            }),400
    #note to delete
    note_to_delete=Notes.query.filter_by(user_id=user_id,id=id).first()
    if note_to_delete is None:
        return jsonify({
            "error":"Note not found"
        }),404
    db.session.delete(note_to_delete)
    db.session.commit()
    return "",201

    
#database model
#users table
class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(50),nullable=False)
    email=db.Column(db.String(100),nullable=False)
    password=db.Column(db.String(255),nullable=False)
    notes=db.relationship("Notes",back_populates="owner")

#notes table
class Notes(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    title=db.Column(db.String(50),nullable=False)
    description=db.Column(db.String(100),nullable=False)
    user_id=db.Column(db.Integer,db.ForeignKey("user.id"))
    #connect notes to users table
    owner=db.relationship("User",back_populates="notes")
if __name__=="__main__":
    with app.app_context():
        db.create_all()
        # db.drop_all()

    app.run(debug=True)