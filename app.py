from functions import is_valid_email, verify_code, verify_code_expiration
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy import Column, Integer, String, and_
from flask_migrate import Migrate
from flask import Flask
from flask_mail import Mail, Message
from sqlalchemy.dialects.postgresql import UUID
from data import data, user_profile
from dotenv import load_dotenv
from sqlalchemy.dialects.postgresql import ARRAY
from datetime import datetime
import os
import pendulum
import html
import uuid
from itsdangerous import URLSafeSerializer

# Function to encode the ID
def encode_id(id):
    return serializer.dumps(id)

# Function to decode the ID
def decode_id(encoded_id):
    return serializer.loads(encoded_id)


app = Flask(__name__) # creates a flask app and sends store in an instance app

app.config.from_object("config")
app.config.get("SQLALCHEMY_DATABASE_URI")
app.config.get("SQLALCHEMY_TRACK_MODIFICATIONS")

serializer = URLSafeSerializer(app.config.get("AES_KEY"))
# Flask-Mail Configuration for Gmail SMTP
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # Use TLS port
app.config['MAIL_USE_TLS'] = True  # Enable TLS encryption
app.config['MAIL_USE_SSL'] = False  # Do not use SSL
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Your Gmail username (email address)
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Your Gmail password or app-specific password
app.config['MAIL_DEFAULT_SENDER'] = 'victoralaegbu@gmail.com'  # Default sender (can be the same as username)
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_ASCII_ATTACHMENTS'] = False

mail = Mail(app) #initializing the mail class with app

db = SQLAlchemy(app) # create an instance of th SQLALCHEMY to access the database from here 
migrate = Migrate(app, db) # connects flask migrate to the app an SQLAlchemy
bcrypt = Bcrypt(app) #initializing the bcrypt



class Users(db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_uuid = db.Column(UUID(as_uuid=True), unique=True)
    firstname = db.Column(db.String(255), nullable=False)
    lastname = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(70), nullable=False, unique=True)
    password = db.Column(db.String(1000), nullable=True)
    is_confirmed = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    verify_code = db.Column(db.String(8), nullable=True)
    verify_code_expires = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    user_profile = db.relationship('Profile', backref="profile", uselist=False)

    # Relationship to user profile and OAuth accounts
    oauth_accounts = db.relationship('OAuthAccount', backref='oauth', lazy=True)

class Profile(db.Model):
    __tablename__ = "profile"
    profile_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id')) 
    company_name = db.Column(db.String(100), nullable=True)
    company_type = db.Column(db.String(50), nullable=True)
    company_size = db.Column(db.String(100), nullable=True)
    start_year = db.Column(db.String(50), nullable=True)
    annual_revenue = db.Column(db.String(50), nullable=True)
    company_role = db.Column(ARRAY(String))
    phone = db.Column(db.String(15), nullable=True)
    province = db.Column(db.String(50), nullable=True)
    country = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC')) 



class OAuthProvider(db.Model):
    __tablename__ = 'oauth_providers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)  # e.g., 'Google', 'Facebook'
    client_id = db.Column(db.String(100), nullable=True)
    client_secret = db.Column(db.String(100), nullable=False)
    redirect_uri = db.Column(db.String(200), nullable=False)

class OAuthAccount(db.Model):
    __tablename__ = 'oauth_accounts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('oauth_providers.id'), nullable=False)
    provider_user_id = db.Column(db.String(100), nullable=False)  # User ID from the OAuth provider
    access_token = db.Column(db.String(200))  # Optional: for making API calls
    refresh_token = db.Column(db.String(200))  # Optional: for refreshing access token

class PasswordTable(db.Model):
    __tablename__ = "passwordtable"
    pwd_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))   
    reset_token = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    expires_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))


class LoginTable(db.Model):
    __tablename__ = "logintable"
    login_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    auth_method = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    auth_method = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    user_agent = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    expires_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))


#Route for first registration
@app.route('/register')
def register(): # The hashed uuid value will be appended to the url link
    try:
        message = ""
        email = html.escape(data['email'])
        password = data["password"]
        if not is_valid_email(data['email']): #checking if email is in correct format
            return jsonify({"message": "Email is not in correct format"})
        else:
            #checking if email exists?
            user_email = Users.query.filter_by(email=email).first()
            if user_email:
                return jsonify({"exists": True, "is_verified":False, "message": "Account with email already exists"})
            
            firstname = html.escape(data['firstname'])
            lastname = html.escape(data['lastname'])
            #hash the password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            #creating a user uuid for identification
            new_user_uuid = uuid.uuid4()

            #convert the uuid to a string and encrypt
            encrypted_id = encode_id(str(new_user_uuid))

            #Instantiating an object of users
            new_user = Users(
                        user_uuid = new_user_uuid, 
                        firstname = firstname, 
                        lastname = lastname, 
                        email = email,
                        password = hashed_password, 
                        verify_code=verify_code, 
                        verify_code_expires=verify_code_expiration
                    )
            new_user.user_profile = Profile(user_id=Users.user_id)
            #message to send to the user
            mail_message = "Ur registration code is: " + verify_code
            

            #TODO persist info to the data
            db.session.add(new_user)
            db.session.commit()

            #TODO send mail to user
            msg = Message("Confirm Registration",
                  sender='victoralaegbu@gmail.com',
                  recipients=[email])  # Change to recipient's email
            msg.body = mail_message
            mail.send(msg)

            #TODO return a json object
            return jsonify({
                    "status": 200, 
                    "message": "Registration successful", 
                    "is_confirmed": False, 
                    "is_verified":False, 
                    "id": encrypted_id
                })
            
    except Exception as e:
        db.session.rollback()
        return str(e)
    finally:
        db.session.close()


@app.route('/verify_user/<id>')
def verify_user(id):
    try:
        message = ""
        #TODO collect verification code from form
        verify_data={
            "code": "wubswrhX"
        }
        #TODO decode the encrypted uuid and covert back to uuid format
        decoded_uuid = uuid.UUID(decode_id(id))

        #TODO get record of the user
        user = Users.query.filter(and_(Users.user_uuid == decoded_uuid, Users.verify_code == verify_data['code'])).first()
        if user:
            user.is_verified = True
            db.session.commit()
            message = jsonify({"status": "verified", "is_verified": True, "is_confirmed":False, "message": "verification successful"})
        else:
            message = jsonify({"status": "unverified", "is_verified": False, "is_confirmed":False, "message": "verification unsuccessful"})
        return message
    except Exception as e:
        db.session.rollback()
        return str(e)
    finally:
        db.session.close()

@app.route('/resend_code/<id>')
def resend_code(id):
    try:
        decoded_uuid = uuid.UUID(decode_id(id))
       
        #get record of the user
        user = Users.query.filter_by(user_uuid = decoded_uuid).first()
        if user:
            #TODO #specifically get the mail
            user_email = user.email

            #TODO generate a new code and new expiration time and assign them to their respective instances
            user.verify_code = verify_code
            user.verify_code_expires = verify_code_expiration

            # Commit the changes
            db.session.commit()

            #TODO send code to the email
            code_mail_message = "You requested for the confirmation code see it below <br>" + verify_code
            msg = Message("Confirm Registration",
            sender='victoralaegbu@gmail.com',
            recipients=[user_email])  # Change to recipient's email
            msg.body = code_mail_message
            mail.send(msg) 
            return jsonify({"status": 200, "message": "code re-sent to email"})
        else:
            return jsonify({"message": "An unexpected error occured"})

    except Exception as e:
        db.session.rollback()
        return str(e)
    finally:
        db.session.close()

@app.route('/confirm_user/<id>')
def confirm_user(id):
    try:
        #TODO confirm that the user is sending a POST REQUEST

        #TODO collect info from client and remove all htmlentities and make sure they are not empty
        company_name = html.escape(user_profile["company_name"])
        country = html.escape(user_profile["country"])
        company_type = html.escape(user_profile["company_type"])
        company_size = html.escape(user_profile["company_size"])
        start_year = html.escape(user_profile["start_year"])
        annual_revenue = html.escape(user_profile["annual_revenue"])
        company_role = html.escape(user_profile["company_role"])
        province = html.escape(user_profile["province"])
        phone = html.escape(user_profile["phone"])


        #TODO decode the uuid and assign to a variable
        decoded_uuid = uuid.UUID(decode_id(id))

        
        user_query = Users.query.filter_by(user_uuid = decoded_uuid).first()

        #TODO collect and assign user's id and email
        user_id = user_query.user_id
        user_email = user_query.email

        #TODO send data to the database
        user_query.is_confirmed = True #updating is_confirmed column

        user_query.user_profile = Profile(
                company_name=company_name,
                company_type=company_type,
                company_size=company_size,
                start_year=start_year,
                annual_revenue=annual_revenue,
                company_role=company_role,
                phone=phone,
                province=province
        )

        db.session.commit()
        #TODO send confirmation email to the user
        message = "Congratulations your account has been confirmed"
        msg = Message("Registration COnfirmation",
        sender='victoralaegbu@gmail.com',
        recipients=[user_email])  # Change to recipient's email
        msg.body = message
        mail.send(msg) 
        return jsonify({
            "is_confirmed": True
        })
    except Exception as e:
        db.session.rollback()
        return str(e)
    finally:
        db.session.close()
@app.route('/')
def index():
    return Users.__table__.columns.keys()
