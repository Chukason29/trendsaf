from flask import Blueprint, request, jsonify
from ...models import Users, Profile
from ...config import Config
from ... import db
from ... import bcrypt
from ... import mail
from itsdangerous import URLSafeSerializer
from sqlalchemy import Column, Integer, String, and_
from flask_mail import Mail, Message
import re
import random
import string
import pendulum
import uuid
import base64
import os
import hashlib
import html


signup_bp = Blueprint('signup', __name__)

serializer = URLSafeSerializer(Config.AES_KEY)
def encode_id(id):
    return serializer.dumps(id)

# Function to decode the ID
def decode_id(encoded_id):
    return serializer.loads(encoded_id)

@signup_bp.route('/register', methods=["POST"])
def register(): # The hashed uuid value will be appended to the url link
    try:
        data = {
            "firstname" : "Tolu",
            "lastname" : "Alaegbu",
            "email" : "ebuka@waowx.com",
            "password" : "010101012203"
        }
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


@signup_bp.route('/verification/<id>')
def verification(id):
    try:
        message = ""
        #TODO collect verification code from form
        verify_data={
            "code": "VZ5f8u5Y"
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

@signup_bp.route('/code_resend/<id>')
def code_resend(id):
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
            msg = Message(
                "Confirm Registration",
                sender='victoralaegbu@gmail.com',
                recipients=[user_email]
            )  # Change to recipient's email
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

@signup_bp.route('/confirmation/<id>')
def confirmation(id):
    try:
        #TODO confirm that the user is sending a POST REQUEST
        user_profile = {
            "company_name" : "Tolu and sons",
            "company_type": "Suppliers",
            "company_size": "A",
            "start_year": "1984",
            "annual_revenue": "C",
            "company_role": "B",
            "phone": "+234907876356",
            "province": "Ngalo",
            "country": "Rwanda",
        }
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
@signup_bp.route('/')
def index():
    return "Hello World"


def is_valid_email(email):
    # Define the regular expression for validating an email
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    
    # Use re.match to check if the string matches the email pattern
    if re.match(email_regex, email):
        return True
    return False


#function to generate random code for registration and password resetting
def generate_random_code(length):
    # Combine letters and digits
    characters = string.ascii_letters + string.digits
    # Generate a random code
    return ''.join(random.choices(characters, k=length))

#Generate a random alphanumeric code of length 8
verify_code = generate_random_code(8)


#this function collects a time and adds a duration it
def time_duration(previous_time, added_duration):
    pass


def add_duration(hours):
    # Get the current time using Pendulum
    current_time = pendulum.now()
    
    # Add the specified duration (in days)
    new_time = current_time.add(hours=hours)
    return new_time

# A 24 hour expiration time for registration code
verify_code_expiration = add_duration(24)
