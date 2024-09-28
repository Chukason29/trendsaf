from flask import Blueprint, request, jsonify, abort, session
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from datetime import timedelta
from ...functions import encode_id, decode_id, get_token_auth_header, generate_reset_token
from ...models import Users, Profile
from ...config import Config
from ... import bcrypt, db, mail
import uuid
import jwt

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        #TODO get email and password from
        data = request.get_json()
        if 'email' not in data or 'password' not in data:
            abort(422)
        email = request.json.get('email')
        password = request.json.get('password')

        #TODO perform rate limiting

        #TODO compare email and password if they are great
        #TODO checked if user exits
        user = Users.query.filter_by(email=email).first()
        if user:
            #checked if there is a password match
            if password and bcrypt.check_password_hash(user.password, password):
                #TODO collected the uuid of the user encode it and use as the identity of the user in the JWT
                id = encode_id(str(user.user_uuid))
                if user.is_verified == True:
                    #TODO create a JWT token ==> On the jwt token i will add the verification and confirmation status to the client
                    access_token = create_access_token(
                        identity=id,
                        additional_claims={
                            "is_confirmed": user.is_confirmed,
                            "is_verified" : user.is_verified,
                        },
                        expires_delta=timedelta(minutes=720)
                    )
               
                    return jsonify({"access_token":access_token})
                else:
                    return jsonify({"id": id})
            return jsonify({"message": "wrong email or password"})
        else:
            return jsonify({"message": "wrong email or password"})      
    except Exception as e:
        return str(e)


@auth_bp.route('/password_reset_request', methods=['POST'])
def password_reset_request():
    try:
        #TODO get email from client
        client_user = request.get_json()
        if "email" not in client_user:
            abort(422)
        

        #TODO query the db to get uuid for the user with email
        user = Users.query.filter(client_user['email'] == Users.email).one_or_none()
        if user:
            id = user.user_uuid

            #TODO generate token 
            
            
            #TODO send token to the user's email
            reser_url = f"https://trendsaf.co/reset-password?token={generate_reset_token(user)}"
            mail_message = "Ur password reset link: " + reser_url
            msg = Message("Confirm Registration",
                sender='victoralaegbu@gmail.com',
                recipients=[client_user['email']])  # Change to recipient's email
            msg.body = mail_message
            mail.send(msg)

            return generate_reset_token(user)

        
    except Exception as e:
        raise
    finally:
        pass

@auth_bp.route('/auth_access', methods=['POST'])
@jwt_required()
def auth_access():
    try:
        id = uuid.UUID(decode_id(get_jwt_identity()))
        result = (
        db.session.query(Users, Profile)
            .join(Profile, Users.user_id == Profile.user_id)  # Join on user_id
            .filter(Users.user_uuid == id)  # Filter based on user_uuid
            .one_or_none()
        )
    except Exception as e:
        return str(e)
    
    return result

