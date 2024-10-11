from flask import Blueprint, request, jsonify, abort, session, make_response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from datetime import timedelta
from ...functions import encode_id, decode_id, get_token_auth_header, generate_reset_token, validate_reset_token, is_json
from ...models import Users, Profile
from ...config import Config
from ... import bcrypt, db, mail
import uuid
import jwt
import html
import secrets
import datetime

auth_bp = Blueprint('auth', __name__)

@auth_bp.before_request
def before_request():
    session.permanent = True
    auth_bp.permanent_session_lifetime = datetime.timedelta(hours=12) # session will be alive for 20 minutes

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        #TODO get email and password from
        data = request.get_json()
        if not is_json(data):
            abort(415)
        if 'email' not in data or 'password' not in data:
            abort(422)
        email = request.json.get('email')
        password = request.json.get('password')

        #TODO perform rate limiting

        #TODO compare email and password if they are great
        #TODO checked if user exits
        user = Users.query.filter_by(email=email).first()
        if not user:
            return jsonify({
                "status" : False,
                "message" : "wrong email or password"
            })
            #checked if there is a password match
        if not (password and bcrypt.check_password_hash(user.password, password)):
            return jsonify({
                "status" : False,
                "message" : "wrong email or password"
            })
        #TODO collected the uuid of the user encode it and use as the identity of the user in the JWT
        id = encode_id(str(user.user_uuid))
        
        if user.is_verified == True:                 
            #TODO create a JWT token ==> On the jwt token i will add the verification and confirmation status to the client
            access_token = create_access_token(
                identity=id,
                expires_delta=timedelta(minutes=600),
                additional_claims=({"is_confirmed": user.is_confirmed})
            )
            #TODO create a crsf token and set it as a coookie
            csrf_token = secrets.token_hex(16)
            response = jsonify({
                    "status": True,
                    "is_verified": user.is_verified,
                    "is_confirmed": user.is_confirmed
                })
            #Set access_token as an HttpOnly cookie
            response.set_cookie(
                'access_token',
                access_token,
                httponly=True,  # Prevents JavaScript access
                secure=True,    # Use True if using HTTPS
                samesite='None' # Change based on your requirements
            )

            #Set CSRF token as a non-HttpOnly cookie
            response.set_cookie('csrf_token', access_token, httponly=False)

            #creating session for user once verification is true                        
            session["user_uuid"] = id

            #checking if the user is confirmed 
            if user.is_confirmed == True:     
                result = (db.session.query(Users, Profile)
                            .join(Profile, Users.user_id == Profile.user_id)  # Join on user_id
                            .filter(Users.user_uuid == id)  # Filter based on user_uuid
                            .one_or_none()
                        )
                session["user_role"] = result.role
                response =  jsonify({
                    "status": True,
                    "is_verified": user.is_verified,
                    "is_confirmed": user.is_confirmed,
                    "user_role" : result.company_role,
                    "company_name": result.company_name,
                    "company_type" : result.company_type,
                    "company_size" : result.company_size,
                    "start_year": result.start_year,
                    "province" : result.province
                })

            return response, 200
                        
    except Exception as e:
        raise

@auth_bp.route('/logout', methods=['POST'])
def logout():
    #session.clear()
    return jsonify({"message": "logged out"})

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
            msg = Message("Password Reset",
                sender='victoralaegbu@gmail.com',
                recipients=[client_user['email']])  # Change to recipient's email
            msg.body = mail_message
            mail.send(msg)

            return ({"status":True, "message": "link sent successfully"}), 200
        else:
            return jsonify({"status":False, "message": "User does not exit"})
               
    except Exception as e:
        raise
    finally:
        pass


@auth_bp.route('/password_reset', methods=['POST'])
def password_reset():
    try:
        #TODO Get the reset_token via http header from client
        user = request.get_json()
        if "token" not in user or "password" not in user:
            abort(422)
        token = user['token']
        password = user["password"]

        #TODO validate token
        validate_response = validate_reset_token(token).get_json()
        if "id" in validate_response:
            
            #decode the encoded uuid and convert it back to a UUID
            user_uuid = uuid.UUID(decode_id(validate_response["id"]))

            user = Users.query.filter_by(user_uuid=user_uuid).first()

            #encrypt the password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            #update the user's passwor
            user.password=hashed_password
            db.session.commit()
            return jsonify({"status": True, "message": "password changed successfully"})
        else:     
            return validate_reset_token(token)
    except Exception as e:
        db.session.rollback()
        raise
    finally:
        db.session.close() 

@auth_bp.route('/auth_access', methods=['POST'])
@jwt_required()
def auth_access():
    try:
        #TODO Get the CSRF token from the request
        csrf_token_in_cookie = request.cookies.get('csrf_token')
        csrf_token_in_header = request.headers.get('X-CSRF-TOKEN')

        if not csrf_token_in_header or csrf_token_in_header != csrf_token_in_cookie:
            abort(403)
        #TODO get the jwt token from the header and extract
        id = uuid.UUID(decode_id(get_jwt_identity()))
        result = (
        db.session.query(Users, Profile)
            .join(Profile, Users.user_id == Profile.user_id)  # Join on user_id
            .filter(Users.user_uuid == id)  # Filter based on user_uuid
            .one_or_none()
        )
        return jsonify(result)
    except Exception as e:
        return str(e)
    
    return result


@auth_bp.route('/confirmation', methods=["POST"])
@jwt_required()
def confirmation():
        try:
            #TODO Get the access token from the request
            csrf_token_in_cookie = request.cookies.get('access_token')

            #TODO Get the CSRF token from the request
            csrf_token_in_header = request.headers.get('X-CSRF-TOKEN')

            #TODO get the jwt token from the header and extract
            id = decode_id(get_jwt_identity())

            session_id = str(uuid.UUID(decode_id(session["user_uuid"])))
                  
            
            if not csrf_token_in_header or csrf_token_in_header != csrf_token_in_cookie:
                abort(403)
            
            #making sure that jwt identity and session identity is same
            if not session_id == id:
                abort(404)
            
            
            user_profile = request.get_json()
            
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


            #TODO converting id to proper uuid and assign to a variable
            decoded_uuid = uuid.UUID(id)

            
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
            msg = Message("Registration onfirmation",
            sender='victoralaegbu@gmail.com',
            recipients=[user_email])  # Change to recipient's email
            msg.body = message
            mail.send(msg) 
            return jsonify({
                "is_confirmed": True,
                "message" : "user confirmed successfully"
            })
        except Exception as e:
            db.session.rollback()
            raise
        finally:
            db.session.close()
