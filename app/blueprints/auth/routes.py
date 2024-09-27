from flask import Blueprint, request, jsonify, abort
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from ...functions import encode_id, decode_id
from ...models import Users, Profile
from ...config import Config
from ... import bcrypt

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


                #TODO create a JWT token ==> On the jwt token i will add the verification and confirmation status to the client
                access_token = create_access_token(
                    identity=id,
                    additional_claims={
                        "is_confirmed": user.is_confirmed,
                        "is_verified" : user.is_verified
                    }
                )
                return jsonify({"access_token":access_token})
        
    except Exception as e:
        return str(e)
