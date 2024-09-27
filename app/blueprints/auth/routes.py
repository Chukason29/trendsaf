from flask import Blueprint, request, jsonify, abort
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

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

        #TODO check if user if verified, if not send to verification page

        #TODO check if the user is confirmed if not send to profile update page



        #TODO create and sign a jwt token
        access_token = create_access_token(identity=email)
        return jsonify({"access_token":access_token})
    except Exception as e:
        return str(e)
