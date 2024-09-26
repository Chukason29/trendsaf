from flask import Blueprint, request, jsonify

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET'])
def login():
    # Authentication logic here
    return jsonify({"message": "Logged in"}), 200
