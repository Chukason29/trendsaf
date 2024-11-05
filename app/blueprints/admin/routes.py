from flask import Blueprint, request, jsonify, abort, session, make_response, url_for, redirect
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from sqlalchemy import Column, Integer, String, and_
from datetime import timedelta
from ...functions import encode_id, decode_id, get_token_auth_header, generate_reset_token, validate_reset_token, is_json, generate_verification_link,generate_password_link, validate_password_link
from ...models import Users, Profile, Tokens
from ...config import Config
from ... import bcrypt, db, mail
import uuid
import jwt
import html
import secrets
import datetime
import json

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/addcrop', methods=['POST'])
def addcrop():
    try:
        #TODO get crop_name from request
        data = request.get_json()
        if not is_json(data):
            abort(415)
        if 'crop_name' not in data:
            abort(422)
        crop_name = request.json.get('crop_name')
        is_crop_exists= Users.query.filter_by(crop_name = crop_name).first()
        if is_crop_exists :
            return jsonify({
                "status": False,
                "message" : "Crop name already exists"
            })
        new_crop = Users(crop_name = crop_name)
        db.session.add(new_crop)
        db.session.commit()  
    except:
        db.session.rollback()
        raise
    
