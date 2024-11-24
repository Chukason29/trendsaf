from flask import Blueprint, request, jsonify, abort, session, make_response, url_for, redirect
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from flask_mail import Mail, Message
from sqlalchemy import Column, Integer, String, and_
from sqlalchemy.orm import joinedload
from datetime import timedelta
from ...functions import encode_id, decode_id, get_token_auth_header, generate_reset_token, validate_reset_token, is_json, generate_verification_link,generate_password_link, validate_password_link
from ...models import Users, Profile, Tokens, Crops, Countries, Regions, CropCategories, CropVariety, Product
from ...config import Config
from ... import bcrypt, db, mail
from datetime import date
import uuid
import jwt
import html
import secrets
import datetime
import json
import pendulum

user_bp = Blueprint('user', __name__)
@user_bp.route('/crops/prices',  methods=['POST'])
@jwt_required()
def crop_prices():
    try:
        #TODOGetting the user's id
        id = uuid.UUID(decode_id(get_jwt_identity()))

        #Retrieve authorization token
        auth_token = request.headers.get("Authorization").split(" ")[1]
        user_data = decode_token(auth_token, allow_expired=False)
        
        user_query = Users.query.filter_by(user_uuid = id).first()

        #Getting request body
        data = request.get_json()
        if not is_json(data):
            abort(415)
            
        if 'crop_variety_id' not in data or 'country_id' not in data or 'duration' not in data:
            abort(422)
            
        #TODO get the values of crop_variety_id and country_id
        crop_variety_id = data['crop_variety_id']
        country_id = data['country_id']
        duration = data['duration']
        
        #TODO get today's date using python
        now = pendulum.now()
        current_week_start = now.start_of("week")
        previous_week_start = current_week_start.subtract(weeks=1)
                
        
        return jsonify({
            "current_week" : current_week_start,
            "previous_week": previous_week_start
        })
        #TODO get average price for the previous week or month
        
        #TODO get average price for the current week or month
        
        #TODO
        
        
    except:
        db.session.rollback()
        raise

