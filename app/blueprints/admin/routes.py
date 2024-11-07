from flask import Blueprint, request, jsonify, abort, session, make_response, url_for, redirect
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from flask_mail import Mail, Message
from sqlalchemy import Column, Integer, String, and_
from datetime import timedelta
from ...functions import encode_id, decode_id, get_token_auth_header, generate_reset_token, validate_reset_token, is_json, generate_verification_link,generate_password_link, validate_password_link
from ...models import Users, Profile, Tokens, Crops, Countries, Regions
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
@jwt_required()
def addcrop():
    try:
        #TODOGetting the user's id
        id = uuid.UUID(decode_id(get_jwt_identity()))
  
        #Retrieve authorization token
        auth_token = request.headers.get("Authorization").split(" ")[1]
        user_data = decode_token(auth_token, allow_expired=False)
        
        user_query = Users.query.filter_by(user_uuid = id).first()
        
        if user_query and user_data['user_role'] == "Z":
            data = request.get_json()
            if not is_json(data):
                abort(415)
            if 'crop_name' not in data:
                abort(422)
            crop_name = request.json.get('crop_name')
            is_crop_exists= Crops.query.filter_by(crop_name = crop_name).first()
            if is_crop_exists :
                return jsonify({
                    "status": False,
                    "message" : "Crop name already exists"
                })
            new_crop = Crops(crop_name = crop_name)
            db.session.add(new_crop)
            db.session.commit()
            
            return jsonify({
                "status": True,
                "message": "New crop added"
            })
        else:
            return jsonify({
                "status": False,
                "message" : "Unauthorized access"
            })
    except:
        db.session.rollback()
        raise
    

@admin_bp.route('/addcountry', methods=['POST'])
@jwt_required()
def addcountry():
    try:
        id = uuid.UUID(decode_id(get_jwt_identity()))
        #Retrieve authorization token
        auth_token = request.headers.get("Authorization").split(" ")[1]
        user_data = decode_token(auth_token, allow_expired=False)
        user_query = Users.query.filter_by(user_uuid = id).first()
        if user_query and user_data['company_role'] == "Z":
            data = request.get_json()
            if not is_json(data):
                abort(415)
            if 'country_name' not in data or 'country_code' not in data:
                abort(422)
            country_name = request.json.get('country_name')
            country_code = request.json.get('country_code')
            is_country_exists= Countries.query.filter_by(country_name = country_name).first()
            if is_country_exists :
                return jsonify({
                    "status": False,
                    "message" : "Country name already exists"
                })
            new_country = Countries(country_name = country_name, country_code = country_code)
            db.session.add(new_country)
            db.session.commit()
            
            return jsonify({
                "status": True,
                "message": "New country added"
            })
        else:
            abort(403)
    except:
        db.session.rollback()
        raise
    

@admin_bp.route('/addregion', methods=['POST'])
@jwt_required()
def addregion():
    try:
        id = uuid.UUID(decode_id(get_jwt_identity()))
        #Retrieve authorization token
        auth_token = request.headers.get("Authorization").split(" ")[1]
        user_data = decode_token(auth_token, allow_expired=False)
        
        
        user_query = Users.query.filter_by(user_uuid = id).first()
        if user_query and user_data['company_role'] == "Z":
            data = request.get_json()
            
            country = request.get_json()
            if not is_json(country):
                abort(415)
            if 'region_name' not in country or 'country_name' not in country or 'country_id' not in country:
                abort(422)
            region_name = request.json.get('region_name')
            country_name = request.json.get('country_name')
            country_id = request.json.get('country_id')
            new_region = Regions(region_name = region_name, country_id = country_id)
            db.session.add(new_region)
            db.session.commit()
            
            return jsonify({
                "status": True,
                "message": "New region added"
            })
        else:
            abort(403)
    except:
        db.session.rollback()
        raise
    
