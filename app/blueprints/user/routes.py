from flask import Blueprint, request, jsonify, abort, session, make_response, url_for, redirect
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from flask_mail import Mail, Message
from sqlalchemy import Column, Integer, String, and_, func
from sqlalchemy.orm import joinedload
from datetime import timedelta, datetime
from ...functions import encode_id, decode_id, get_token_auth_header, generate_reset_token, validate_reset_token, is_json, generate_verification_link,generate_password_link, validate_password_link
from ...models import Users, Profile, Tokens, Crops, Countries, Regions, CropCategories, CropVariety, Product
from ...config import Config
from ... import bcrypt, db, mail
from datetime import date
import pandas as pd
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
            
        if 'crop_code' not in data or 'country_code' not in data or 'duration' not in data:
            abort(422)
            
        #TODO get the values of crop_variety_id and country_id
        crop_code = data['crop_code']
        #crop_variety_code = data['crop_variety_code']
        country_code = data['country_code']
        duration = data['duration']
        #TODO get today's date using python
        now = pendulum.now()
        date_format = "%a, %d %b %Y %H:%M:%S"
        if duration == "week":   
            current_duration =now.start_of("week").subtract(days=1) 
            previous_duration =current_duration.subtract(weeks=1)
            
                       
            '''current_duration = current_duration.strftime("%a, %d %b %Y %H:%M:%S")
            current_duration = datetime.datetime.strptime(current_duration, date_format)
            current_duration = int(current_duration.timestamp())
            
            previous_duration = previous_duration.strftime("%a, %d %b %Y %H:%M:%S")
            previous_duration = datetime.datetime.strptime(previous_duration, date_format)
            previous_duration = int(previous_duration.timestamp())'''
            
            
        elif duration == "month":
            current_duration = now.start_of("month")
            previous_duration = current_duration.subtract(months=1)
                
        result = db.session.query(
            CropVariety.variety_code.label('variety_code'),
            CropVariety.variety_name.label('variety_name'),
            Product.price.label('price'),
            Product.unit.label('unit'),
            Product.created_at.label('created_at'),
            Regions.region_name.label('region'),
        ).join(
            Product, CropVariety.variety_code == Product.variety_code
        ).join(
            Regions, Regions.region_code == Product.region_code  # Fix here
        ).filter (and_(
            Product.country_code == country_code, Product.created_at.between(previous_duration, now)
        )).group_by(
            CropVariety.variety_code, CropVariety.variety_name, Product.price, Product.unit, Product.created_at, Regions.region_name  # Fix group_by to match SELECT columns
        )


        result_json = [
        {
            "variety_code": row.variety_code,
            "variety_name": row.variety_name,
            "region" : row.region,
            "unit" : row.unit,
            "price": row.price,
            "price-change": 0,
            "created_at" : row.created_at
        }
        for row in result
        ]
        
        def convert_rfc1123_to_datetime(date_str):
            return datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S GMT")
        
        def filter_by_date_range(data, start_date_str, end_date_str):
            start_date = convert_rfc1123_to_datetime(start_date_str)
            end_date = convert_rfc1123_to_datetime(end_date_str)
            
            # Filter the list based on the 'created_at' field
            filtered_data = [
                item for item in data
                if start_date <= convert_rfc1123_to_datetime(item["created_at"]) <= end_date
            ]
    
            return filtered_data
        
        return jsonify(result_json)  
        
    except:
        db.session.rollback()
        raise


@user_bp.route('/crops/chart',  methods=['POST'])
@jwt_required()
def crop_chart():
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
            
        if 'crop_id' not in data or 'crop_variety_id' not in data or 'country_id' not in data or 'duration' not in data:
            abort(422)
            
        #TODO get the values of crop_variety_id and country_id
        crop_id = data['crop_id']
        crop_variety_id = data['crop_variety_id']
        country_id = data['country_id']
        duration = data['duration']
        
        #.filter(Product.created_at.between(current_duration, now)) \
        #TODO get today's date using python
        now = pendulum.now()
        
        if duration == "week":   
            current_duration = now.start_of("week").subtract(days=1)
            previous_duration = current_duration.subtract(weeks=1)
            
        elif duration == "month":   
            current_duration = now.start_of("month")
            previous_duration = current_duration.subtract(months=1)
                
        result = db.session.query(
            Product.price.label('price'),
            Product.created_at.label('date'),

        ).join(Product, CropVariety.crop_variety_id == Product.crop_variety_id) \
        .filter(Product.crop_id == crop_id) \
        .filter(Product.country_id == country_id) \
        .filter(Product.crop_variety_id == crop_variety_id) \
        .filter(Product.created_at >= current_duration) \
        .all()

        result_json = [
        {
            "x": row.price,
            "y": row.date,
        }
        for row in result
        ]
    
        return jsonify(result_json)
    except:
        db.session.rollback()
        raise

@user_bp.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-CSRF-TOKEN"
    return response