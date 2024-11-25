from flask import Blueprint, request, jsonify, abort, session, make_response, url_for, redirect
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from flask_mail import Mail, Message
from sqlalchemy import Column, Integer, String, and_, func
from sqlalchemy.orm import joinedload
from datetime import timedelta
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
            
        if 'crop_variety_id' not in data or 'country_id' not in data or 'duration' not in data:
            abort(422)
            
        #TODO get the values of crop_variety_id and country_id
        crop_variety_id = data['crop_variety_id']
        country_id = data['country_id']
        duration = data['duration']
        
        #TODO get today's date using python
        now = pendulum.now()
        
        if duration == "week":   
            current_duration = now.start_of("week").subtract(days=1)
            previous_duration = current_duration.subtract(weeks=1)
        elif duration == "month":   
            current_duration = now.start_of("month")
            previous_duration = current_duration.subtract(months=1)
                
        
        
        #TODO get average price for the current week or month
        current_week_data = (
            db.session.query(
                CropVariety.crop_variety_name.label("crop_variety_name"),
                func.avg(Product.price).label("avg_price")
            )
            .join(CropVariety, Product.crop_variety_id == CropVariety.crop_variety_id)
            .filter(Product.created_at >= current_duration, 
                    Product.country_id == country_id, 
                    Product.crop_variety_id == crop_variety_id
            )
            .group_by(CropVariety.crop_variety_name)
            .all()
        )
        
        #TODO get average price for the current week or month
        previous_week_data = (
        db.session.query(
                CropVariety.crop_variety_name.label("crop_variety_name"),
                func.avg(Product.price).label("avg_price")
            )
            .join(CropVariety, Product.crop_variety_id == CropVariety.crop_variety_id)
            .filter(
                Product.created_at >= previous_duration,
                Product.created_at < current_duration,
                Product.country_id == country_id, 
                Product.crop_variety_id == crop_variety_id
            )
            .group_by(CropVariety.crop_variety_name)
            .all()
        )
        # Step 3.4: Convert results to DataFrames for easy processing
        current_df = pd.DataFrame(current_week_data, columns=["crop_variety_name", "avg_price"])
        previous_df = pd.DataFrame(previous_week_data, columns=["crop_variety_name", "avg_price"])

        # Merge dataframes to calculate week-on-week changes
        merged_df = pd.merge(
            current_df,
            previous_df,
            on="crop_variety_name",
            how="outer",
            suffixes=("_current", "_previous")
        )

        # Step 3.5: Calculate week-on-week percentage change
        merged_df["week_on_week_change"] = (
            (merged_df["avg_price_current"] - merged_df["avg_price_previous"])
            / merged_df["avg_price_previous"]
        ) * 100

        # Replace NaN values for cleaner output
        merged_df.fillna({"avg_price_current": 0, "avg_price_previous": 0, "week_on_week_change": 0}, inplace=True)

        # Step 3.6: Convert results to JSON
        result_json = merged_df.to_json(orient="records")
        #TODO
        return result_json
        
    except:
        db.session.rollback()
        raise
