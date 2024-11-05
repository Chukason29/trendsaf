from flask import Blueprint, request, jsonify, abort
from sqlalchemy import Column, Integer, String, and_, desc, asc
from ...models import Users, Crops, Countries
from ...config import Config
import html
import json

general_bp = Blueprint('general_routes', __name__)
@general_bp.route('/get_crops', methods = ['POST', 'GET'])
def get_crops():
    crops = Crops.query.order_by(asc(Crops.crop_name)).all()
    all_crops = [{"id": crop.crop_id, "name": crop.crop_name} for crop in crops]
    return jsonify(all_crops)

@general_bp.route('/get_countries', methods = ['POST', 'GET'])
def get_countries():
    countries = Countries.query.all()
    all_countries = [{"id": country.country_id, "name": country.country_name, "code": country.country_code } for country in countries]
    return jsonify(all_countries)
