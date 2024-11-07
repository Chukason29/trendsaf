from flask import Blueprint, request, jsonify, abort
from sqlalchemy import Column, Integer, String, and_, desc, asc
from ...models import Users, Crops, Countries, Regions, CropCategories
from ...config import Config
import html
import json

general_bp = Blueprint('general_routes', __name__)
@general_bp.route('/crops', methods = ['POST', 'GET'])
def get_crops():
    crops = Crops.query.order_by(asc(Crops.crop_name)).all()
    all_crops = [{"id": crop.crop_id, "name": crop.crop_name} for crop in crops]
    return jsonify(all_crops)

@general_bp.route('/cropcategories', methods = ['POST', 'GET'])
def get_cropcategories():
    crop = request.get_json()
    #TODO check is certain params are missing
    if "crop_id" not in crop:
        abort(422)
    crop_id = crop['crop_id']
    cropCategories = CropCategories.query.filter_by(crop_id=crop_id).all()
    all_crops = [
        {
            "id": cropCategory.crop_categories_id, 
            "variety": cropCategory.crop_variety, 
            "code":cropCategory.crop_code
        } for cropCategory in cropCategories]
    return jsonify(all_crops)

@general_bp.route('/countries', methods = ['POST', 'GET'])
def get_countries():
    countries = Countries.query.all()
    all_countries = [{"id": country.country_id, "name": country.country_name, "code": country.country_code } for country in countries]
    return jsonify(all_countries)


@general_bp.route('/regions', methods = ['POST', 'GET'])
def get_regions():
    #TODO get the country of the region needed
    country = request.get_json()
    
    #TODO check is certain params are missing
    if 'country_name' not in country or "country_id" not in country:
        abort(422)
    country_id = country['country_id']
    #TODO query the regions table based on the id sent
    regions = Regions.query.filter_by(country_id = country_id).all()
    allregions = [{"region_name" : region.region_name, "region_id" : region.region_id,} for region in regions]
    return jsonify(allregions)
