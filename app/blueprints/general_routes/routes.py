from flask import Blueprint, request, jsonify, abort
from sqlalchemy import Column, Integer, String, and_, desc, asc
from ...models import Users, Crops, Countries, Regions, CropCategories, CropVariety
from ...config import Config
import html
import json

general_bp = Blueprint('general_routes', __name__)
@general_bp.route('/cropcategories', methods = ['POST', 'GET'])
def get_cropcategories():
    crop_categories = CropCategories.query.all()
    all_crops = [{"id": crop_category.crop_category_id} for crop_category in crop_categories]
    return jsonify(all_crops)

@general_bp.route('/crops', methods = ['POST', 'GET'])
def get_crops():
    crop = request.get_json()
    #TODO check is certain params are missing
    if "crop_category_id" not in crop:
        abort(422)
    crop_category_id = crop['crop_category_id']
    crops = Crops.query.filter_by(crop_category_id=crop_category_id).all()
    all_crops = [
        {
            "id": crop.crop_id, 
            "name":crop.crop_name
        } for crop in crops]
    return jsonify(all_crops)


@general_bp.route('/crops/varieties', methods = ['POST', 'GET'])
def get_varieties():
    crop = request.get_json()
    #TODO check is certain params are missing
    if "crop_id" not in crop:
        abort(422)
    crop_id = crop['crop_id']
    crops = CropVariety.query.filter_by(crop_id=crop_id).all()
    all_crops = [
        {
            "id": crop.crop_variety_id, 
            "name":crop.crop_variety_name
        } for crop in crops]
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
