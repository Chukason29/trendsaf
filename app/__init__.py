from .functions import is_valid_email, verify_code, verify_code_expiration
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy import Column, Integer, String, and_
from flask_migrate import Migrate
from flask import Flask
from flask_cors import CORS, cross_origin
from flask_mail import Mail, Message
from sqlalchemy.dialects.postgresql import UUID
from .data import data, user_profile
from dotenv import load_dotenv
from datetime import datetime
from .config import Config #collecting the Config class from config.py to configure the app

# Load environment variables from .env
load_dotenv()

# Extensions
db = SQLAlchemy()
migrate = Migrate()
mail = Mail()
bcrypt = Bcrypt()
cors = CORS()

def create_app(config_class=Config):
    
    #Application factory fro creating app
    app = Flask(__name__) # creates a flask app and sends store in an instance app
    
    

    #Configure app
    app.config.from_object(config_class)
    app.config.get(Config.SQLALCHEMY_DATABASE_URI)
    app.config.get(Config.SQLALCHEMY_TRACK_MODIFICATIONS)

     # Initialize extensions with the app
    db.init_app(app)#create an instance of th SQLALCHEMY to access the database from here
    migrate.init_app(app, db) # connects flask migrate to the app an SQLAlchemy
    mail.init_app(app) #initializing the mail class with app
    bcrypt.init_app(app)
    cors.init_app(app, resources=
                  {
                      r"/auth/*": {
                          "origins": "https://trendsaf.co",
                          "methods": ["POST", "GET", "PUT", "PATCH"],
                          "allow_headers": ["Content-Type", "Authorization"], 
                          "expose_headers": ["Authorization"],
                          "supports_credentials": True,
                        },
                        r"/signup/*": {
                          "origins": "https://trendsaf.co",
                          "methods": ["POST", "GET", "PUT", "PATCH"],
                          "allow_headers": ["Content-Type", "Authorization"], 
                          "expose_headers": ["Authorization"],
                          "supports_credentials": True,
                        }
                   })


    # Register blueprints

    #authentication/login blueprint
    from .blueprints.auth.routes import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    #registration, verification and confirmation blueprint
    from .blueprints.signup.routes import signup_bp
    app.register_blueprint(signup_bp, url_prefix='/signup')

    # Register error handlers
    register_error_handlers(app)

    return app


#Handling errors
def register_error_handlers(app):
    """Register custom error pages for common HTTP errors."""
    @app.errorhandler(404)
    def not_found_error(error):
        return {"message": "Resource not found"}, 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()  # If using a database, rollback on error
        return {"message": "Internal server error"}, 500