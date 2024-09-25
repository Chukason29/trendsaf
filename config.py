import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.environ.get('SECRET_KEY')
DEBUG = os.environ.get('DEBUG')
AES_KEY = os.environ.get("AES_KEY")
if DEBUG == "True":
    DEBUG = 1
elif DEBUG == "False":
    DEBUG = 0
SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')

SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')

if SQLALCHEMY_TRACK_MODIFICATIONS == "True":
    SQLALCHEMY_TRACK_MODIFICATIONS = 1
elif SQLALCHEMY_TRACK_MODIFICATIONS == "False" :
    SQLALCHEMY_TRACK_MODIFICATIONS = 0

