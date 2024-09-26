import re
import random
import string
import pendulum
import uuid
import base64
import os
import hashlib




data = {
            "firstname" : "Victor",
            "surname" : "Polycarp",
            "email" : "chuksalaegbu@gmail.com",
            "phone": "09039444542",
            "role": ["aggregator"],
            "password": "54321",
            "street_name": "LordBridge",
            "city": "Lome",
            "zip": "500016",
            "province": "Kaduna",
            "country": "India"
        }
def is_valid_email(email):
    # Define the regular expression for validating an email
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    
    # Use re.match to check if the string matches the email pattern
    if re.match(email_regex, email):
        return True
    return False


#function to generate random code for registration and password resetting
def generate_random_code(length):
    # Combine letters and digits
    characters = string.ascii_letters + string.digits
    # Generate a random code
    return ''.join(random.choices(characters, k=length))

#Generate a random alphanumeric code of length 8
verify_code = generate_random_code(8)


#this function collects a time and adds a duration it
def time_duration(previous_time, added_duration):
    pass


def add_duration(hours):
    # Get the current time using Pendulum
    current_time = pendulum.now()
    
    # Add the specified duration (in days)
    new_time = current_time.add(hours=hours)
    return new_time

# A 24 hour expiration time for registration code
verify_code_expiration = add_duration(24)


# Function to hash the ID using SHA256
def encode_id(id):
    return base64.urlsafe_b64encode(hashlib.sha256(str(id).encode()).digest()).decode('utf-8')