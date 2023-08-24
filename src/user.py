"""
Functions for user registration and login handling.
"""

import json
import pwinput

from utilities import get_email, get_password
from security import (hash, check_hashed_string, generate_keys, encrypt_file,
                      decrypt_file, create_certificate)

USER_INFO_FILE = "user_information.json"
MAX_LOGIN_ATTEMPTS = 3


def register_user():
    """
    Register a new user for the SecureDrop application on this client.

    :return: None
    """
    # Request user's full name and validate email address.
    full_name = input("Enter Full Name: ")
    email_address = get_email("Enter Email Address: ")

    # Request user's password.
    password = get_password()

    # Hash the users password.
    password = hash(password)

    # Format user information into JSON format.
    user_info_dict = {
        "user": {
            "full_name": full_name,
            "email_address": email_address,
            "password": password
        }
    }
    json_contents = json.dumps(user_info_dict)

    # Generate key pairs for this user.
    generate_keys()

    # Generate digital certificate for this user.
    create_certificate()

    # Encrypt and write user information to file.
    encrypt_file(json_contents, USER_INFO_FILE)

    # Registration is complete.
    print("User Registered.")


def login():
    """
    Handle user login attempts.

    :return: True on successful login, false otherwise.
    """
    # Read and decrypt contents of the user information file.
    json_contents = decrypt_file(USER_INFO_FILE)
    user_info_json = json.loads(json_contents)
    email_json = user_info_json["user"]["email_address"]
    password_json = user_info_json["user"]["password"]

    # Allow the user to perform a certain number of login attempts.
    num_attempts = 0
    while num_attempts < MAX_LOGIN_ATTEMPTS:

        # Request user's email.
        email = get_email("Enter Email Address: ")

        # Request user's password.
        password = pwinput.pwinput(prompt="Enter Password: ", mask="*")

        # Check user inputs against saved information.
        if (email_json == email and check_hashed_string(password, password_json)):
            return True
        else:
            print("Email and Password Combination Invalid.\n")
            num_attempts = num_attempts + 1

    print("Exceeded maximum login attempts.")
    return False


def get_user_info():
    """
    Get user information registered on this client.

    :return: Dictionary containing user's full name and email address.
    """
    # Read and decrypt contents of the user information file.
    json_contents = decrypt_file(USER_INFO_FILE)
    user_info_json = json.loads(json_contents)

    # Obtain user full name and email.
    name = user_info_json["user"]["full_name"]
    email = user_info_json["user"]["email_address"]

    # Construct and return dictionary.
    user_info = {"full_name": name, "email_address": email}
    return user_info
