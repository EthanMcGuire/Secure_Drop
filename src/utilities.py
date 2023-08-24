"""
Utility functions for SecureDrop application.
"""

import re
import pwinput

EMAIL_REGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
MIN_PASSWORD_LENGTH = 10


def get_email(prompt):
    """
    Acquire valid user email.

    :param prompt: String to display when prompting email input.
    :return: Valid email address.
    """
    email_address = input(prompt)

    while not is_valid_email(email_address):
        print("\nInvalid email address.")
        email_address = input(prompt)

    return email_address


def get_password():
    """
    Acquire password from the user and validate input.

    :return: Valid password according to application's password policies.
    """
    passwords_match = False

    while not passwords_match:
        # Mask the password on the command-line.
        password = pwinput.pwinput(prompt="Enter Password: ", mask="*")

        # Confirm the entered password follows security policies.
        while not is_valid_password(password):
            print("\nInvalid password.")
            password = pwinput.pwinput(prompt="Enter Password: ", mask="*")

        # Confirm password again.
        pw_validate = pwinput.pwinput(prompt="Re-Enter Password: ", mask="*")
        if password == pw_validate:
            print("\nPasswords Match.")
            passwords_match = True
        else:
            print("\nPasswords Do Not Match.")

    return password


def is_valid_email(email_address):
    """
    Check if the given email is valid. An email is valid if it is has a name
    (an alphanumeric string with some allowed special characters), followed by
    the at sign (@) and a domain name.

    :param email_address: Email address provided by user.
    """
    if re.fullmatch(EMAIL_REGEX, email_address):
        return True

    return False


def is_valid_password(password):
    """
    Check if the given password follows security rules.
    The password must contain:
        (1) At least MIN_PASSWORD_LENGTH characters.
        (2) At least one special character.
        (3) At least one capital letter.
        (4) At least one numerical digit.
    """
    # Check password length.
    if (len(password) < MIN_PASSWORD_LENGTH):
        print(
            f"\nPassword should be at least {MIN_PASSWORD_LENGTH} characters long."
        )
        return False

    # Check for at least one special characters.
    if not any(not c.isalnum() for c in password):
        print("\nPassword needs a special character.")
        return False

    # Check for at least one capital letter.
    if not any(c.isupper() for c in password):
        print("\nPassword needs a capital letter.")
        return False

    # Check for at least one numerical digit.
    if not any(c.isnumeric() for c in password):
        print("\nPassword needs a numerical digit.")
        return False

    # Password has met security policies.
    return True
