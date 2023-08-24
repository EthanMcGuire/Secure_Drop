"""
SecureDrop Application
"""
import os

from user import USER_INFO_FILE, register_user, login, get_user_info
from secure_drop_shell import SecureDropShell


def main():
    """
    Driver function to execute SecureDrop application.

    :return: None
    """
    # Check if a user is registered on this client by checking if the JSON
    # file containing user information exists.
    if os.path.exists(USER_INFO_FILE):

        # A user already exists. Allow login attempts.
        success = login()

        # Start the application shell on successful login.
        if success:

            # Initialize session with current user information.
            current_user_info = get_user_info()
            shell = SecureDropShell(current_user_info)

            # Start shell.
            shell.cmdloop()
    else:

        # Prompt new user registration.
        # It is assumed that the user will enter a valid response.
        print("No users are registered with this client.")
        user_input = input("Do you want to register a new user (y/n)? ")

        # Perform the one-time user registration procedure.
        if user_input == "y":
            register_user()

    print("Exiting SecureDrop.")


if __name__ == "__main__":
    main()
