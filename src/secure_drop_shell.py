"""
Module for SecureDrop shell implementation.
"""
import cmd
import json
import os
from time import sleep

from utilities import get_email
from security import encrypt_file, decrypt_file, check_hashed_string
from network.server import Server
from network.client import Client, get_listening_ports

CONTACTS_FILE = "contacts.json"


class SecureDropShell(cmd.Cmd):
    """
    SecureDrop application shell.
    """

    # Shell attributes.
    intro = "Welcome to SecureDrop. \nType \"help\" For Commands.\n"
    prompt = "secure_drop> "

    def __init__(self, user_info):
        """
        Initialize SecureDrop shell.

        :param user_info: Dictionary containing information of current user.
        :return: None.
        """
        cmd.Cmd.__init__(self)
        cmd.Cmd.use_rawinput = True  # Allow input() to be used for raw input.

        self.user_name = user_info["full_name"]
        self.user_email = user_info["email_address"]

        # Setup and start server.
        self.server = Server(self.user_name, self.user_email)
        self.server.run()

        # Setup client.
        self.client = Client(self.user_name, self.user_email)

    def do_help(self, arg):
        """
        Display available commands.

        :param arg: String of argument(s) entered after command name.
        :return: None.
        """
        print("  \"add\"  -> Add a new contact")
        print("  \"list\" -> List all online contacts")
        print("  \"send\" -> Transfer file to contact")
        print("  \"exit\" -> Exit SecureDrop")

    def do_add(self, arg):
        """
        Add a new contact.

        :param arg: String of argument(s) entered after command name.
        :return: None.
        """
        # Request new contact's full name and validate email address.
        full_name = input("  Enter Full Name: ")
        email_address = get_email("  Enter Email Address: ")

        new_contact_dict = {
            "full_name": full_name,
            "email_address": email_address
        }

        if os.path.exists(CONTACTS_FILE):

            # Read and decrypt contents of contacts file.
            json_contents = decrypt_file(CONTACTS_FILE)

            # Extract contents as a dictionary data structure.
            # contact_dict["contacts"] is a list of all registered contacts.
            contact_dict = json.loads(json_contents)

            # If a contact exists, update their information in the dictionary.
            # The email address is used as the user identifier.
            exists = False
            for contact in contact_dict["contacts"]:
                # Update contact name of existing contact.
                if contact["email_address"] == email_address:
                    contact["full_name"] = full_name
                    exists = True

            # Add new contact to contacts dictionary.
            if not exists:
                contact_dict["contacts"].append(new_contact_dict)
        else:

            # Initialize contacts dictionary.
            contact_dict = {"contacts": [new_contact_dict]}

        # Format contacts dictionary back into JSON format.
        json_contents = json.dumps(contact_dict)

        # Encrypt data and write to file.
        encrypt_file(json_contents, CONTACTS_FILE)

        print("  Contact Added.")

    def do_list(self, arg):
        """
        List all contacts that satisfy the following requirements.
            1. The contact information has been added to this user's contacts.
            2. The contact has also added this user's information to their contacts.
            3. The contact is online on the user's local network.

        :param arg: String of argument(s) entered after command name.
        :return: None.
        """
        online_contacts = []

        if os.path.exists(CONTACTS_FILE):
            # Decrypt and extract contents from contacts file.
            json_contents = decrypt_file(CONTACTS_FILE)
            contact_dict = json.loads(json_contents)

            for contact in contact_dict["contacts"]:
                contact_name = contact["full_name"]
                contact_email = contact["email_address"]

                # Check if contact is online and has added this user's info.
                if self.is_contact_mutual_and_online(contact_email):
                    online_contacts.append(f"{contact_name} <{contact_email}>")

        # Print online contacts.
        if online_contacts:
            print("  The following contacts are online.")
            for contact in online_contacts:
                print("  *", contact)
        else:
            print("  No contacts are online.")

    def do_send(self, arg):
        """
        Transfer file to contact.
        The user must provide the email of the contact and the file to send to the user.

        :param arg: String of argument(s) entered after command name.
        :return: None.
        """
        # Parse and validate arguments.
        arg_list = arg.split()
        if len(arg_list) != 2:
            print("  Invalid number of arguments.")
            return

        contact_email = arg_list[0]
        file = arg_list[1]

        # Check if email belongs to a contact.
        contact_exists = False
        if os.path.exists(CONTACTS_FILE):
            json_contents = decrypt_file(CONTACTS_FILE)
            contact_dict = json.loads(json_contents)
            for contact in contact_dict["contacts"]:
                if contact["email_address"] == contact_email:
                    contact_exists = True

        if not contact_exists:
            print("  Contact does not exist.")
            return

        # Check if the file exists.
        if not os.path.isfile(file):
            print("  File does not exist.")
            return

        # Check if this contact is online and mutual.
        if not self.is_contact_mutual_and_online(contact_email):
            print("  Contact is not online.")
            return

        # Request to send the file to the contact.
        contact_port = self.get_contact_port(contact_email)
        message = "SEND FILE?"
        reply = self.client.send_message(contact_port, message)

        if reply != "y":
            print("  Contact has declined the transfer request.")
            return

        # Send the file to the contact.
        print("  Contact has accepted the transfer request.")
        reply = self.client.send_file(contact_port, file)

        with open(file, "r") as f:
          contents = f.read()
      
        # Confirm the receieved file contents are correct
        if check_hashed_string( contents, reply ):
            print("  File has been successfully transferred.")
        else:
            print("  Error transferring file.")

    def do_exit(self, arg):
        """
        Exit SecureDrop.

        :param arg: String of argument(s) entered after command name.
        :return: True, to stop the shell.
        """
        return True

    def emptyline(self):
        """
        Do nothing when an empty line is entered in the prompt.

        :return: None
        """
        sleep(1)
        return

    def is_contact_mutual_and_online(self, contact_email):
        """
        Check if the contact is a mutual contact and is online.

        :param contact_email: Contact's email.
        :return: True if the contact meets the requirements, false otherwise.
        """
        contact_port = self.get_contact_port(contact_email)

        # If contact was not found, contact is not online.
        if contact_port == 0:
            return False

        # Send a message to determine if the contact is a mutual contact.
        message = f"MUTUAL?"
        reply = self.client.send_message(contact_port, message)

        if reply == "YES":
            return True
        else:
            return False

    def get_contact_port(self, contact_email):
        """
        Get the contact's server port.

        :param contact_email: Contact's email.
        :return: Contact's server port, or 0 if nonexistent.
        """
        # Get a list of server ports on the local network.
        ports = get_listening_ports()

        # Send a message to each port to determine its identity.
        for port in ports:
            message = f"ARE YOU {contact_email}?"
            reply = self.client.send_message(port, message)
            if reply == "YES":
                return port

        # Messages have been sent to each port, but none are the contact.
        return 0
