"""
Module for SecureDrop server.
"""
import errno
import json
import os
import parse
import socket
import threading
import ssl

from security import decrypt_file, hash

CONTACTS_FILE = "contacts.json"


class Server():
    """
    SecureDrop Server.
    """

    # SecureDrop communicates with other SecureDrop users on the local network.
    HOST = "127.0.0.1"

    # A SecureDrop server listens to a port starting at or after 50,000.
    BASE_PORT = 50000

    LISTEN_TIME = 5

    # User's private key and CA-signed certificate.
    PRIVATE_KEY = "private_key.pem"
    CERT_NAME = "certificate.pem"

    # Specific messages from the client to parse.
    IDENTITY_MSG = "ARE YOU {}? CLIENT: {} <{}> <{}>"
    MUTUAL_MSG = "MUTUAL? CLIENT: {} <{}> <{}>"
    REQUEST_MSG = "SEND FILE? CLIENT: {} <{}> <{}>"
    CLIENT_MSG = "CLIENT: {} <{}> <{}>"

    def __init__(self, user_name, user_email):
        """
        Setup and execute server for SecureDrop user.

        :param user_name: User's full name.
        :param user_email: User's email address.
        :return: None
        """
        self.user_name = user_name
        self.user_email = user_email
        self.setup_context()
        self.setup_socket()

        self.file_transfer_in_progress = False

        self.client_sequence_numbers = {}

    def setup_context(self):
        """
        Setup SSL context.

        :return: None
        """
        # Setup SSL context and load user's certificate.
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=self.CERT_NAME, keyfile=self.PRIVATE_KEY)

    def setup_socket(self):
        """
        Setup the server-side socket.

        :return: None
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.port = self.BASE_PORT

        # Attempt to bind the socket to the given host and port number.
        # If a socket is in use, attempt to bind the socket to the
        # next consecutive port that is available.
        bind_success = False
        while not bind_success:
            try:
                self.socket.bind((self.HOST, self.port))
                bind_success = True
            except socket.error as e:
                if e.errno == errno.EADDRINUSE:
                    self.port = self.port + 1
                else:
                    print("  Connection failed.")

    def listen(self):
        """
        Have the server listen on the port and respond to any messages.

        :return: None
        """
        self.socket.listen(self.LISTEN_TIME)

        with self.context.wrap_socket(self.socket, server_side=True) as ssock:
            while True:
                if self.file_transfer_in_progress:
                    # Accept connection from client.
                    connection, addr = ssock.accept()

                    # Receive filename from client.
                    file = connection.recv(1024)
                    file = file.decode("utf-8")
                    connection.send(bytes(f"Received {file}.", "utf-8"))

                    # Receive file data from client.
                    data = connection.recv(1024)
                    data = data.decode("utf-8")

                    # Hash and send back the file data to confirm its contents.
                    connection.send(bytes(hash(data), "utf-8"))

                    # Save file.
                    with open(file, "w") as f:
                        f.write(data)

                    connection.close()

                    # No longer receiving a file.
                    self.file_transfer_in_progress = False
                else:
                    # Accept connection and get message from client.
                    connection, addr = ssock.accept()
                    client_message = connection.recv(1024).decode("utf-8")

                    # Process message from client.
                    server_message = self.process_message(client_message)

                    # Send message to client.
                    connection.send(bytes(server_message, "utf-8"))
                    connection.close()

    def process_message(self, message):
        """
        Take action based on message from client.

        :param message: Message sent from a client.
        :return: Reply message to send to the client.
        """
        result = parse.search(self.CLIENT_MSG, message)

        # Get the client's email
        sender_email = result.fixed[1]

        # Get the client's sequence number.
        sequenceNew = result.fixed[2]

        # Compare sequenceNew to the old sequence value
        if sender_email in self.client_sequence_numbers.keys():
            sequenceOld = self.client_sequence_numbers[sender_email]

            # Ignore older sequence numbers.
            if (sequenceNew <= sequenceOld):
                # This message is not valid (could be a replay attack).
                #print(f"Old message was received from {sender_email}, ignoring the message.")
                return "UNKNOWN"
            else:
                # Valid sequence, set the new value.
                self.client_sequence_numbers[sender_email] = sequenceNew
        else:
            # Get the senders sequence number
            self.client_sequence_numbers[sender_email] = sequenceNew

        # Handle messages related to identity.
        if "ARE YOU" in message:
            result = parse.parse(self.IDENTITY_MSG, message)
            email = result.fixed[0]
            if self.user_email == email:
                return "YES"
            else:
                return "NO"

        # Handle messages related to online/mutual contacts.
        if "MUTUAL" in message:
            result = parse.parse(self.MUTUAL_MSG, message)
            email = result.fixed[1]

            # Check if client exists in user's contacts.
            if os.path.exists(CONTACTS_FILE):
                json_contents = decrypt_file(CONTACTS_FILE)
                contact_dict = json.loads(json_contents)
                for contact in contact_dict["contacts"]:
                    if contact["email_address"] == email:
                        return "YES"

            # Client is not in user's contacts.
            return "NO"

        # Handle message related to sending files.
        if "SEND" in message:
            # A SEND request was made to this user.
            result = parse.parse(self.REQUEST_MSG, message)
            contact_name = result.fixed[0]
            contact_email = result.fixed[1]

            print("Incoming message! Press enter to view message.")
            reply = input(
                f"Contact '{contact_name} <{contact_email}>' is sending a file. Accept (y/n)? "
            )

            if "y" in reply:
                self.file_transfer_in_progress = True

            return reply

        # We do not know how to handle this string.
        # This should not happen.
        return "UNKNOWN"

    def run(self):
        """
        Run the server in a separate thread.

        :return: None
        """
        thread = threading.Thread(target=self.listen)
        thread.daemon = True
        thread.start()
