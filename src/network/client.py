"""
Module for SecureDrop client.
"""
import psutil
import os
import socket
import ssl
import random


class Client():
    """
    SecureDrop Client.
    """

    # SecureDrop communicates with other SecureDrop users on the local network.
    HOST = "127.0.0.1"

    LISTEN_TIME = 5

    # CA certificate.
    CA_CERT = "CA.pem"

    def __init__(self, user_name, user_email):
        """
        Setup client for SecureDrop user.

        :param user_name: User's full name.
        :param user_email: User's email address.
        :return: None
        """
        self.user_name = user_name
        self.user_email = user_email

        # Initialize a seed and generate a sequence number for the client.
        random.seed()
        self.sequence_number = random.randint(1, 10000)

    def send_message(self, port, message):
        """
        Send a message to the server listening on the specified port.

        :param port: Port that the server is listening on.
        :param message: Message to send to the server.
        :return: Message reply from the server.
        """
        # Append message with user information.
        message = message + f" CLIENT: {self.user_name} <{self.user_email}> <{self.sequence_number}>"

        # Increment this users sequence number
        self.sequence_number += 1

        # Setup SSL context.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Load CA root certificate to verify server certificate.
        context.load_verify_locations(self.CA_CERT)

        # Setup client socket.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Wrap the socket with our context to provide SSL security.
            with context.wrap_socket(s, server_hostname="localhost") as ssock:
                # Connect and send message to the server.
                ssock.connect((self.HOST, port))
                ssock.send(bytes(message, "utf-8"))

                # Obtain reply from the server.
                reply = ssock.recv(1024).decode("utf-8")

        return reply

    def send_file(self, port, file):
        """
        Send a file to a contact.

        :param port: Port that the server is listening on.
        :param file: File to send.
        :return: Message reply from the server.
        """
        # Setup SSL context.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Load CA root certificate to verify server certificate.
        context.load_verify_locations(self.CA_CERT)

        # Setup and connect client socket to server.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Wrap the socket with our context to provide SSL security.
            with context.wrap_socket(s, server_hostname="localhost") as ssock:
                # Connect to server.
                ssock.connect((self.HOST, port))

                # Read contents of the file.
                with open(file, "r") as f:
                    data = f.read()

                # Send filename to server.
                message = os.path.basename(file)
                ssock.send(bytes(message, "utf-8"))
                reply1 = ssock.recv(1024).decode("utf-8")

                # Send file data to server.
                # This reply contains the hash of the received file.
                ssock.send(bytes(data, "utf-8"))
                reply2 = ssock.recv(1024).decode("utf-8")

        return reply2


def get_listening_ports():
    """
    Get a list of listening server ports on the local network.

    :return: List of sockets corresponding to SecureDrop servers.
    """
    listening_sockets = {}
    for c in psutil.net_connections():
        if c.status == "LISTEN":
            listening_sockets[c.pid] = c.laddr.port

    port_list = []
    for pid, port in listening_sockets.items():
        p = psutil.Process(pid)
        if p.name() == "python.exe":
            port_list.append(port)

    return port_list
