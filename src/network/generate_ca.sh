#!/bin/sh

openssl req -x509 -newkey rsa:2048 -keyout CA_key.pem -out CA.pem -outform PEM -sha256 -days 365 -nodes -subj "/C=US/ST=Massachusetts/L=Lowell/O=UML/OU=Org/CN=localhost"