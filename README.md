# Description

This application is a secure file transfer project where two users log in to the program and can transfer files to one another. This is similar to the idea of air drop on iphone, but instead is done on a single computer. This project was done as a final project for our Computing Security class in college. 

The goal of this project was to practice network security. Specifically the encryption of user account information and communications via the internet. DES and RSA are using to encrypt json data as well as sending packets to other users. Other encryption methods such as salting and hashing, and SSL were also used.

# Installation

To run this program, you will need at least 2 seperate directories of the source code. Think of it as 2 users installing the program seperately. You will need to install Python3 and the dependencies listed in requirements.txt.
    pip install -r requirements.txt

# How to Use

Once installed, each user runs secure_drop.py through the command line:
    python secure_drop.py

This will ask you to create a user account. Once a user account is created in both installations, we can continue.

![An image showing the registration request on command prompt.](/assets/images/register.PNG)

After registering, run the program again. Running help will show you a list of commands:

![An image showing the list of commands on command prompt.](/assets/images/commands.PNG)

Use the add command to add the other user to your list of contacts. This will ask for a name and an email address. The command will NOT fail if a incorrect email is given, but communications with this email will fail.

![An image showing the add command on command prompt.](/assets/images/add.PNG)

The list command will list all of your online contacts. If both accounts are online, you should see the other account listed.

![An image showing the list command on command prompt.](/assets/images/list.PNG)

The send command is used to send a file to another contact.

![An image showing the send command on command prompt.](/assets/images/send.PNG)

In order for the file to be sent, the other contact must accept that file transfer:

![An image showing a user accept a send request.](/assets/images/accept.PNG)
