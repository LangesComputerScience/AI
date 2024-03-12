# Programmer: Mr. Lange
# Date: 3.12.2024
# Program: Password Generator
# Resource: https://youtu.be/jRAAaDll34Q?si=SZq8WSYzjrmuAoIA

import hashlib
import os

def generate_salt():
    return os.urandom(16)  # Generates a random 16-byte salt

def hash_password(password, salt):
    # Combine password and salt before hashing
    salted_password = password.encode() + salt
    # Hash the salted password using SHA-256 algorithm
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password

def main():
    password = input("Enter your password: ")
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    print("Hashed password:", hashed_password)

if __name__ == "__main__":
    main()
