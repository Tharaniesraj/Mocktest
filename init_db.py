from app import app, User
from flask import Flask
from pymongo import MongoClient
import bcrypt

# MongoDB configuration
client = MongoClient('mongodb+srv://CCEHEAD:CCEHEAD@mocktest.fofsz.mongodb.net/?retryWrites=true&w=majority&appName=MockTest')
db = client['mock_test_db']  # Replace with your database name
password = 'admin123'

def init_database():
    with app.app_context():
        # Create admin user
        admin = {
            'username': 'admin',
            'email': 'admin@ksriet.ac.in',
            'is_admin': True,
            'password_hash': bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())  # Ensure to import this function
        }
        db.users.insert_one(admin)  # Insert admin user into MongoDB

        print("Database initialized successfully!")

if __name__ == '__main__':
    init_database()
