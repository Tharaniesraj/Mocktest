import sqlite3
from app import app, db, User
from flask import Flask

def init_database():
    with app.app_context():
        # Create tables
        db.create_all()
                
        # Create admin user
        admin = User(
            username='admin',
            email='admin@ksriet.ac.in',
            is_admin=True
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

        print("Database initialized successfully!")
        
if __name__ == '__main__':
    init_database()