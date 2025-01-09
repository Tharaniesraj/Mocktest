from app import app, db, User, Exam, Question
from flask import Flask

def init_database():
    with app.app_context():
        # Create tables
        db.create_all()

        # Create admin user
        admin = User(
            username='admin',
            email='admin@ksr.edu',
            is_admin=True
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

        # Create sample exams
        competitive_exam = Exam(
            name='KSR Engineering Competitive Exam',
            description='Mock test for competitive engineering entrance',
            duration=60  # 60 minutes
        )
        db.session.add(competitive_exam)
        db.session.commit()

        # Create sample questions
        questions = [
            Question(
                exam_id=competitive_exam.id,
                text='What is the capital of Tamil Nadu?',
                option_a='Mumbai',
                option_b='Chennai',
                option_c='Bangalore',
                option_d='Delhi',
                correct_answer='B'
            ),
            Question(
                exam_id=competitive_exam.id,
                text='What is 15 + 7?',
                option_a='20',
                option_b='21',
                option_c='22',
                option_d='23',
                correct_answer='C'
            ),
            Question(
                exam_id=competitive_exam.id,
                text='Who is the father of the Indian Constitution?',
                option_a='Mahatma Gandhi',
                option_b='Jawaharlal Nehru',
                option_c='B.R. Ambedkar',
                option_d='Sardar Patel',
                correct_answer='C'
            )
        ]
        db.session.bulk_save_objects(questions)
        db.session.commit()

        print("Database initialized successfully!")
        print("Admin credentials:")
        print("Username: admin")
        print("Password: admin123")

if __name__ == '__main__':
    init_database()
