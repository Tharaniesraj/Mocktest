from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'KSR_MOCK_TEST_APP_SECRET_KEY'
app.config['Mongodb_DATABASE_URI'] = 'mongodb+srv://CCEHEAD:CCEHEAD@mocktest.fofsz.mongodb.net/?retryWrites=true&w=majority&appName=MockTest'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'csv'}

# MongoDB configuration
client = MongoClient(app.config['Mongodb_DATABASE_URI'])
db = client['mock_test_db']  # Replace with your database name

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin):
    def __init__(self, username, email, password_hash, is_admin=False):
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.is_admin = is_admin

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@app.route('/')
def index():
    
    return render_template('index.html')
@app.route('/library')
def library():
    return render_template('library.html')

@app.route('/welcome')
def welcome():
    return render_template('welcome.html')

@app.route('/gate')
def gate():
    return render_template('gate.html')

@app.route('/tnpsc')
def tnpsc():
    return render_template('tnpsc.html')

@app.route('/branches/cse')
def cse():
    return render_template('branches/cse.html')

@app.route('/branches/ece')
def ece():
    return render_template('branches/ece.html')

@app.route('/branches/eee')
def eee():
    return render_template('branches/eee.html')

@app.route('/branches/bme')
def bme():
    return render_template('branches/bme.html')

@app.route('/branches/mech')
def mech():
    return render_template('branches/mech.html')

@app.route('/branches/it')
def it():
    return render_template('branches/it.html')

@app.route('/branches/cs')
def cs():
    return render_template('branches/cs.html')

@app.route('/branches/ce')
def ce():
    return render_template('branches/ce.html')

@app.route('/branches/mba')
def mba():
    return render_template('branches/mba.html')

@app.route('/branches/mca')
def mca():
    return render_template('branches/mca.html')

@app.route('/branches/ae')
def ae():
    return render_template('branches/ae.html')

@app.route('/branches/sfe') 
def sfe():
    return render_template('branches/sfe.html') 

@app.route('/branches/iot')
def iot():
    return render_template('branches/iot.html')

@app.route('/branches/csd')
def csd():
    return render_template('branches/csd.html')

@app.route('/branches/me')
def me():
    return render_template('branches/me.html')

@app.route('/branches/aids')
def aids():
    return render_template('branches/aids.html')

@app.route('/branches/group1')
def group1():
    return render_template('branches/group1.html')

@app.route('/branches/group2')
def group2():
    return render_template('branches/group2.html')

@app.route('/branches/group3')
def group3():
    return render_template('branches/group3.html')  

@app.route('/branches/group4')
def group4():
    return render_template('branches/group4.html')   

@app.route('/branches/upsc')
def upsc():
    return render_template('branches/upsc.html')

@app.route('/admin/courses')
def courses():
    return render_template('admin/courses.html')    

def is_valid_college_email(email):
    # Check if the email ends with '@college'
    return email.endswith('@ksriet.ac.in') or email.endswith('@ksrce.ac.in')

# User loader
@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({"_id": user_id})  # Fetch user from MongoDB
    if user_data:
        return User(user_data['username'], user_data['email'], user_data['password_hash'], user_data['is_admin'])
    return None

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need to be an admin to access this page.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if email is a college email
        if not is_valid_college_email(email):
            flash('Registration is only allowed with a college email address.', 'danger')
            return redirect(url_for('register'))

        # Check if user already exists
        if db.users.find_one({"username": username}):
            flash('Username already exists')
            return redirect(url_for('register'))
        
        # Create new user
        new_user = {
            'username': username,
            'email': email,
            'password_hash': generate_password_hash(password),
            'is_admin': False
        }
        db.users.insert_one(new_user)  # Insert new user into MongoDB
        
        flash('Registration successful!')
        return redirect(url_for('welcome'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard' if current_user.is_admin else 'welcome'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = db.users.find_one({"username": username})
        
        if user_data:
            if check_password_hash(user_data['password_hash'], password):
                user = User(user_data['username'], user_data['email'], user_data['password_hash'], user_data['is_admin'])
                login_user(user)
                flash('Login successful!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page if next_page else url_for('admin_dashboard' if user.is_admin else 'welcome'))
            else:
                flash('Invalid password', 'danger')
        else:
            flash('Username not found', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    available_exams = list(db.exams.find())  # Fetch all exams from MongoDB
    completed_exams = list(db.exam_results.find({"user_id": current_user.id}))  # Fetch completed exams
    completed_exam_ids = [result['exam_id'] for result in completed_exams]
    
    return render_template('dashboard.html', 
                         available_exams=available_exams,
                         completed_exams=completed_exams,
                         completed_exam_ids=completed_exam_ids)

@app.route('/exam/<int:exam_id>')
@login_required
def take_exam(exam_id):
    if current_user.is_admin:
        return redirect(url_for('manage_questions', exam_id=exam_id))
        
    exam = db.exams.find_one({"_id": exam_id})  # Fetch exam from MongoDB
    if not exam:
        flash('Exam not found.', 'warning')
        return redirect(url_for('dashboard'))
    
    # Check if user has already taken this exam
    previous_result = db.exam_results.find_one({"user_id": current_user.id, "exam_id": exam_id})
    if previous_result:
        flash('You have already taken this exam. View your results below.', 'info')
        return redirect(url_for('view_result', result_id=previous_result['_id']))
    
    questions = list(db.questions.find({"exam_id": exam_id}))  # Fetch questions for the exam
    if not questions:
        flash('This exam has no questions yet.', 'warning')
        return redirect(url_for('dashboard'))
    
    return render_template('exam.html', exam=exam, questions=questions)

# Additional routes will also need to be updated similarly...
@app.route('/exam/<int:exam_id>/submit', methods=['POST'])
@login_required
def submit_exam(exam_id):
    if current_user.is_admin:
        flash('Administrators cannot take exams.', 'warning')
        return redirect(url_for('admin_dashboard'))
        
    exam = Exam.query.get_or_404(exam_id)
    questions = Question.query.filter_by(exam_id=exam_id).all()
    
    score = 0
    total_questions = len(questions)
    
    for question in questions:
        answer = request.form.get(f'question_{question.id}')
        if answer and answer == question.correct_answer:
            score += 1
    
    percentage = (score / total_questions) * 100 if total_questions > 0 else 0
    
    result = ExamResult(
        user_id=current_user.id,
        exam_id=exam_id,
        score=percentage,
        total_questions=total_questions
    )
    db.session.add(result)
    db.session.commit()
    
    flash(f'Exam submitted successfully! Your score: {percentage:.1f}%', 'success')
    return redirect(url_for('view_result', result_id=result.id))

@app.route('/result/<int:result_id>')
@login_required
def view_result(result_id):
    result = ExamResult.query.get_or_404(result_id)
    if result.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to view this result.', 'danger')
        return redirect(url_for('dashboard'))
    
    exam = Exam.query.get(result.exam_id)
    return render_template('result.html', 
        score=int(result.score), 
        total_questions=result.total_questions, 
        correct_answers=int(result.score / 100 * result.total_questions))

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    exams = Exam.query.all()
    total_users = User.query.filter_by(is_admin=False).count()
    total_questions = Question.query.count()
    total_results = ExamResult.query.count()
    
    return render_template('admin/dashboard.html', 
                         exams=exams,
                         total_users=total_users,
                         total_questions=total_questions,
                         total_results=total_results)

# Logic to make a user an admin
def make_user_admin(user_id):
    user = User.query.get(user_id)  # Function to find user by ID
    if user:
        user.is_admin = True  # Update user role to admin
        db.session.commit()
        return True
    return False

# Example usage in admin_dashboard
@app.route('/admin/make_admin/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def make_admin(user_id):
    if make_user_admin(user_id):
        return "User made admin successfully!", 200
    return "User not found!", 404

@app.route('/admin/new-exam', methods=['GET', 'POST'])
@login_required
@admin_required
def new_exam():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        duration = request.form['duration']
        
        exam = Exam(name=name, description=description, duration=duration)
        db.session.add(exam)
        db.session.commit()
        
        flash('Exam created successfully! Now add questions to your exam.')
        return redirect(url_for('manage_questions', exam_id=exam.id))
    
    return render_template('admin/new_exam.html')

@app.route('/admin/exam/<int:exam_id>/questions', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_questions(exam_id):
    exam = Exam.query.get_or_404(exam_id)
    questions = Question.query.filter_by(exam_id=exam_id).all()
    

    if request.method == 'POST':
        text = request.form['text']
        option_a = request.form['option_a']
        option_b = request.form['option_b']
        option_c = request.form['option_c']
        option_d = request.form['option_d']
        correct_answer = request.form['correct_answer']
        
        question = Question(
            exam_id=exam_id,
            text=text,
            option_a=option_a,
            option_b=option_b,
            option_c=option_c,
            option_d=option_d,
            correct_answer=correct_answer
        )
        db.session.add(question)
        db.session.commit()
        
        if 'add_another' in request.form:
            flash('Question added successfully! Add another question.')
            return redirect(url_for('manage_questions', exam_id=exam_id))
        else:
            flash('Question added successfully! Exam is ready.')
            return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/manage_questions.html', exam=exam, questions=questions)

@app.route('/admin/question/<int:question_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_question(question_id):
    question = Question.query.get_or_404(question_id)
    exam_id = question.exam_id
    db.session.delete(question)
    db.session.commit()
    
    flash('Question deleted successfully!')
    return redirect(url_for('manage_questions', exam_id=exam_id))

@app.route('/admin/delete_exam/<int:exam_id>', methods=['POST'])
@login_required
def delete_exam(exam_id):
    if not current_user.is_admin:
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('dashboard'))
        
    exam = Exam.query.get_or_404(exam_id)
    
    # Delete all questions associated with this exam
    Question.query.filter_by(exam_id=exam_id).delete()
    
    # Delete all exam results associated with this exam
    ExamResult.query.filter_by(exam_id=exam_id).delete()
    
    # Delete the exam
    db.session.delete(exam)
    db.session.commit()
    
    flash('Exam deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/submit-questions', methods=['POST'])
@login_required
@admin_required
def submit_questions():
    if not current_user.is_authenticated or not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    exam_id = request.form.get('exam_id')
    
    # Handle file upload
    if 'file' in request.files:
        file = request.files['file']
        if file and file.filename != '':
            # Secure filename
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Parse the uploaded file
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    questions_data = f.readlines()
                
                questions_added = 0
                # Process questions from file
                for line_num, line in enumerate(questions_data, 1):
                    # Try multiple delimiters
                    parts = [p.strip() for p in re.split(r'[,\t|]', line.strip())]
                    
                    # More flexible parsing
                    if len(parts) >= 6:
                        try:
                            new_question = Question(
                                exam_id=exam_id,
                                text=parts[0],
                                option_a=parts[1],
                                option_b=parts[2],
                                option_c=parts[3],
                                option_d=parts[4],
                                correct_answer=parts[5].upper()  # Ensure A, B, C, or D
                            )
                            db.session.add(new_question)
                            questions_added += 1
                        except Exception as question_error:
                            print(f"Error processing line {line_num}: {line}")
                            print(f"Error details: {question_error}")
                
                db.session.commit()
                flash(f'Successfully uploaded {questions_added} questions from file!', 'success')
            except Exception as e:
                db.session.rollback()
                print(f"File upload error: {e}")
                flash(f'Error processing file: {str(e)}', 'danger')
    
    # Handle manual question entry
    questions = request.form.getlist('question[]')
    if questions:
        for i in range(len(questions)):
            new_question = Question(
                exam_id=exam_id,
                text=request.form.getlist('question[]')[i],
                option_a=request.form.getlist('optionA[]')[i],
                option_b=request.form.getlist('optionB[]')[i],
                option_c=request.form.getlist('optionC[]')[i],
                option_d=request.form.getlist('optionD[]')[i],
                correct_answer=request.form.getlist('correctAnswer[]')[i]
            )
            db.session.add(new_question)
        
        db.session.commit()
        flash('Questions added successfully!', 'success')
    
    return redirect(url_for('manage_questions', exam_id=exam_id))

@app.route('/student_rankings')
@login_required
def student_rankings():
    # Get all exam results and sort them by percentage in descending order
    exam_results = ExamResult.query.all()
    
    # Create a list to store ranking information
    rankings = []
    
    # Group results by exam and calculate rankings
    exams = Exam.query.all()
    for exam in exams:
        exam_specific_results = [
            result for result in exam_results 
            if result.exam_id == exam.id
        ]
        
        # Sort results by score percentage in descending order
        sorted_results = sorted(
            exam_specific_results, 
            key=lambda x: (x.score / x.total_questions * 100), 
            reverse=True
        )
        
        # Add rank to each result
        for idx, result in enumerate(sorted_results, 1):
            user = User.query.get(result.user_id)
            percentage = (result.score / result.total_questions * 100)
            
            rankings.append({
                'rank': int(idx),
                'username': user.username,
                'exam_name': exam.name,
                'score': int(result.score),
                'total_questions': int(result.total_questions),
                'percentage': int(percentage)
            })
    
    return render_template('student_rankings.html', rankings=rankings)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
