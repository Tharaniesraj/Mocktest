from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from functools import wraps
from flask import abort
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'KSR_MOCK_TEST_APP_SECRET_KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mock_test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'csv'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    duration = db.Column(db.Integer)  # in minutes

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(255), nullable=False)
    option_b = db.Column(db.String(255), nullable=False)
    option_c = db.Column(db.String(255), nullable=False)
    option_d = db.Column(db.String(255), nullable=False)
    correct_answer = db.Column(db.String(1), nullable=False)

class ExamResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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

# Routes
@app.route('/')
def index():
    return render_template('index.html')
def is_valid_college_email(email):
    """
    Validate if the email belongs to a college domain.
    Add your specific college domains here.
    """
    # List of allowed college email domains
    allowed_domains = [
        '@ksriet.ac.in',  # Replace with your specific college domains
        '@ksrce.ac.in',
        
        # Add more college domains as needed
    ]
    
    return any(email.lower().endswith(domain) for domain in allowed_domains)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if not is_valid_college_email(email):
            flash('Registration is only allowed with a college email address.', 'danger')
            return redirect(url_for('register'))

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        

        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful!')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard' if current_user.is_admin else 'welcome'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Validate college email domain during login
        if not is_valid_college_email(email):
            flash('Login is only allowed with a college email address.', 'danger')
            return redirect(url_for('login'))
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('admin_dashboard' if user.is_admin else 'welcome'))
        
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    available_exams = Exam.query.all()
    completed_exams = ExamResult.query.filter_by(user_id=current_user.id).all()
    completed_exam_ids = [result.exam_id for result in completed_exams]
    
    return render_template('dashboard.html', 
                         available_exams=available_exams,
                         completed_exams=completed_exams,
                         completed_exam_ids=completed_exam_ids)

@app.route('/exam/<int:exam_id>')
@login_required
def take_exam(exam_id):
    if current_user.is_admin:
        return redirect(url_for('manage_questions', exam_id= exam_id))
        
    exam = Exam.query.get_or_404(exam_id)
    # Check if user has already taken this exam
    previous_result = ExamResult.query.filter_by(user_id=current_user.id, exam_id=exam_id).first()
    if previous_result:
        flash('You have already taken this exam. View your results below.', 'info')
        return redirect(url_for('view_result', result_id=previous_result.id))
    
    questions = Question.query.filter_by(exam_id=exam_id).all()
    if not questions:
        flash('This exam has no questions yet.', 'warning')
        return redirect(url_for('dashboard'))
    
    return render_template('exam.html', exam=exam, questions=questions)

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
    return render_template('result.html', score=result.score, total_questions=result.total_questions, correct_answers=result.score / 100 * result.total_questions)

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
def submit_questions():

    # Extract data from the form
    exam_id = request.form.get('exam_id')
    questions = request.form.getlist('question[]')
    optionsA = request.form.getlist('optionA[]')
    optionsB = request.form.getlist('optionB[]')
    optionsC = request.form.getlist('optionC[]')
    optionsD = request.form.getlist('optionD[]')
    correct_answers = request.form.getlist('correctAnswer[]')

    for i in range(len(questions)):
        new_question = Question(
            exam_id=exam_id,
            text=questions[i],
            option_a=optionsA[i],
            option_b=optionsB[i],
            option_c=optionsC[i],
            option_d=optionsD[i],
            correct_answer=correct_answers[i]
        )
        db.session.add(new_question)
    db.session.commit()

    return redirect(url_for('index'))  # Ensure this matches your route

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Ensure the database is created
    with app.app_context():
        db.create_all()
    
    app.run(debug=True)
