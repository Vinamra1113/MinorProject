from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ------------------- Models -------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    transactions = db.relationship('Transaction', backref='user', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    card_number = db.Column(db.String(20))
    amount = db.Column(db.Float)
    location = db.Column(db.String(100))
    is_fraud = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# ------------------- User Loader -------------------
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ------------------- Fraud Detection Logic -------------------
def detect_fraud(amount, location):
    """Fraud detection rules for India (INR)"""
    risk_score = 0

    domestic_locations = [
        'mumbai', 'delhi', 'bangalore', 'hyderabad', 'chennai',
        'kolkata', 'pune', 'ahmedabad', 'surat', 'jaipur', 'jabalpur',
        'indore', 'bhopal', 'gwalior', 'ujjain', 'sagar',
        'satna', 'ratlam', 'chhindwara', 'khandwa', 'rewa',
        'nagpur', 'lucknow', 'kanpur', 'vadodara', 'rajkot',
        'coimbatore', 'madurai', 'visakhapatnam', 'trivandrum', 'kochi',
        'patna', 'ranchi', 'guwahati', 'amritsar', 'ludhiana'
    ]

    common_international = [
        'london', 'tokyo', 'paris', 'sydney', 'toronto',
        'dubai', 'singapore', 'hong kong', 'new york', 'san francisco',
        'los angeles', 'chicago', 'berlin', 'rome', 'barcelona',
        'vienna', 'amsterdam', 'seoul', 'bangkok', 'kuala lumpur',
        'doha', 'abu dhabi', 'istanbul', 'zurich', 'copenhagen',
        'stockholm', 'auckland', 'melbourne', 'osaka', 'frankfurt'
    ]

    high_risk_countries = [
        'pakistan', 'afghanistan', 'north korea', 'syria', 'yemen',
        'iran', 'somalia', 'sudan', 'libya', 'myanmar',
        'iraq', 'lebanon', 'eritrea', 'burkina faso', 'mali',
        'niger', 'chad', 'central african republic', 'congo', 'venezuela'
    ]

    if amount > 75000:
        risk_score += 40
    elif amount > 50000:
        risk_score += 30
    elif amount > 25000:
        risk_score += 15

    loc = location.lower()
    if loc in domestic_locations:
        risk_score += 0
    elif loc in common_international:
        risk_score += 5
    elif loc in high_risk_countries:
        risk_score += 50
    else:
        risk_score += 20

    if risk_score >= 40:
        return True, 0.9
    elif risk_score >= 35:
        return True, 0.8
    elif risk_score > 25:
        return False, 0.5
    else:
        return False, 0.05

# ------------------- Init DB -------------------
with app.app_context():
    db.create_all()

# ------------------- Routes -------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash("Username already taken")
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/check-fraud', methods=['POST'])
@login_required
def check_fraud():
    data = request.json
    if not all(k in data for k in ['card_number', 'amount', 'location']):
        return jsonify({'error': 'Missing required fields'}), 400

    is_fraud, confidence = detect_fraud(
        amount=float(data['amount']),
        location=data['location']
    )

    transaction = Transaction(
        card_number=data['card_number'][-4:],
        amount=float(data['amount']),
        location=data['location'],
        is_fraud=is_fraud,
        user_id=current_user.id
    )
    db.session.add(transaction)
    db.session.commit()

    return jsonify({
        'is_fraud': is_fraud,
        'confidence': confidence
    })

if __name__ == '__main__':
    app.run(debug=True)
