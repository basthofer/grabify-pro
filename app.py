from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
import shortuuid
from datetime import datetime
from user_agents import parse
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///urls.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(500), nullable=False)
    short_code = db.Column(db.String(10), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    visits = db.relationship('Visit', backref='url', lazy=True)

class Visit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('url.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))
    browser = db.Column(db.String(200))
    os = db.Column(db.String(100))
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    region = db.Column(db.String(100))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_ip_details(ip):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}')
        data = response.json()
        if data['status'] == 'success':
            return {
                'country': data['country'],
                'city': data['city'],
                'region': data['regionName']
            }
    except:
        pass
    return {'country': 'Unknown', 'city': 'Unknown', 'region': 'Unknown'}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/shorten', methods=['POST'])
def shorten():
    original_url = request.form.get('url')
    if not original_url:
        flash('Please enter a URL')
        return redirect(url_for('index'))
    
    short_code = shortuuid.uuid()[:6]
    url = URL(original_url=original_url, short_code=short_code)
    db.session.add(url)
    db.session.commit()
    
    return render_template('index.html', 
                         short_url=request.host_url + short_code)

@app.route('/<short_code>')
def redirect_to_url(short_code):
    url = URL.query.filter_by(short_code=short_code).first_or_404()
    
    # Record visit
    user_agent = parse(request.user_agent.string)
    ip_info = get_ip_details(request.remote_addr)
    
    visit = Visit(
        url=url,
        ip_address=request.remote_addr,
        browser=f"{user_agent.browser.family} {user_agent.browser.version_string}",
        os=f"{user_agent.os.family} {user_agent.os.version_string}",
        country=ip_info['country'],
        city=ip_info['city'],
        region=ip_info['region']
    )
    db.session.add(visit)
    db.session.commit()
    
    return redirect(url.original_url)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('admin'))
            
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/admin')
@login_required
def admin():
    urls = URL.query.all()
    return render_template('admin.html', urls=urls)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create admin user if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password_hash=generate_password_hash('admin123')  # Change this password
            )
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True,host='0.0.0.0')