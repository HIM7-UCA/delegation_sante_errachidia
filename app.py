from flask import Flask, request, redirect, url_for, render_template,flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from flask_bootstrap import Bootstrap

app = Flask(__name__)
Bootstrap(app)

# Initialize the LoginManager once
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Specify the login view here


app.config['SECRET_KEY'] = 'HICHAM'
app.config['RESPONSE_FOLDER'] = 'responses'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/delegation'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'gif'}
db = SQLAlchemy(app)

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
# Initialize the database
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/statistics')
def statistics():
    return render_template('statistics.html')


@app.route('/communication')
def communication():
    news_items = News.query.all()
    return render_template('communication.html', news_items=news_items)

@app.route('/news/<int:news_id>')
def news_detail(news_id):
    news_item = News.query.get_or_404(news_id)
    return render_template('news_detail.html', news=news_item)
@app.route('/add', methods=['GET', 'POST'])
def add_news():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    if request.method == 'POST':
        title = request.form['title']
        header = request.form['header']
        content = request.form['content']
        image = request.files['image']

        # Handle file upload
        if image and allowed_file(image.filename):
            filename = f"image{News.query.count() + 1}.{image.filename.rsplit('.', 1)[1].lower()}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(filepath)
        else:
            filename = None

        news_item = News(title=title, header=header, content=content, image=filename)
        db.session.add(news_item)
        db.session.commit()
        return redirect(url_for('communication'))

    return render_template('add_news.html')
# Route pour éditer une news
@app.route('/edit_news/<int:news_id>', methods=['GET', 'POST'])
@login_required
def edit_news(news_id):
    news_item = News.query.get_or_404(news_id)
    
    # Vérification si l'utilisateur est un administrateur
    if current_user.role != 'admin':
        flash("You don't have permission to edit this news.", "danger")
        return redirect(url_for('news_detail', news_id=news_id))
    
    if request.method == 'POST':
        news_item.title = request.form['title']
        news_item.header = request.form['header']
        news_item.content = request.form['content']
        image = request.files['image']
        
        if image and allowed_file(image.filename):
            filename = f"image{news_id}.{image.filename.rsplit('.', 1)[1].lower()}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(filepath)
            news_item.image = filename

        db.session.commit()
        flash("News updated successfully!", "success")
        return redirect(url_for('news_detail', news_id=news_item.id))

    return render_template('edit_news.html', news=news_item)

# Route pour supprimer une news
@app.route('/delete_news/<int:news_id>', methods=['POST'])
@login_required
def delete_news(news_id):
    news_item = News.query.get_or_404(news_id)
    db.session.delete(news_item)
    db.session.commit()
    return redirect(url_for('communication'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect_based_on_role()
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user :
            login_user(user)
            return redirect_based_on_role()
        else:
            return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match")

        password = password

        # Create a new user with the default role 'user'
        new_user = User(username=username, email=email, password=password, role='user')
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def redirect_based_on_role():
    if current_user.role == 'user':
        return redirect(url_for('user_home'))
    elif current_user.role == 'hr':
        return redirect(url_for('hr_home'))
    elif current_user.role == 'admin':
        return redirect(url_for('communication'))
    else:
        return "Invalid role for user."

# Define models
    
class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image = db.Column(db.String(255))
    title = db.Column(db.String(255), nullable=False)
    header = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.Enum('user', 'hr', 'admin'), nullable=False)
    requests = db.relationship('Request', backref='user', lazy=True)


class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    demand_file = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Enum('pending', 'responded'), default='pending')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    responses = db.relationship('Response', backref='request', uselist=False, lazy=True)

class Response(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    response_file = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

# Ensure the upload and response directories exist
for folder in [app.config['UPLOAD_FOLDER'], app.config['RESPONSE_FOLDER']]:
    if not os.path.exists(folder):
        os.makedirs(folder)

@app.route('/user')
@login_required
def user_home():
    if current_user.role != 'user':
        return redirect(url_for('login'))
    requests = Request.query.filter_by(user_id=current_user.id).all()
    return render_template('user_home.html', requests=requests)

@app.route('/download/<int:request_id>')
@login_required  # Ensures only logged-in users can access this route
def download_request(request_id):
    request_record = Request.query.get(request_id)
    if request_record and request_record.status == 'responded' and request_record.user_id == current_user.id:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], request_record.demand_file)
        return send_from_directory(directory=app.config['UPLOAD_FOLDER'],
                                   path=request_record.demand_file,
                                   as_attachment=False)
    else:
        return "File not found or request not responded.", 404

@app.route('/user/upload', methods=['GET', 'POST'])
@login_required
def upload_request():
    if current_user.role != 'user':
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_request = Request(user_id=current_user.id, demand_file=filename)
            db.session.add(new_request)
            db.session.commit()
            return redirect(url_for('user_home'))
    return render_template('upload_request.html')

@app.route('/hr')
@login_required
def hr_home():
    if current_user.role != 'hr':
        return redirect(url_for('login'))
    requests = Request.query.all()
    responses = Response.query.all()
    requests_with_responses = []
    for request_item in requests:
        demand = request_item.demand_file
        response = None
        for response_item in responses:
            if response_item.request_id == request_item.id:
                response = response_item.response_file
                break
        requests_with_responses.append({'user': request_item.user.username, 'demand': demand, 'response': response})
    return render_template('hr_home.html', requests=requests_with_responses)

@app.route('/hr/respond/<demand>', methods=['GET', 'POST'])
@login_required
def respond_request(demand):
    if current_user.role != 'hr':
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file:
            response_filename = f'response_{demand}'
            file.save(os.path.join(app.config['RESPONSE_FOLDER'], response_filename))
            request_item = Request.query.filter_by(demand_file=demand).first()
            if request_item:
                new_response = Response(request_id=request_item.id, response_file=response_filename)
                db.session.add(new_response)
                db.session.commit()
                request_item.status = 'responded'
                db.session.commit()
            return redirect(url_for('hr_home'))
    return render_template('respond_request.html', demand=demand)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/responses/<filename>')
def response_file(filename):
    return send_from_directory(app.config['RESPONSE_FOLDER'], filename)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)

