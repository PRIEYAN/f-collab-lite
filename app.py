from flask import Flask, url_for, redirect, request, render_template, session, jsonify
from flask_socketio import SocketIO, join_room, emit
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from flask_cors import CORS
from dotenv import load_dotenv
import os, random, string, datetime

# Load environment variables
load_dotenv()

app = Flask(__name__)
oauth = OAuth(app)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app, supports_credentials=True)

app.secret_key = os.getenv('RANDOM_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ---- Database Models ----
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_email = db.Column(db.String(100), db.ForeignKey('user.email'))
    team_name = db.Column(db.String(100), unique=True, nullable=False)
    teamcode = db.Column(db.String(10), unique=True, nullable=False)
    team_slogan = db.Column(db.Text, nullable=True)
    team_bio = db.Column(db.Text, nullable=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teamcode = db.Column(db.String(10), db.ForeignKey('team.teamcode'))
    username = db.Column(db.String(100))
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)




with app.app_context():
    db.create_all()

# ---- Google OAuth Setup ----
google = oauth.register(
    name='google',
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    api_base_url='https://www.googleapis.com/oauth2/v3/',
    client_kwargs={'scope': 'openid profile email'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
)

def generate_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

# ---- Routes ----
@app.route('/')
def home():
    if session.get('auth'):
        return redirect(url_for('front'))
    return render_template('Home.html')

@app.route('/google')
def google_login():
    redirect_uri = url_for("authorize_google", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/authorize/google", methods=['GET', 'POST'])
def authorize_google():
    token = google.authorize_access_token()
    resp = google.get("userinfo")
    user_info = resp.json()
    email = user_info.get("email")
    
    if email:
        existing_user = User.query.filter_by(email=email).first()
        if not existing_user:
            new_user = User(username=user_info.get("given_name"), email=email)
            db.session.add(new_user)
            db.session.commit()
        
        session['auth'] = True
        session['email'] = email
        session['username'] = user_info.get("given_name")

    return redirect(url_for('front'))

@app.route('/front')
def front():
    if not session.get('auth'):
        return redirect(url_for('home'))

    return render_template('Front.html', username=session.get('username'))

@app.route('/joinExistingTeam', methods=['POST', 'GET'])
def join_existing_team():
    if not session.get('auth'):
        return redirect(url_for('home'))

    if request.method == 'POST':
        teamcode = request.form.get('teamcode')
        existing_team = Team.query.filter_by(teamcode=teamcode).first()

        if existing_team:
            # Redirect to the correct team name
            return redirect(url_for('room', team_name=existing_team.team_name))
        else:
            return render_template('jointeam.html', message="Invalid team code. Please try again.")

    return render_template('jointeam.html', message=None)

@app.route('/TeamRegistration', methods=['POST', 'GET'])
def team_registration():
    if not session.get('auth'):
        return redirect(url_for('home'))

    if request.method == 'POST':
        team_name = request.form.get('teamName')
        slogan = request.form.get("slogan")
        bio = request.form.get("bio")

        # Check if team name already exists
        if Team.query.filter_by(team_name=team_name).first():
            return render_template("register.html", message="Team name already exists")

        teamcode = generate_code()
        admin_email = session.get('email')

        if not admin_email:
            return redirect(url_for('home'))

        new_team = Team(
            admin_email=admin_email,
            team_name=team_name,
            teamcode=teamcode,
            team_slogan=slogan,
            team_bio=bio
        )

        db.session.add(new_team)
        db.session.commit()

        # Redirect to the newly created team's page
        return redirect(url_for('room', team_name=team_name))
    
    return render_template('register.html', message=None)


active_teams = {}  # Dictionary to track active users in each team

@app.route('/community/<team_name>')
def room(team_name):
    if not session.get('auth'):
        return redirect(url_for('home'))

    room_data = Team.query.filter_by(team_name=team_name).first()
    if not room_data:
        return redirect(url_for('team_registration'))

    teamcode = room_data.teamcode
    team_messages = Message.query.filter_by(teamcode=teamcode).order_by(Message.timestamp.asc()).all()

    # Get active members from dictionary (default to empty list)
    team_members = active_teams.get(teamcode, [])

    return render_template('project.html', 
                           teamcode=teamcode, 
                           team_leader=room_data.team_name, 
                           team_members=team_members, 
                           bio=room_data.team_bio, 
                           messages=team_messages)





# ---- WebSockets (SocketIO) ----
@socketio.on('join')
def handle_join(data):
    room = data['room']
    username = session.get('username')

    if username:
        if room not in active_teams:
            active_teams[room] = []  # Initialize list if room is empty

        if username not in active_teams[room]:
            active_teams[room].append(username)  # Add user to active list

    join_room(room)
    emit('receive_message', {'username': 'System', 'message': f'{username} joined {room}'}, room=room)

# ✅ FIXED `/joinTeam` route to match request URL
@app.route('/joinTeam')
def join_team():
    return redirect(url_for('join_existing_team'))

@socketio.on('send_message')
def handle_message(data):
    room = data['room']
    message = data['message']
    email = session.get('email')

    if email:
        user = User.query.filter_by(email=email).first()
        if user:
            new_message = Message(teamcode=room, username=user.username, message=message)
            db.session.add(new_message)
            db.session.commit()
            
            emit('receive_message', {'username': user.username, 'message': message}, room=room)

@app.route('/todolist')
def todolist():
    if not session.get('auth'):
        return redirect(url_for('home'))
    return render_template('todolist.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


if __name__ == "__main__":
    socketio.run(app, debug=True, port=5050)
