from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import random
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # salainen avain sessioiden suojaamiseen
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Istunnon aikakatkaisu
app.config['SESSION_PERMANENT'] = True

# SocketIO sallii kaikki alkuperät
socketio = SocketIO(app, cors_allowed_origins="*")

# Simuloitu tietokanta käyttäjille
users_db = {}
users = {}

@app.route('/')
def index():
    if 'username' in session:
        return render_template('chat.html')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None  # Virheviesti, jos kirjautuminen epäonnistuu
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = users_db.get(username)
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            error = 'Invalid username or password'  # Virheviesti

    # Lähetetään virheviesti takaisin lomakkeelle
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users_db:
            return 'Username already exists'
        
        hashed_password = generate_password_hash(password)
        users_db[username] = {'password': hashed_password}
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# SocketIO-tapahtumat
@socketio.on("connect")
def handle_connect():
    print(f"New connection from {request.sid}")
    if 'username' not in session:
        print("User not logged in, disconnecting")
        return False  # estetään yhteys, jos käyttäjä ei ole kirjautunut
    
    username = session['username']
    gender = random.choice(["girl","boy"])
    avatar_url = f"https://avatar.iran.liara.run/public/{gender}?username={username}"
    
    users[request.sid] = {"username": username, "avatar": avatar_url}
    
    emit("user_joined", {"username": username, "avatar": avatar_url}, broadcast=True)
    emit("set_username", {"username": username})

@socketio.on("disconnect")
def handle_disconnect():
    user = users.pop(request.sid, None)
    if user:
        emit("user_left", {"username": user["username"]}, broadcast=True)

@socketio.on("send_message")
def handle_message(data):
    user = users.get(request.sid)
    if user:
        emit("new_message", {
            "username": user["username"],
            "avatar": user["avatar"],
            "message": data["message"]
        }, broadcast=True)

@socketio.on("update_username")
def handle_update_username(data):
    old_username = users[request.sid]["username"]
    new_username = data["username"]
    users[request.sid]["username"] = new_username

    emit("username_updated", {
        "old_username": old_username,
        "new_username": new_username
    }, broadcast=True)





if __name__ == "__main__":
    socketio.run(app)
