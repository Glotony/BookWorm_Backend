from flask import Flask, request, send_file, jsonify, redirect, session, url_for, send_from_directory
from flask_cors import CORS
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import uuid
import jwt
import datetime
import os
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

load_dotenv()

# ----------------------------
# Flask Setup
# ----------------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")
CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": "*"}})

# ----------------------------
# MongoDB Configuration
# ----------------------------
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "PdfDb")
app.config["MONGO_URI"] = f"mongodb://localhost:27017/{MONGO_DB_NAME}"
app.config["UPLOAD_FOLDER"] = os.getenv("UPLOAD_FOLDER", "UPLOADS")
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])

mongo = PyMongo(app)

# ----------------------------
# OAuth Setup
# ----------------------------
oauth = OAuth(app)

# Discord OAuth
discord = oauth.register(
    name='discord',
    client_id=os.getenv("DISCORD_CLIENT_ID"),
    client_secret=os.getenv("DISCORD_CLIENT_SECRET"),
    access_token_url='https://discord.com/api/oauth2/token',
    authorize_url='https://discord.com/api/oauth2/authorize?prompt=login',
    api_base_url='https://discord.com/api/',
    client_kwargs={'scope': 'identify email'}
)

# Google OAuth with OpenID Connect
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# ----------------------------
# JWT Helper
# ----------------------------


def generate_token(user_id):
    return jwt.encode({
        "user_id": str(user_id),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.secret_key, algorithm="HS256")


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("token")
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        try:
            decoded = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            user = mongo.db.users.find_one(
                {"_id": ObjectId(decoded["user_id"])})
            if not user:
                return jsonify({"message": "User not found!"}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token!"}), 401
        return f(user, *args, **kwargs)
    return decorated


def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated(user, *args, **kwargs):
            if user.get("role", "user") not in roles:
                return jsonify({"message": "Forbidden: insufficient permissions"}), 403
            return f(user, *args, **kwargs)
        return decorated
    return decorator

# ----------------------------
# Health Check
# ----------------------------


@app.route("/", methods=["GET"])
def api_root():
    return jsonify({"message": "PDF Manager API is running"}), 200

# ----------------------------
# OAuth Routes
# ----------------------------


@app.route("/api/login/discord")
def login_discord():
    return discord.authorize_redirect(url_for("callback_discord", _external=True))


@app.route("/api/callback/discord")
def callback_discord():
    token = discord.authorize_access_token()
    userinfo = discord.get("users/@me").json()
    email = userinfo.get("email") or f"{userinfo['id']}@discord.local"
    user = mongo.db.users.find_one({"email": email})
    if not user:
        user = {
            "name": userinfo["username"],
            "email": email,
            "provider": "discord",
            "provider_id": userinfo["id"],
            "picture": f"https://cdn.discordapp.com/avatars/{userinfo['id']}/{userinfo['avatar']}.png",
            "role": "user"
        }
        mongo.db.users.insert_one(user)
        user = mongo.db.users.find_one({"email": email})
    jwt_token = generate_token(user["_id"])
    response = redirect(f'{os.getenv("FRONTEND_URL", "/")}/dashboard.html')
    response.set_cookie("token", jwt_token, httponly=True, samesite='Lax')
    return response


@app.route("/api/login/google")
def login_google():
    return google.authorize_redirect(url_for("callback_google", _external=True))


@app.route("/api/callback/google")
def callback_google():
    # This gets the token response
    token = google.authorize_access_token()

    # Parse id_token with nonce=None if you don't use it
    id_info = google.parse_id_token(token, nonce=None)

    email = id_info.get("email")
    user = mongo.db.users.find_one({"email": email})

    if not user:
        user = {
            "name": id_info.get("name"),
            "email": email,
            "provider": "google",
            "provider_id": id_info.get("sub"),
            "picture": id_info.get("picture"),
            "role": "user"
        }
        mongo.db.users.insert_one(user)
        user = mongo.db.users.find_one({"email": email})

    jwt_token = generate_token(user["_id"])
    response = redirect(f'{os.getenv("FRONTEND_URL", "/")}/dashboard.html')
    response.set_cookie("token", jwt_token, httponly=True, samesite='Lax')
    return response

# ----------------------------
# Registration / Login / Logout
# ----------------------------


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.json
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    if not name or not email or not password:
        return jsonify({"message": "Name, email, and password are required!"}), 400
    if mongo.db.users.find_one({"email": email}):
        return jsonify({"message": "Email already exists!"}), 400
    hashed_password = generate_password_hash(password)
    mongo.db.users.insert_one({
        "name": name,
        "email": email,
        "password": hashed_password,
        "role": "user"
    })
    return jsonify({"message": "Registration successful!"}), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"message": "Email and password are required."}), 400
    user = mongo.db.users.find_one({"email": email})
    if not user or not check_password_hash(user.get("password", ""), password):
        return jsonify({"message": "Invalid credentials!"}), 401
    token = generate_token(user["_id"])
    response = jsonify({"message": "Login successful!"})
    response.set_cookie("token", token, httponly=True, samesite='Lax')
    return response


@app.route("/api/logout", methods=["POST"])
def logout():
    try:
        session.clear()
        response = jsonify({"message": "Logged out successfully"})
        response.set_cookie("token", "", expires=0)
        return response, 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ----------------------------
# PDF Library - Global for All Users
# ----------------------------
@app.route("/api/dashboard", methods=["GET"])
@token_required
def api_dashboard(current_user):
        pdfs = mongo.db.pdfs.find({})
        pdfs_list = [{
            "filename": pdf["filename"],
            "original_filename": pdf["original_filename"],
            "id": str(pdf["_id"]),
            "uploaded_by": pdf.get("user_id")
        } for pdf in pdfs]
        return jsonify({"user": current_user, "pdfs": pdfs_list})


@app.route("/api/upload", methods=["POST"])
@token_required
@role_required(["admin", "moderator"])
def upload_pdf(current_user):
    if "file" not in request.files:
        return jsonify({"message": "No file provided"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"message": "No selected file"}), 400
    if file and file.filename.endswith(".pdf"):
        unique_id = str(uuid.uuid4())
        ext = os.path.splitext(file.filename)[1]
        filename = f"{unique_id}{ext}"
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)
        mongo.db.pdfs.insert_one({
            "file_id": unique_id,
            "original_filename": secure_filename(file.filename),
            "filename": filename,
            "path": file_path,
            "user_id": str(current_user["_id"]),
            "uploaded_at": datetime.datetime.utcnow()
        })
        return jsonify({"message": "PDF uploaded to library!", "file_id": unique_id, "filename": file.filename}), 201
    return jsonify({"message": "Only PDFs allowed!"}), 400


@app.route("/api/delete/<file_id>", methods=["DELETE"])
@token_required
@role_required(["admin", "moderator"])
def delete_pdf(current_user, file_id):
    pdf = mongo.db.pdfs.find_one({"file_id": file_id})
    if pdf:
        try:
            if os.path.exists(pdf["path"]):
                os.remove(pdf["path"])
        except Exception as e:
            logging.error(f"File delete error: {e}")
        mongo.db.pdfs.delete_one({"file_id": file_id})
        return jsonify({"message": "Deleted PDF!"}), 200
    return jsonify({"message": "PDF not found!"}), 404


@app.route("/api/download/<file_id>", methods=["GET"])
@token_required
def download_pdf(current_user, file_id):
    pdf = mongo.db.pdfs.find_one({"file_id": file_id})
    if pdf and os.path.exists(pdf["path"]):
        return send_file(pdf["path"], as_attachment=True, download_name=pdf["original_filename"])
    return jsonify({"message": "PDF not found!"}), 404

# ----------------------------
# Books - Global for All Users
# ----------------------------


@app.route("/api/books/finished", methods=["GET"])
@token_required
def get_finished_books(current_user):
    books = mongo.db.books.find({"status": "finished"})
    books_list = [{"title": b["title"], "author": b["author"],
                   "finished_at": b.get("finished_at")} for b in books]
    return jsonify(books_list)


@app.route("/api/books/borrowed", methods=["GET"])
@token_required
def get_borrowed_books(current_user):
    books = mongo.db.books.find({"status": "borrowed"})
    books_list = [{"title": b["title"], "author": b["author"]} for b in books]
    return jsonify(books_list)


@app.route("/api/books/add", methods=["POST"])
@token_required
@role_required(["admin", "moderator"])
def add_book(current_user):
    data = request.json
    title = data.get("title")
    author = data.get("author")
    status = data.get("status", "borrowed")
    if not title or not author:
        return jsonify({"message": "Title and author required"}), 400
    mongo.db.books.insert_one({
        "title": title,
        "author": author,
        "status": status,
        "finished_at": datetime.datetime.utcnow() if status == "finished" else None
    })
    return jsonify({"message": "Book added!"}), 201


# ----------------------------
# Static Upload Serve
# ----------------------------
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")


@app.route("/uploads/<path:filename>")
def serve_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# ----------------------------
# Run App
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True, port=3000)
