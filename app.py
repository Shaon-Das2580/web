from flask import Flask, jsonify, request
import pyodbc
from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from dotenv import load_dotenv
import os
import bcrypt
import datetime

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Azure SQL Connection String from environment variable
SQL_CONNECTION_STRING = os.environ.get("SQL_CONNECTION_STRING")

# Azure Blob Storage Connection String from environment variable
BLOB_CONNECTION_STRING = os.environ.get("BLOB_CONNECTION_STRING")

# Initialize Blob Service Client
blob_service_client = BlobServiceClient.from_connection_string(BLOB_CONNECTION_STRING)

@app.route('/')
def home():
    return "Backend without JWT is running!"

# User Signup
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'consumer')

    if role not in ['creator', 'consumer']:
        return jsonify({'error': 'Invalid role specified!'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Users (username, email, password, role) VALUES (?, ?, ?, ?)",
                       (username, email, hashed_password, role))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User registered successfully!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, role FROM Users WHERE email = ?", (email,))
        row = cursor.fetchone()
        conn.close()

        if not row or not bcrypt.checkpw(password.encode('utf-8'), row[2].encode('utf-8')):
            return jsonify({'message': 'Invalid email or password!'}), 401

        return jsonify({'message': 'Login successful!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Upload file to Azure Blob Storage
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    blob_name = file.filename

    try:
        # Get the container client
        container_client = blob_service_client.get_container_client("videos")

        # Upload the file
        container_client.upload_blob(blob_name, file, overwrite=True)

        # Save metadata to SQL
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Videos (title, filepath) VALUES (?, ?)",
                       (blob_name, blob_name))
        conn.commit()
        conn.close()

        return jsonify({'message': f"File '{blob_name}' uploaded successfully!"}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# List all videos with pagination
@app.route('/videos', methods=['GET'])
def list_videos():
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))
    offset = (page - 1) * limit

    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, filepath, upload_date FROM Videos ORDER BY upload_date DESC OFFSET ? ROWS FETCH NEXT ? ROWS ONLY", (offset, limit))
        rows = cursor.fetchall()
        videos = [{'id': row[0], 'title': row[1], 'filepath': row[2], 'upload_date': row[3]} for row in rows]
        conn.close()
        return jsonify(videos), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Add comments to a video
@app.route('/videos/<int:video_id>/comments', methods=['POST'])
def add_comment(video_id):
    data = request.json
    comment = data.get('comment')

    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Comments (video_id, comment) VALUES (?, ?)", (video_id, comment))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Comment added successfully!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/videos/<int:video_id>/rate', methods=['POST'])
def rate_video(video_id):
    data = request.json
    rating = data.get('rating')
    if not (1 <= rating <= 5):
        return jsonify({'error': 'Invalid rating value'}), 400
    try:
        conn = pyodbc.connect(SQL_CONNECTION_STRING)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Ratings (video_id, rating) VALUES (?, ?)", (video_id, rating))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Rating added successfully!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
