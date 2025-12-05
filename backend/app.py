# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import json
from bson import ObjectId
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask_socketio import SocketIO, join_room, leave_room
from math import radians, sin, cos, sqrt, atan2

# ---------------------- App Setup ----------------------
app = Flask(__name__)

# ⚠️ CHANGE THIS IN PRODUCTION (use env var ideally)
app.config['SECRET_KEY'] = 'supersecretjwtkey'

# ---------------------- CORS & Socket.IO ---------------
# Allow all origins (simple for project/demo). You can later restrict to your domain.
CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)

socketio = SocketIO(
    app,
    cors_allowed_origins="*"
)

# ---------------------- Security Headers ---------------
@app.after_request
def add_security_headers(response):
    # Example Permissions-Policy limiting powerful features
    response.headers['Permissions-Policy'] = (
        "geolocation=(self), "
        "camera=(), "
        "microphone=(), "
        "payment=(), "
        "usb=()"
    )
    return response

# ---------------------- MongoDB ------------------------
# ⚠️ PASTE YOUR OWN MONGO URI HERE
MONGO_URI = "YOUR_MONGODB_ATLAS_URI_HERE"
client = MongoClient(MONGO_URI, tls=True)
db = client['CrimeSpot']

users_col = db['users']
crimes_col = db['crimes']
alerts_col = db['alerts']

# ---------------------- Helpers / Auth -----------------
def decode_token(token):
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        print("JWT decode error:", e)
        return None


def token_required(f):
    """Ensures a valid JWT token is provided with the request"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split()
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                token = parts[1]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        data = decode_token(token)
        if not data:
            return jsonify({'message': 'Token is invalid!'}), 401

        current_user = users_col.find_one({'email': data['email']})
        if not current_user:
            return jsonify({'message': 'User not found!'}), 404

        return f(current_user, *args, **kwargs)
    return decorated


def role_required(roles):
    """Restricts route access to specific roles"""
    def decorator(f):
        @wraps(f)
        def wrapper(current_user, *args, **kwargs):
            if current_user.get('role') not in roles:
                return jsonify({'message': 'Access denied'}), 403
            return f(current_user, *args, **kwargs)
        return wrapper
    return decorator


# ---------------------- Utility -----------------------
def serialize_doc(doc):
    """Converts MongoDB ObjectIds and datetime fields to JSON-serializable format"""
    if not doc:
        return None
    doc = dict(doc)
    for key, value in doc.items():
        if isinstance(value, ObjectId):
            doc[key] = str(value)
        elif isinstance(value, datetime):
            doc[key] = value.isoformat()
    return doc


def haversine_km(lat1, lon1, lat2, lon2):
    """Return distance between two lat/lon points in kilometers using Haversine formula."""
    R = 6371.0  # Earth radius in km
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    return R * c


def check_crime_zone(user_lat, user_lng, current_time, radius_km=1.0):
    """
    Checks if user is within a high-crime zone (default radius_km kilometers).
    Returns a list of notification dicts for crimes within the radius.
    Each notification includes computed distance (km).
    """
    crimes = list(crimes_col.find({}))
    notifications = []

    for crime in crimes:
        try:
            # 1) crime['lat'], crime['lng'] (your current format)
            # 2) crime['location'] GeoJSON -> {'type':'Point', 'coordinates':[lng, lat]}
            if 'lat' in crime and 'lng' in crime:
                crime_lat = float(crime['lat'])
                crime_lng = float(crime['lng'])
            else:
                loc = crime.get('location')
                if isinstance(loc, dict) and 'coordinates' in loc:
                    crime_lng = float(loc['coordinates'][0])
                    crime_lat = float(loc['coordinates'][1])
                else:
                    continue

            distance_km = haversine_km(user_lat, user_lng, crime_lat, crime_lng)
            print(f"[DEBUG] Crime '{crime.get('type','unknown')}' at {crime.get('location')} -> distance: {distance_km:.3f} km")

            if distance_km <= radius_km:
                if current_time.hour >= 20 or current_time.hour <= 5:
                    notifications.append({
                        'location': crime.get('location') or f"{crime_lat},{crime_lng}",
                        'message': f'You are in a high-crime zone ({crime.get("type","")}) during night hours.',
                        'lat': crime_lat,
                        'lng': crime_lng,
                        'type': crime.get('type'),
                        'distance_km': round(distance_km, 3)
                    })
                else:
                    notifications.append({
                        'location': crime.get('location') or f"{crime_lat},{crime_lng}",
                        'message': f'You are near a recorded crime ({crime.get("type","")}).',
                        'lat': crime_lat,
                        'lng': crime_lng,
                        'type': crime.get('type'),
                        'distance_km': round(distance_km, 3)
                    })
        except Exception as e:
            print("Error checking crime entry:", e)
            continue

    return notifications


# ---------------------- Routes ------------------------
@app.route('/')
def index():
    return jsonify({'message': '🚨 CrimeSpot Backend Running Successfully!'})


# --------- CORS preflight for /login (optional but safe) ----------
@app.route('/login', methods=['OPTIONS'])
def login_options():
    # Just respond OK; CORS headers are added by flask-cors
    return '', 200


# --------- Register/Login ----------
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'message': 'Bad request'}), 400

    if users_col.find_one({'email': data['email']}):
        return jsonify({'message': 'User already exists'}), 400

    hashed = generate_password_hash(data['password'])
    users_col.insert_one({
        'email': data['email'],
        'password': hashed,
        'role': data.get('role', 'user')
    })

    return jsonify({'message': 'User registered successfully'})


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'message': 'Bad request'}), 400

    user = users_col.find_one({'email': data['email']})
    if not user or not check_password_hash(user['password'], data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode(
        {'email': user['email'], 'exp': datetime.now(timezone.utc) + timedelta(hours=12)},
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )

    role = user.get('role', 'user')
    return jsonify({'token': token, 'role': role})


# --------- Crimes ----------
@app.route('/api/crimes', methods=['GET'])
@token_required
def get_crimes(current_user):
    crimes = [serialize_doc(c) for c in crimes_col.find({})]
    return jsonify(crimes)


@app.route('/api/crimes', methods=['POST'])
@token_required
@role_required(['admin', 'patrol'])
def add_crime(current_user):
    data = request.get_json()
    required = ['location', 'type', 'date', 'lat', 'lng']
    if not data or not all(k in data for k in required):
        return jsonify({'message': 'Missing fields'}), 400

    try:
        data['lat'] = float(data['lat'])
        data['lng'] = float(data['lng'])
    except Exception:
        return jsonify({'message': 'lat and lng must be numbers'}), 400

    crimes_col.insert_one(data)
    return jsonify({'message': 'Crime added successfully'})


@app.route('/api/crimes/<string:loc>', methods=['DELETE'])
@token_required
@role_required(['admin', 'patrol'])
def delete_crime(current_user, loc):
    res = crimes_col.delete_one({'location': loc})
    if res.deleted_count == 0:
        return jsonify({'message': 'No crime found for that location'}), 404
    return jsonify({'message': 'Crime deleted successfully'})


# --------- User location check ----------
@app.route('/api/check-location', methods=['POST'])
@token_required
def check_location(current_user):
    data = request.get_json()
    if not data or 'lat' not in data or 'lng' not in data:
        return jsonify({'message': 'Bad request'}), 400

    try:
        user_lat = float(data['lat'])
        user_lng = float(data['lng'])
    except Exception:
        return jsonify({'message': 'Invalid coordinates'}), 400

    current_time = datetime.now(timezone.utc)
    alerts = check_crime_zone(user_lat, user_lng, current_time, radius_km=1.0)

    for alert in alerts:
        payload = {**alert, 'user': current_user['email']}
        socketio.emit('crime_zone_alert', payload, room='patrols')
        socketio.emit('crime_zone_alert', payload, room='users')

    return jsonify({'alerts': alerts})


# --------- User location update ----------
@app.route('/api/location/update', methods=['POST'])
@token_required
def update_location(current_user):
    """
    Used by frontend after login to:
    - save user's last location
    - check whether the user is in a crime-prone zone
    - emit alerts to patrols (via Socket.IO) if needed
    Accepts:
      { "lat": ..., "lng": ... }
      or { "latitude": ..., "longitude": ... }
    """
    data = request.get_json() or {}
    lat_key = 'lat' if 'lat' in data else ('latitude' if 'latitude' in data else None)
    lng_key = 'lng' if 'lng' in data else ('longitude' if 'longitude' in data else None)

    if not lat_key or not lng_key:
        return jsonify({'message': 'Bad request - missing coordinates'}), 400

    try:
        user_lat = float(data.get(lat_key))
        user_lng = float(data.get(lng_key))
    except (ValueError, TypeError):
        return jsonify({'message': 'Invalid coordinates'}), 400

    # Save last known location for user
    try:
        users_col.update_one(
            {'email': current_user['email']},
            {'$set': {
                'last_location': {
                    'lat': user_lat,
                    'lng': user_lng,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            }}
        )
    except Exception as e:
        print("Failed to save last_location:", e)

    current_time = datetime.now(timezone.utc)
    alerts = check_crime_zone(user_lat, user_lng, current_time, radius_km=1.0)

    payloads = []
    if alerts:
        for alert in alerts:
            payload = {
                'user': current_user.get('email'),
                'location': alert.get('location'),
                'message': alert.get('message'),
                'lat': alert.get('lat'),
                'lng': alert.get('lng'),
                'type': alert.get('type'),
                'distance_km': alert.get('distance_km'),
                'detected_at': current_time.isoformat()
            }
            payloads.append(payload)

        socketio.emit('crime_zone_alert', payloads, room='patrols')
        socketio.emit('crime_zone_alert', payloads, room='users')

        try:
            for payload in payloads:
                alerts_col.insert_one({
                    'type': 'auto_crime_zone_detection',
                    'payload': payload,
                    'timestamp': current_time.isoformat()
                })
        except Exception as e:
            print("Failed to insert auto alert:", e)

    return jsonify({
        'alert': bool(alerts),
        'message': f'{len(alerts)} crime-zone alert(s) detected near your location.',
        'alerts': alerts
    }), 200


# --------- User alert to patrol ----------
@app.route('/api/alert', methods=['POST'])
@token_required
def alert_patrol(current_user):
    data = request.get_json()
    if not data or 'location' not in data or 'message' not in data:
        return jsonify({'message': 'Bad request'}), 400

    alert = {
        'location': data['location'],
        'message': data['message'],
        'lat': data.get('lat'),
        'lng': data.get('lng'),
        'reported_by': current_user['email'],
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

    inserted = alerts_col.insert_one(alert)
    alert['_id'] = str(inserted.inserted_id)

    safe_alert = json.loads(json.dumps(alert, default=str))
    socketio.emit('new_alert', safe_alert, room='patrols')

    return jsonify({'message': 'Alert sent to patrols successfully'})


# ---------------------- Socket.IO events ---------------------
@socketio.on('connect')
def handle_connect(auth):
    token = auth.get('token') if isinstance(auth, dict) else None
    user_info = decode_token(token) if token else None

    if not user_info:
        print("Socket connection with invalid token - disconnecting")
        return False

    email = user_info.get('email')
    user = users_col.find_one({'email': email})
    if not user:
        print("Socket connection for unknown user - disconnecting")
        return False

    role = user.get('role', 'user')
    sid = request.sid
    print(f"Socket connected: sid={sid}, email={email}, role={role}")

    if role == 'patrol':
        join_room('patrols')
    elif role == 'admin':
        join_room('admins')
    else:
        join_room('users')


@socketio.on('disconnect')
def handle_disconnect():
    print('Socket disconnected')


# ---------------------- Run Server -------------------
if __name__ == '__main__':
    # For local development; on Render you use gunicorn with this module
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
