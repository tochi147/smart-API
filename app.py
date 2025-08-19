from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS

app = Flask(__name__)

# ✅ Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://smart_edge_user:uhyqP7CNwto9FVOllYBmQfCmfymRn52p@dpg-d2hs2uruibrs73djpbu0-a.oregon-postgres.render.com/smart_edge"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'yoursecretkey'  # ⚠️ Change this in production!

# ✅ Enable CORS for all routes
CORS(app)

# ✅ Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# ✅ User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# ✅ Create tables (only runs once at startup)
with app.app_context():
    db.create_all()

# ✅ Register endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400

    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# ✅ Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    user = User.query.filter_by(username=data['username']).first()
    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401

    access_token = create_access_token(identity=user.username)
    return jsonify({'token': access_token}), 200

# ✅ Protected route
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({'message': f'Hello {current_user}, you have accessed a protected route!'}), 200

if __name__ == '__main__':
    app.run(debug=True)
