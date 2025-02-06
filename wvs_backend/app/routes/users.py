from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app.models import User
from app import db

bp = Blueprint('users', __name__)

@bp.route('/register', methods=['POST'])
def register():
    try:
        username = request.json.get('username')
        password = request.json.get('password')
        email = request.json.get('email')
        
        if not username or not password or not email:
            return jsonify({'error': 'All fields are required'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already taken'}), 400
            
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'message': 'User created successfully'}), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@bp.route('/login', methods=['POST'])
def login():
    try:
        username = request.json.get('username')
        password = request.json.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Missing credentials'}), 400
            
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid credentials'}), 401
            
        access_token = create_access_token(identity=username)
        return jsonify({
            'access_token': access_token,
            'username': username
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    return jsonify({
        'username': user.username,
        'email': user.email,
        'created_on': user.created_on.isoformat()
    }), 200

@bp.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    current_user = User.query.filter_by(username=get_jwt_identity()).first()
    
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    users = User.query.all()
    users_data = [{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'created_on': user.created_on.isoformat()
    } for user in users]
    
    return jsonify(users_data), 200