from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
import bcrypt

db = SQLAlchemy()

class CheckPassword:
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

class Customer(db.Model, CheckPassword):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    date_created = db.Column(db.DateTime, default=func.current_timestamp())
    blocked = db.Column(db.Boolean, default=False)

    def __init__(self, username, password, name):
        self.name = name
        self.username = username
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.blocked = False

class Provider(db.Model, CheckPassword):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    date_created = db.Column(db.DateTime, default=func.current_timestamp())
    description = db.Column(db.String(512), nullable=False)
    service_type = db.Column(db.String(32), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    document_filename = db.Column(db.String(200), nullable=True)
    blocked = db.Column(db.Boolean, default=False)

    def __init__(self, username, password, name, description, service_type, document_filename):
        self.name = name
        self.username = username
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.description = description
        self.service_type = service_type
        self.document_filename = document_filename
        self.blocked = False

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(512), nullable=False)
    price = db.Column(db.Float, nullable=False)

    def __init__(self, name, description, price):
        self.name = name
        self.description = description
        self.price = price

class ServiceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('provider.id'), nullable=True)
    date_requested = db.Column(db.DateTime, default=func.current_timestamp())
    time = db.Column(db.String(8), nullable=False)
    service_type = db.Column(db.String(32), nullable=False)
    remarks = db.Column(db.String(512), nullable=True)
    description = db.Column(db.String(512), nullable=True)
    service_address = db.Column(db.String(512), nullable=False)
    status = db.Column(db.String(32), nullable=False, default='Pending')
    rating = db.Column(db.Integer, nullable=True)
    review = db.Column(db.Text, nullable=True)

    def __init__(self, service_id, customer_id, provider_id, time, service_type, service_address, status='Pending', remarks=None, description=None, review=None, rating=None):
        self.service_id = service_id
        self.customer_id = customer_id
        self.provider_id = provider_id
        self.time = time
        self.service_type = service_type
        self.remarks = remarks
        self.description = description
        self.service_address = service_address
        self.status = status
        self.review = review
        self.rating = rating

class Admin(db.Model, CheckPassword):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
