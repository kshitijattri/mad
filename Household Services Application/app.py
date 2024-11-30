from flask import Flask, render_template, request, redirect, session, flash, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import db, Customer, Provider, Service, ServiceRequest, Admin 
import os, bcrypt

UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt'} 

app = Flask(__name__)

app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600 

db.init_app(app) 
jwt = JWTManager(app)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


with app.app_context():
    db.create_all()

    if not Admin.query.filter_by(username='admin').first():
        admin_user = Admin(username='admin', password='admin')  
        db.session.add(admin_user)
        db.session.commit()


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/customer_login', methods=['GET', 'POST'])
def customer_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = Customer.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            session['username'] = user.username
            session['customer_id'] = user.id
            flash('Login successful!', 'success')
            return redirect('/customer_dashboard')
        flash('Invalid username or password', 'error')

    return render_template('customer_login.html')


@app.route('/customer_registration', methods=['GET', 'POST'])
def customer_registration():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']

        if Customer.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('customer_registration.html')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        new_customer = Customer(name=name, username=username, password=hashed_password)
        db.session.add(new_customer)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect('/customer_login')

    return render_template('customer_registration.html')


@app.route('/customer_dashboard', methods=['GET'])
def customer_dashboard():
    customer_id = session.get('customer_id')
    if not customer_id:
        flash('Please log in first.', 'error')
        return redirect('/customer_login')

    customer = Customer.query.get(customer_id)
    return render_template('customer_dashboard.html', customer=customer)


@app.route('/create_servicerequest', methods=['GET', 'POST'])
def create_servicerequest():
    customer_id = session.get('customer_id')
    if not customer_id:
        flash('Please log in to create a service request.', 'error')
        return redirect('/customer_login')

    if request.method == 'POST':
        service_id = request.form.get('service_id')
        service_address = request.form['service_address']
        description = request.form['description']
        preferred_time = request.form['preferred_time']

        service = Service.query.get(service_id)
        if not service:
            flash('Invalid service selected.', 'error')
            return redirect('/create_servicerequest')

        new_request = ServiceRequest(
            service_id=service_id,
            customer_id=customer_id,
            provider_id=None,
            time=preferred_time,
            service_address=service_address,
            description=description,
            service_type=service.name
        )
        db.session.add(new_request)
        db.session.commit()
        flash('Service request created successfully!', 'success')
        return redirect('/my_bookings')

    services = Service.query.all()
    return render_template('create_servicerequest.html', services=services)


@app.route('/my_bookings', methods=['GET'])
def my_bookings():
    customer_id = session.get('customer_id')
    if not customer_id:
        flash('Please log in to view your bookings.', 'error')
        return redirect('/customer_login')

    bookings = ServiceRequest.query.filter_by(customer_id=customer_id).all()
    return render_template('my_bookings.html', bookings=bookings)


@app.route('/delete_service_request/<int:service_request_id>', methods=['POST'])
def delete_service_request(service_request_id):
    service_request = ServiceRequest.query.get_or_404(service_request_id)
    db.session.delete(service_request)
    db.session.commit()
    flash('Service request deleted successfully!', 'success')
    return redirect('/my_bookings')

@app.route('/close_service_request/<int:service_request_id>', methods=['POST'])
def close_service_request(service_request_id):
    service_request = ServiceRequest.query.get_or_404(service_request_id)

    service_request.status = 'Closed'
    db.session.commit()

    flash('Service request closed successfully. Please leave a review for the provider.', 'success')


    return redirect(url_for('leave_review', service_request_id=service_request_id))


@app.route('/leave_review/<int:service_request_id>', methods=['GET', 'POST'])
def leave_review(service_request_id):
    service_request = ServiceRequest.query.get_or_404(service_request_id)

    if service_request.status != 'Closed':
        flash('This service request is not yet closed.', 'error')
        return redirect('/customer_dashboard')

    if request.method == 'POST':
        review_text = request.form['review']
        rating = request.form.get('rating')


        service_request.review = review_text
        service_request.rating = rating
        db.session.commit()

        flash('Thank you for your review!', 'success')
        return redirect('/customer_dashboard')

    return render_template('leave_review.html', service_request=service_request)


@app.route('/accept_service_request/<int:request_id>', methods=['POST'])
def accept_service_request(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)

    if service_request.provider_id is not None:
        
        flash('This service request has already been accepted by another provider.', 'error')
        return redirect('/provider_servicerequests')  

    
    provider = Provider.query.filter_by(username=session['username']).first()

    if provider:
        
        if provider.blocked:
            flash('You are blocked and cannot accept service requests.', 'error')
            return redirect('/provider_servicerequests') 

        
        service_request.provider_id = provider.id
        service_request.status = 'Accepted'
        db.session.commit()

        flash('Service request accepted successfully!', 'success')
    else:
        flash('Provider not found or not logged in', 'error')

    return redirect('/provider_servicerequests')

@app.route('/customer_logout', methods=['GET'])
def customer_logout():
    session.pop('customer_id', None)
    flash('Logged out successfully!', 'success')
    return redirect('/customer_login')


@app.route('/provider_login', methods=['GET', 'POST'])
def provider_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        provider = Provider.query.filter_by(username=username).first()
        if provider and bcrypt.checkpw(password.encode('utf-8'), provider.password.encode('utf-8')):
            session['username'] = provider.username
            session['provider_id'] = provider.id
            flash('Login successful!', 'success')
            return redirect('/provider_dashboard')
        flash('Invalid username or password', 'error')

    return render_template('provider_login.html')



@app.route('/provider_registration', methods=['GET', 'POST'])
def provider_registration():
    if request.method == 'POST':

        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        service_type = request.form['service_type']
        description = request.form['description']

        existing_user = Provider.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'error')
            return render_template('provider_registration.html', name=name, username=username, service_type=service_type, description=description)

        if 'document' not in request.files or request.files['document'].filename == '':
            flash('Please upload a document for verification.', 'error')
            return render_template('provider_registration.html', name=name, username=username, service_type=service_type, description=description)

        file = request.files['document']


        if not allowed_file(file.filename):
            flash('Invalid file type. Allowed types are PDF, DOCX, or TXT.', 'error')
            return render_template('provider_registration.html', name=name, username=username, service_type=service_type, description=description)


        filename = secure_filename(file.filename)
        upload_folder = app.config.get('UPLOAD_FOLDER', 'static/uploads')
        os.makedirs(upload_folder, exist_ok=True)  
        filepath = os.path.join(upload_folder, filename)
        file.save(filepath)

        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        
        new_provider = Provider(
            name=name,
            username=username,
            password=hashed_password,
            service_type=service_type,
            description=description,
            document_filename=filename
        )
        db.session.add(new_provider)
        db.session.commit()

        flash('Registration successful! Please wait for admin verification.', 'success')
        return redirect('/provider_login')

    
    services = Service.query.all()
    return render_template('provider_registration.html', services=services)


@app.route('/provider_dashboard', methods=['GET'])
def provider_dashboard():
    provider_id = session.get('provider_id')
    if not provider_id:
        flash('Please log in first.', 'error')
        return redirect('/provider_login')

    provider = Customer.query.get(provider_id)
    return render_template('provider_dashboard.html', provider=provider, active_page = 'home')

@app.route('/provider_servicerequests')
def provider_servicerequests():
    if 'username' in session:
        provider = Provider.query.filter_by(username=session['username']).first()

        if provider is None:
            flash('Please log in as a provider first.', 'error')
            return redirect('/provider_login')
        
        if not provider.verified:
            flash('Your account is not verified by an admin. Please wait for verification.', 'error')
            return redirect('/provider_dashboard') 

    
        service_requests = ServiceRequest.query.filter_by(service_type=provider.service_type).all()
        return render_template('provider_servicerequests.html', service_requests=service_requests, active_page = 'service_requests')

    flash('You must be logged in to view service requests.', 'error')
    return redirect('/provider_login')

@app.route('/provider_logout', methods=['GET'])
def provider_logout():
    session.pop('username', None)
    flash('Logged out successfully!', 'success')
    return redirect('/provider_login')



@app.route('/api/admin_login', methods=['POST'])
def api_admin_login():

    data = request.get_json()  
    username = data.get('username')
    password = data.get('password')

    user = Admin.query.filter_by(username=username).first()
    if user and user.check_password(password):

        access_token = create_access_token(identity={"id": user.id, "username": user.username})
        return jsonify({"access_token": access_token}), 200  

    return jsonify({"msg": "Invalid username or password"}), 401

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

    
        response = app.test_client().post('/api/admin_login', json={
            'username': username,
            'password': password
        })

        if response.status_code == 200:
            
            token_data = response.get_json()
            session['access_token'] = token_data['access_token']
            flash('Login successful', 'success')
            return redirect('/admin_dashboard')

        flash('Invalid username or password', 'error')

    return render_template('admin_login.html')

@app.route('/api/admin_dashboard', methods=['GET'])
@jwt_required()  
def api_admin_dashboard():
    current_user = get_jwt_identity()  
    user = Admin.query.filter_by(id=current_user["id"]).first()

    if user:
        return jsonify({"id": user.id, "username": user.username}), 200

    return jsonify({"msg": "User not found"}), 404

@app.route('/admin_dashboard', methods=['GET'])
def admin_dashboard():
    token = session.get('access_token') 

    if not token:
        flash('Please log in first', 'error')
        return redirect('/admin_login')

    headers = {"Authorization": f"Bearer {token}"}
    
    
    response = app.test_client().get('/api/admin_dashboard', headers=headers)
    
    if response.status_code == 200:
        user_data = response.get_json()
        return render_template('admin_dashboard.html', user=user_data, active_page='home')
    else:
        flash('Session expired or unauthorized access. Please log in again.', 'error')
        return redirect('/admin_login')
    

@app.route('/customer_admin')
def customer_admin():
    customers = Customer.query.all()
    return render_template('customer_admin.html', customers=customers, active_page='customers')

@app.route('/view_customer/<int:customer_id>')
def view_customer(customer_id):
    
    customer = Customer.query.get_or_404(customer_id)
    
    return render_template('view_customer.html', customer=customer)

@app.route('/block_customer/<int:customer_id>', methods=['POST'])
def block_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    customer.blocked = True  
    db.session.commit()
    flash(f'Customer {customer.name} has been blocked.', 'success')
    return redirect('/customer_admin')

@app.route('/unblock_customer/<int:customer_id>', methods=['POST'])
def unblock_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    customer.blocked = False 
    db.session.commit()
    flash(f'Customer {customer.name} has been unblocked.', 'success')
    return redirect('/customer_admin')

@app.route('/provider_admin')
def provider_admin():
    providers = Provider.query.all()
    return render_template('provider_admin.html', providers=providers, active_page='providers')

@app.route('/admin_verify_provider/<int:provider_id>', methods=['POST'])
def admin_verify_provider(provider_id):
    provider = Provider.query.get_or_404(provider_id)


    provider.verified = True
    db.session.commit()
    
    flash('Provider verified successfully!', 'success')
    return redirect('/provider_admin')

@app.route('/view_provider/<int:provider_id>')
def view_provider(provider_id):

    provider = Provider.query.get_or_404(provider_id)
    
 
    document_filename = provider.document_filename if provider.document_filename else "No document uploaded"
    

    return render_template('view_provider.html', provider=provider, document_filename=document_filename)

@app.route('/block_provider/<int:provider_id>', methods=['POST'])
def block_provider(provider_id):
    provider = Provider.query.get_or_404(provider_id)
    provider.blocked = True  
    db.session.commit()
    flash(f'Provider {provider.name} has been blocked.', 'success')
    return redirect('/provider_admin')

@app.route('/unblock_provider/<int:provider_id>', methods=['POST'])
def unblock_provider(provider_id):
    provider = Provider.query.get_or_404(provider_id)
    provider.blocked = False 
    db.session.commit()
    flash(f'Provider {provider.name} has been unblocked.', 'success')
    return redirect('/provider_admin')

@app.route('/service_admin')
def service_admin():
    services = Service.query.all()
    return render_template('service_admin.html', services=services, active_page='services')

@app.route('/create_service', methods=['GET', 'POST'])
def create_service():
    if request.method == 'POST':
        
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        

        new_service = Service(name=name, description=description, price=price)
        db.session.add(new_service)
        db.session.commit()
        flash('Service Created.', 'success')
        return redirect('/service_admin')

    return render_template('create_service.html')


@app.route('/update_service/<int:service_id>', methods=['GET', 'POST'])
def update_service(service_id):
    service = Service.query.get_or_404(service_id)
    
    if request.method == 'POST':
        service.name = request.form['name']
        service.description = request.form['description']
        service.price = request.form['price']
        db.session.commit()
        flash('Service updated successfully!', 'success')
        return redirect('/service_admin')
    
    return render_template('update_service.html', service=service)

@app.route('/delete_service/<int:service_id>', methods=['POST'])
def delete_service(service_id):
    service = Service.query.get_or_404(service_id)
    db.session.delete(service)
    db.session.commit()
    flash('Service deleted successfully!', 'success')
    return redirect('/service_admin')


@app.route('/update_customer/<int:customer_id>', methods=['GET', 'POST'])
def update_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    if request.method == 'POST':
        customer.name = request.form['name']
        customer.username = request.form['username']
        
        db.session.commit()
        flash('Customer updated successfully!', 'success')
        return redirect('/customer_admin')
    
    return render_template('update_customer.html', customer=customer)


@app.route('/servicerequest_admin')
def servicerequest_admin():
    if 'username' in session:
        customer = Customer.query.filter_by().first()
        
        service_requests = ServiceRequest.query.filter_by().all()
        return render_template('servicerequest_admin.html', service_requests=service_requests, active_page = 'service requests')

    return redirect('/servicerequest_admin.html')

@app.route('/view_service_request/<int:service_request_id>')
def view_service_request(service_request_id):
    
    service_request = ServiceRequest.query.get_or_404(service_request_id)
    
    
    return render_template('view_service_request.html', service_request=service_request)

@app.route('/admin_logout')
def admin_logout():
    session.pop('access_token', None)
    flash('Logged out successfully', 'success')
    return redirect('/admin_login')

if __name__ == '__main__':
    app.run(debug=True)
