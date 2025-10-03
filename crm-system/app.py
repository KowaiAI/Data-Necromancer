from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from functools import wraps

app = Flask(**name**)
app.config[‘SECRET_KEY’] = os.environ.get(‘SECRET_KEY’, ‘dev-secret-key-change-in-production’)
app.config[‘SQLALCHEMY_DATABASE_URI’] = ‘sqlite:///crm.db’
app.config[‘SQLALCHEMY_TRACK_MODIFICATIONS’] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = ‘login’

# Import models

from models import User, Customer, Lead, Opportunity, Activity, Task, Note

# Import blueprints

from modules.customers import customers_bp
from modules.leads import leads_bp
from modules.opportunities import opportunities_bp
from modules.activities import activities_bp
from modules.tasks import tasks_bp
from modules.analytics import analytics_bp

# Register blueprints

app.register_blueprint(customers_bp, url_prefix=’/customers’)
app.register_blueprint(leads_bp, url_prefix=’/leads’)
app.register_blueprint(opportunities_bp, url_prefix=’/opportunities’)
app.register_blueprint(activities_bp, url_prefix=’/activities’)
app.register_blueprint(tasks_bp, url_prefix=’/tasks’)
app.register_blueprint(analytics_bp, url_prefix=’/analytics’)

@login_manager.user_loader
def load_user(user_id):
return User.query.get(int(user_id))

@app.route(’/’)
def index():
if current_user.is_authenticated:
return redirect(url_for(‘dashboard’))
return redirect(url_for(‘login’))

@app.route(’/login’, methods=[‘GET’, ‘POST’])
def login():
if current_user.is_authenticated:
return redirect(url_for(‘dashboard’))

```
if request.method == 'POST':
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()
    
    if user and check_password_hash(user.password_hash, data.get('password')):
        login_user(user, remember=data.get('remember', False))
        return jsonify({'success': True, 'redirect': url_for('dashboard')})
    
    return jsonify({'success': False, 'message': 'Invalid email or password'}), 401

return render_template('login.html')
```

@app.route(’/logout’)
@login_required
def logout():
logout_user()
return redirect(url_for(‘login’))

@app.route(’/dashboard’)
@login_required
def dashboard():
# Get summary statistics
total_customers = Customer.query.filter_by(user_id=current_user.id).count()
total_leads = Lead.query.filter_by(user_id=current_user.id, status=‘new’).count()
total_opportunities = Opportunity.query.filter_by(user_id=current_user.id).count()

```
# Get open opportunities value
open_opps = Opportunity.query.filter_by(
    user_id=current_user.id,
    stage__in=['prospecting', 'qualification', 'proposal', 'negotiation']
).all()
pipeline_value = sum(opp.value for opp in open_opps if opp.value)

# Get recent activities
recent_activities = Activity.query.filter_by(
    user_id=current_user.id
).order_by(Activity.created_at.desc()).limit(10).all()

# Get upcoming tasks
upcoming_tasks = Task.query.filter_by(
    user_id=current_user.id,
    completed=False
).filter(Task.due_date >= datetime.now()).order_by(Task.due_date).limit(5).all()

# Get overdue tasks
overdue_tasks = Task.query.filter_by(
    user_id=current_user.id,
    completed=False
).filter(Task.due_date < datetime.now()).count()

return render_template('dashboard.html',
    total_customers=total_customers,
    total_leads=total_leads,
    total_opportunities=total_opportunities,
    pipeline_value=pipeline_value,
    recent_activities=recent_activities,
    upcoming_tasks=upcoming_tasks,
    overdue_tasks=overdue_tasks
)
```

@app.route(’/api/search’)
@login_required
def search():
query = request.args.get(‘q’, ‘’)
if len(query) < 2:
return jsonify({‘results’: []})

```
# Search across customers, leads, and opportunities
customers = Customer.query.filter_by(user_id=current_user.id).filter(
    db.or_(
        Customer.company_name.ilike(f'%{query}%'),
        Customer.contact_name.ilike(f'%{query}%'),
        Customer.email.ilike(f'%{query}%')
    )
).limit(5).all()

leads = Lead.query.filter_by(user_id=current_user.id).filter(
    db.or_(
        Lead.company_name.ilike(f'%{query}%'),
        Lead.contact_name.ilike(f'%{query}%'),
        Lead.email.ilike(f'%{query}%')
    )
).limit(5).all()

opportunities = Opportunity.query.filter_by(user_id=current_user.id).filter(
    Opportunity.title.ilike(f'%{query}%')
).limit(5).all()

results = {
    'customers': [{'id': c.id, 'name': c.company_name, 'type': 'customer'} for c in customers],
    'leads': [{'id': l.id, 'name': l.company_name, 'type': 'lead'} for l in leads],
    'opportunities': [{'id': o.id, 'name': o.title, 'type': 'opportunity'} for o in opportunities]
}

return jsonify(results)
```

@app.errorhandler(404)
def not_found(e):
return render_template(‘404.html’), 404

@app.errorhandler(500)
def server_error(e):
return render_template(‘500.html’), 500

if **name** == ‘**main**’:
with app.app_context():
db.create_all()

```
    # Create default admin user if none exists
    if not User.query.filter_by(email='admin@crm.local').first():
        admin = User(
            email='admin@crm.local',
            username='admin',
            password_hash=generate_password_hash('admin123'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Default admin user created: admin@crm.local / admin123")

app.run(debug=True, host='0.0.0.0', port=5000)
```