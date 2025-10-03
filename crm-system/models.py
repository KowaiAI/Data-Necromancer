from datetime import datetime
from flask_login import UserMixin
from app import db

class User(UserMixin, db.Model):
id = db.Column(db.Integer, primary_key=True)
email = db.Column(db.String(120), unique=True, nullable=False, index=True)
username = db.Column(db.String(80), unique=True, nullable=False)
password_hash = db.Column(db.String(255), nullable=False)
is_admin = db.Column(db.Boolean, default=False)
created_at = db.Column(db.DateTime, default=datetime.utcnow)

```
# Relationships
customers = db.relationship('Customer', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
leads = db.relationship('Lead', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
opportunities = db.relationship('Opportunity', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
activities = db.relationship('Activity', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
tasks = db.relationship('Task', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
```

class Customer(db.Model):
id = db.Column(db.Integer, primary_key=True)
user_id = db.Column(db.Integer, db.ForeignKey(‘user.id’), nullable=False, index=True)
company_name = db.Column(db.String(200), nullable=False, index=True)
contact_name = db.Column(db.String(200))
email = db.Column(db.String(120), index=True)
phone = db.Column(db.String(20))
website = db.Column(db.String(200))
address = db.Column(db.Text)
city = db.Column(db.String(100))
state = db.Column(db.String(50))
country = db.Column(db.String(100))
postal_code = db.Column(db.String(20))
industry = db.Column(db.String(100))
company_size = db.Column(db.String(50))
annual_revenue = db.Column(db.Float)
customer_since = db.Column(db.DateTime)
status = db.Column(db.String(50), default=‘active’)  # active, inactive, churned
tags = db.Column(db.String(500))  # Comma-separated tags
notes = db.Column(db.Text)
created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

```
# Relationships
opportunities = db.relationship('Opportunity', backref='customer', lazy='dynamic', cascade='all, delete-orphan')
activities = db.relationship('Activity', backref='customer', lazy='dynamic', cascade='all, delete-orphan')
notes_list = db.relationship('Note', backref='customer', lazy='dynamic', cascade='all, delete-orphan')
```

class Lead(db.Model):
id = db.Column(db.Integer, primary_key=True)
user_id = db.Column(db.Integer, db.ForeignKey(‘user.id’), nullable=False, index=True)
company_name = db.Column(db.String(200), nullable=False, index=True)
contact_name = db.Column(db.String(200), nullable=False)
email = db.Column(db.String(120), index=True)
phone = db.Column(db.String(20))
website = db.Column(db.String(200))
title = db.Column(db.String(100))
source = db.Column(db.String(100))  # website, referral, event, cold_call, etc.
status = db.Column(db.String(50), default=‘new’, index=True)  # new, contacted, qualified, unqualified, converted
lead_score = db.Column(db.Integer, default=0)  # 0-100
industry = db.Column(db.String(100))
company_size = db.Column(db.String(50))
estimated_value = db.Column(db.Float)
notes = db.Column(db.Text)
converted_to_customer_id = db.Column(db.Integer, db.ForeignKey(‘customer.id’), nullable=True)
converted_at = db.Column(db.DateTime)
created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

```
# Relationships
activities = db.relationship('Activity', backref='lead', lazy='dynamic', cascade='all, delete-orphan')
notes_list = db.relationship('Note', backref='lead', lazy='dynamic', cascade='all, delete-orphan')
```

class Opportunity(db.Model):
id = db.Column(db.Integer, primary_key=True)
user_id = db.Column(db.Integer, db.ForeignKey(‘user.id’), nullable=False, index=True)
customer_id = db.Column(db.Integer, db.ForeignKey(‘customer.id’), nullable=True, index=True)
title = db.Column(db.String(200), nullable=False, index=True)
description = db.Column(db.Text)
value = db.Column(db.Float)
probability = db.Column(db.Integer, default=50)  # 0-100
expected_close_date = db.Column(db.DateTime, index=True)
stage = db.Column(db.String(50), default=‘prospecting’, index=True)  
# prospecting, qualification, proposal, negotiation, closed_won, closed_lost
status = db.Column(db.String(50), default=‘open’)  # open, won, lost
loss_reason = db.Column(db.String(200))
next_step = db.Column(db.String(500))
tags = db.Column(db.String(500))
closed_at = db.Column(db.DateTime)
created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

```
# Relationships
activities = db.relationship('Activity', backref='opportunity', lazy='dynamic', cascade='all, delete-orphan')
notes_list = db.relationship('Note', backref='opportunity', lazy='dynamic', cascade='all, delete-orphan')
```

class Activity(db.Model):
id = db.Column(db.Integer, primary_key=True)
user_id = db.Column(db.Integer, db.ForeignKey(‘user.id’), nullable=False, index=True)
customer_id = db.Column(db.Integer, db.ForeignKey(‘customer.id’), nullable=True, index=True)
lead_id = db.Column(db.Integer, db.ForeignKey(‘lead.id’), nullable=True, index=True)
opportunity_id = db.Column(db.Integer, db.ForeignKey(‘opportunity.id’), nullable=True, index=True)
activity_type = db.Column(db.String(50), nullable=False, index=True)  
# call, email, meeting, note, task_completed, etc.
subject = db.Column(db.String(200), nullable=False)
description = db.Column(db.Text)
activity_date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
duration_minutes = db.Column(db.Integer)
outcome = db.Column(db.String(200))
created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Task(db.Model):
id = db.Column(db.Integer, primary_key=True)
user_id = db.Column(db.Integer, db.ForeignKey(‘user.id’), nullable=False, index=True)
customer_id = db.Column(db.Integer, db.ForeignKey(‘customer.id’), nullable=True, index=True)
lead_id = db.Column(db.Integer, db.ForeignKey(‘lead.id’), nullable=True)
opportunity_id = db.Column(db.Integer, db.ForeignKey(‘opportunity.id’), nullable=True)
title = db.Column(db.String(200), nullable=False)
description = db.Column(db.Text)
priority = db.Column(db.String(20), default=‘medium’, index=True)  # low, medium, high, urgent
status = db.Column(db.String(50), default=‘pending’, index=True)  # pending, in_progress, completed, cancelled
due_date = db.Column(db.DateTime, index=True)
completed = db.Column(db.Boolean, default=False, index=True)
completed_at = db.Column(db.DateTime)
reminder_date = db.Column(db.DateTime)
created_at = db.Column(db.DateTime, default=datetime.utcnow)
updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Note(db.Model):
id = db.Column(db.Integer, primary_key=True)
user_id = db.Column(db.Integer, db.ForeignKey(‘user.id’), nullable=False)
customer_id = db.Column(db.Integer, db.ForeignKey(‘customer.id’), nullable=True)
lead_id = db.Column(db.Integer, db.ForeignKey(‘lead.id’), nullable=True)
opportunity_id = db.Column(db.Integer, db.ForeignKey(‘opportunity.id’), nullable=True)
content = db.Column(db.Text, nullable=False)
created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)