from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user
from datetime import datetime
from app import db
from models import Lead, Customer, Activity, Note
from utils import validate_email, validate_phone, calculate_lead_score, paginate_query, export_to_csv

leads_bp = Blueprint(‘leads’, **name**)

@leads_bp.route(’/’)
@login_required
def list_leads():
page = request.args.get(‘page’, 1, type=int)
search = request.args.get(‘search’, ‘’)
status = request.args.get(‘status’, ‘’)
source = request.args.get(‘source’, ‘’)
sort = request.args.get(‘sort’, ‘created_at’)
order = request.args.get(‘order’, ‘desc’)

```
query = Lead.query.filter_by(user_id=current_user.id)

# Apply filters
if search:
    query = query.filter(
        db.or_(
            Lead.company_name.ilike(f'%{search}%'),
            Lead.contact_name.ilike(f'%{search}%'),
            Lead.email.ilike(f'%{search}%')
        )
    )

if status:
    query = query.filter_by(status=status)

if source:
    query = query.filter_by(source=source)

# Apply sorting
if order == 'desc':
    query = query.order_by(getattr(Lead, sort).desc())
else:
    query = query.order_by(getattr(Lead, sort).asc())

# Get unique sources for filter dropdown
sources = db.session.query(Lead.source).filter(
    Lead.user_id == current_user.id,
    Lead.source.isnot(None)
).distinct().all()
sources = [s[0] for s in sources if s[0]]

# Paginate
pagination = paginate_query(query, page=page, per_page=25)

# Calculate lead scores for display
for lead in pagination['items']:
    activities = Activity.query.filter_by(lead_id=lead.id).all()
    lead.calculated_score = calculate_lead_score(lead, activities)

return render_template('leads/list.html',
    leads=pagination['items'],
    pagination=pagination,
    sources=sources,
    current_search=search,
    current_status=status,
    current_source=source
)
```

@leads_bp.route(’/create’, methods=[‘GET’, ‘POST’])
@login_required
def create_lead():
if request.method == ‘POST’:
data = request.form

```
    # Validate required fields
    if not data.get('company_name') or not data.get('contact_name'):
        flash('Company name and contact name are required', 'danger')
        return redirect(url_for('leads.create_lead'))
    
    # Validate email if provided
    if data.get('email') and not validate_email(data.get('email')):
        flash('Invalid email format', 'danger')
        return redirect(url_for('leads.create_lead'))
    
    lead = Lead(
        user_id=current_user.id,
        company_name=data.get('company_name'),
        contact_name=data.get('contact_name'),
        email=data.get('email'),
        phone=data.get('phone'),
        website=data.get('website'),
        title=data.get('title'),
        source=data.get('source', 'manual'),
        status='new',
        industry=data.get('industry'),
        company_size=data.get('company_size'),
        estimated_value=float(data.get('estimated_value')) if data.get('estimated_value') else None,
        notes=data.get('notes')
    )
    
    # Calculate initial lead score
    lead.lead_score = calculate_lead_score(lead)
    
    db.session.add(lead)
    db.session.commit()
    
    # Log activity
    activity = Activity(
        user_id=current_user.id,
        lead_id=lead.id,
        activity_type='lead_created',
        subject=f'Created lead: {lead.company_name}',
        activity_date=datetime.now()
    )
    db.session.add(activity)
    db.session.commit()
    
    flash('Lead created successfully', 'success')
    return redirect(url_for('leads.view_lead', lead_id=lead.id))

return render_template('leads/create.html')
```

@leads_bp.route(’/<int:lead_id>’)
@login_required
def view_lead(lead_id):
lead = Lead.query.filter_by(
id=lead_id,
user_id=current_user.id
).first_or_404()

```
# Get related data
activities = Activity.query.filter_by(
    lead_id=lead_id
).order_by(Activity.activity_date.desc()).limit(20).all()

notes = Note.query.filter_by(
    lead_id=lead_id
).order_by(Note.created_at.desc()).all()

# Calculate current lead score
lead.calculated_score = calculate_lead_score(lead, activities)

return render_template('leads/view.html',
    lead=lead,
    activities=activities,
    notes=notes
)
```

@leads_bp.route(’/<int:lead_id>/edit’, methods=[‘GET’, ‘POST’])
@login_required
def edit_lead(lead_id):
lead = Lead.query.filter_by(
id=lead_id,
user_id=current_user.id
).first_or_404()

```
if request.method == 'POST':
    data = request.form
    
    # Validate email if provided
    if data.get('email') and not validate_email(data.get('email')):
        flash('Invalid email format', 'danger')
        return redirect(url_for('leads.edit_lead', lead_id=lead_id))
    
    # Update fields
    lead.company_name = data.get('company_name')
    lead.contact_name = data.get('contact_name')
    lead.email = data.get('email')
    lead.phone = data.get('phone')
    lead.website = data.get('website')
    lead.title = data.get('title')
    lead.source = data.get('source')
    lead.status = data.get('status')
    lead.industry = data.get('industry')
    lead.company_size = data.get('company_size')
    lead.estimated_value = float(data.get('estimated_value')) if data.get('estimated_value') else None
    lead.notes = data.get('notes')
    lead.updated_at = datetime.now()
    
    # Recalculate lead score
    activities = Activity.query.filter_by(lead_id=lead.id).all()
    lead.lead_score = calculate_lead_score(lead, activities)
    
    db.session.commit()
    
    # Log activity
    activity = Activity(
        user_id=current_user.id,
        lead_id=lead.id,
        activity_type='lead_updated',
        subject=f'Updated lead: {lead.company_name}',
        activity_date=datetime.now()
    )
    db.session.add(activity)
    db.session.commit()
    
    flash('Lead updated successfully', 'success')
    return redirect(url_for('leads.view_lead', lead_id=lead.id))

return render_template('leads/edit.html', lead=lead)
```

@leads_bp.route(’/<int:lead_id>/convert’, methods=[‘GET’, ‘POST’])
@login_required
def convert_lead(lead_id):
lead = Lead.query.filter_by(
id=lead_id,
user_id=current_user.id
).first_or_404()

```
if lead.status == 'converted':
    flash('This lead has already been converted', 'warning')
    return redirect(url_for('leads.view_lead', lead_id=lead.id))

if request.method == 'POST':
    # Create new customer from lead
    customer = Customer(
        user_id=current_user.id,
        company_name=lead.company_name,
        contact_name=lead.contact_name,
        email=lead.email,
        phone=lead.phone,
        website=lead.website,
        industry=lead.industry,
        company_size=lead.company_size,
        customer_since=datetime.now(),
        status='active',
        notes=lead.notes
    )
    
    db.session.add(customer)
    db.session.flush()  # Get the customer ID
    
    # Update lead
    lead.status = 'converted'
    lead.converted_to_customer_id = customer.id
    lead.converted_at = datetime.now()
    
    # Log activity for lead
    lead_activity = Activity(
        user_id=current_user.id,
        lead_id=lead.id,
        activity_type='lead_converted',
        subject=f'Converted lead to customer: {lead.company_name}',
        activity_date=datetime.now()
    )
    db.session.add(lead_activity)
    
    # Log activity for customer
    customer_activity = Activity(
        user_id=current_user.id,
        customer_id=customer.id,
        activity_type='customer_created',
        subject=f'Created from lead: {customer.company_name}',
        activity_date=datetime.now()
    )
    db.session.add(customer_activity)
    
    db.session.commit()
    
    flash(f'Lead converted to customer successfully', 'success')
    return redirect(url_for('customers.view_customer', customer_id=customer.id))

return render_template('leads/convert.html', lead=lead)
```

@leads_bp.route(’/<int:lead_id>/delete’, methods=[‘POST’])
@login_required
def delete_lead(lead_id):
lead = Lead.query.filter_by(
id=lead_id,
user_id=current_user.id
).first_or_404()

```
company_name = lead.company_name
db.session.delete(lead)
db.session.commit()

flash(f'Lead "{company_name}" deleted successfully', 'success')
return redirect(url_for('leads.list_leads'))
```

@leads_bp.route(’/export’)
@login_required
def export_leads():
leads = Lead.query.filter_by(user_id=current_user.id).all()

```
data = []
for lead in leads:
    data.append({
        'Company Name': lead.company_name,
        'Contact Name': lead.contact_name,
        'Email': lead.email,
        'Phone': lead.phone,
        'Source': lead.source,
        'Status': lead.status,
        'Lead Score': lead.lead_score,
        'Estimated Value': lead.estimated_value or '',
        'Created': lead.created_at.strftime('%Y-%m-%d') if lead.created_at else ''
    })

csv_data = export_to_csv(data, 'leads.csv')

from flask import Response
return Response(
    csv_data,
    mimetype='text/csv',
    headers={'Content-Disposition': 'attachment; filename=leads.csv'}
)
```