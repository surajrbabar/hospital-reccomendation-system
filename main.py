from flask import Flask, flash, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config["SECRET_KEY"] = '65b0b774279de460f1cc5c92'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///ums.sqlite"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = 'filesystem'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)


class User2(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = password

    def check_password(self, password):
        return password
# User Class
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hname = db.Column(db.String(255), nullable=False)
    city = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    phoneno = db.Column(db.String(255), nullable=False)
    treatment = db.Column(db.String(255), nullable=False)
    estimated = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Integer, default=0, nullable=False)

    def __repr__(self):
        return f'User("{self.id}","{self.hname}","{self.city}","{self.email}","{self.phoneno}","{self.username}","{self.treatment}","{self.estimated}","{self.status}")'

# create admin Class
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)

# Create all tables
with app.app_context():
    db.create_all()

    # Check if admin exists, if not create one
    existing_admin = Admin.query.first()
    if not existing_admin:
        admin = Admin(username='mayank123', password='mayank123')
        db.session.add(admin)
        db.session.commit()

# main index 
@app.route('/')
def index():
    return render_template('index.html', title="")

# admin loign
@app.route('/admin/', methods=["POST", "GET"])
def adminIndex():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == "" and password == "":
            flash('Please fill all the field', 'danger')
            return redirect('/admin/')
        else:
            admins = Admin.query.filter_by(username=username).first()
            if admins and admins.password == password:  # Directly comparing passwords
                session['admin_id'] = admins.id
                session['admin_name'] = admins.username
                flash('Login Successfully', 'success')
                return redirect('/admin/dashboard')
            else:
                flash('Invalid Email and Password', 'danger')
                return redirect('/admin/')
    else:
        return render_template('admin/index.html', title="Admin Login")

# Rest of the routes and logic remain unchanged...


# admin Dashboard
@app.route('/admin/dashboard')
def adminDashboard():
    if not session.get('admin_id'):
        return redirect('/admin/')
    totalUser=User.query.count()
    totalApprove=User.query.filter_by(status=1).count()
    NotTotalApprove=User.query.filter_by(status=0).count()
    return render_template('admin/dashboard.html',title="Admin Dashboard",totalUser=totalUser,totalApprove=totalApprove,NotTotalApprove=NotTotalApprove)

# admin get all user 
@app.route('/admin/get-all-user', methods=["POST","GET"])
def adminGetAllUser():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if request.method== "POST":
        search=request.form.get('search')
        users=User.query.filter(User.username.like('%'+search+'%')).all()
        return render_template('admin/all-user.html',title='Approve User',users=users)
    else:
        users=User.query.all()
        return render_template('admin/all-user.html',title='Approve User',users=users)

@app.route('/admin/approve-user/<int:id>')
def adminApprove(id):
    if not session.get('admin_id'):
        return redirect('/admin/')
    User().query.filter_by(id=id).update(dict(status=1))
    db.session.commit()
    flash('Approve Successfully','success')
    return redirect('/admin/get-all-user')

# change admin password
@app.route('/admin/change-admin-password',methods=["POST","GET"])
def adminChangePassword():
    admin=Admin.query.get(1)
    if request.method == 'POST':
        username=request.form.get('username')
        password=request.form.get('password')
        if username == "" or password=="":
            flash('Please fill the field','danger')
            return redirect('/admin/change-admin-password')
        else:
            Admin().query.filter_by(username=username).update(dict(password=bcrypt.generate_password_hash(password,10)))
            db.session.commit()
            flash('Admin Password update successfully','success')
            return redirect('/admin/change-admin-password')
    else:
        return render_template('admin/admin-change-password.html',title='Admin Change Password',admin=admin)

# admin logout
@app.route('/admin/logout')
def adminLogout():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if session.get('admin_id'):
        session['admin_id']=None
        session['admin_name']=None
        return redirect('/')
# -------------------------user area----------------------------


# User login
@app.route('/user/',methods=["POST","GET"])
def userIndex():
    if  session.get('user_id'):
        return redirect('/user/dashboard')
    if request.method=="POST":
        # get the name of the field
        email=request.form.get('email')
        password=request.form.get('password')
        # check user exist in this email or not
        users=User().query.filter_by(email=email).first()
        if users and bcrypt.check_password_hash(users.password,password):
            # check the admin approve your account are not
            is_approve=User.query.filter_by(id=users.id).first()
            # first return the is_approve:
            if is_approve.status == 0:
                flash('Your Account is not approved by Admin','danger')
                return redirect('/user/')
            else:
                session['user_id']=users.id
                session['username']=users.username
                flash('Login Successfully','success')
                return redirect('/user/dashboard')
        else:
            flash('Invalid Email and Password','danger')
            return redirect('/user/')
    else:
        return render_template('user/index.html',title="User Login")

# User Register
@app.route('/user/signup',methods=['POST','GET'])
def userSignup():
    if  session.get('user_id'):
        return redirect('/user/dashboard')
    if request.method=='POST':
        # get all input field name
        hname=request.form.get('hname')
        city=request.form.get('city')
        email=request.form.get('email')
        username=request.form.get('username')
        phoneno=request.form.get('phoneno')
        treatment=request.form.get('treatment')
        estimated=request.form.get('estimated')
        password=request.form.get('password')
        # check all the field is filled are not
        if hname =="" or city=="" or email=="" or password=="" or username=="" or phoneno=="" or treatment=="" or estimated=="":
            flash('Please fill all the field','danger')
            return redirect('/user/signup')
        else:
            is_email=User().query.filter_by(email=email).first()
            if is_email:
                flash('Email already Exist','danger')
                return redirect('/user/signup')
            else:
                hash_password=bcrypt.generate_password_hash(password,10)
                user=User(hname=hname,city=city,email=email,password=hash_password,phoneno=phoneno,username=username,estimated=estimated,treatment=treatment)
                db.session.add(user)
                db.session.commit()
                flash('Account Create Successfully Admin Will approve your account in 10 to 30 mint ','success')
                return redirect('/user/')
    else:
        return render_template('user/signup.html',title="User Signup")


# user dashboard
@app.route('/user/dashboard')
def userDashboard():
    if not session.get('user_id'):
        return redirect('/user/')
    if session.get('user_id'):
        id=session.get('user_id')
    users=User().query.filter_by(id=id).first()
    return render_template('user/dashboard.html',title="Hospital Dashboard",user=users)

# user logout
@app.route('/user/logout')
def userLogout():
    if not session.get('user_id'):
        return redirect('/user/')

    if session.get('user_id'):
        session['user_id'] = None
        session['username'] = None
        return redirect('/user/')
    
@app.route('/user/healthTips')
def userHealth():
    return render_template('user/healthTips.html',title= "Hospital Dashboard", user= User2)

@app.route('/user/healthCareServices')
def userHealthCareServices():
    return render_template('user/healthCareServices.html',title= "Hospital Dashboard", user= User)

@app.route('/user/change-password',methods=["POST","GET"])
def userChangePassword():
    if not session.get('user_id'):
        return redirect('/user/')
    if request.method == 'POST':
        email=request.form.get('email')
        password=request.form.get('password')
        if email == "" or password == "":
            flash('Please fill the field','danger')
            return redirect('/user/change-password')
        else:
            users=User.query.filter_by(email=email).first()
            if users:
               hash_password=bcrypt.generate_password_hash(password,10)
               User.query.filter_by(email=email).update(dict(password=hash_password))
               db.session.commit()
               flash('Password Change Successfully','success')
               return redirect('/user/change-password')
            else:
                flash('Invalid Email','danger')
                return redirect('/user/change-password')

    else:
        return render_template('user/change-password.html',title="Change Password")

# user update profile
@app.route('/user/update-profile', methods=["POST","GET"])
def userUpdateProfile():
    if not session.get('user_id'):
        return redirect('/user/')
    if session.get('user_id'):
        id=session.get('user_id')
    users=User.query.get(id)
    if request.method == 'POST':
        # get all input field name
        hname=request.form.get('hname')
        city=request.form.get('city')
        email=request.form.get('email')
        username=request.form.get('username')
        phoneno=request.form.get('phoneno')
        treatment=request.form.get('treatment')
        estimated=request.form.get('estimated')
        if hname =="" or city=="" or email=="" or username=="" or phoneno=="" or treatment=="" or estimated=="": 
            flash('Please fill all the field','danger')
            return redirect('/user/update-profile')
        else:
            session['username']=None
            User.query.filter_by(id=id).update(dict(hname=hname,city=city,email=email,username=username,phoneno=phoneno,treatment=treatment,estimated=estimated))
            db.session.commit()
            session['username']=username
            flash('Profile update Successfully','success')
            return redirect('/user/dashboard')
    else:
        return render_template('user/update-profile.html',title="Update Profile",users=users)
    
    
    
@app.route('/patient/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # handle request
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        new_user = User2(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/patient/login')

    return render_template('patient/register.html')

@app.route('/patient/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User2.query.filter_by(email=email).first()
        
        if user and user.password == password:
            session['user_id'] = user.id  # Store user ID in session
            return redirect('/patient/dash')
        else:
            return render_template('patient/login.html', error='Invalid user')

    return render_template('patient/login.html')






@app.route('/patient/dash', methods=['GET'])
def userDashboard2():
    if not session.get('user_id'):
        return redirect('/patient/')

    filter_by = request.args.get('filter_by')
    search_text = request.args.get('search_text')
    
    with app.app_context():
        if filter_by == 'city':
            all_users1 = User().query.filter(User.city.ilike(f'%{search_text}%')).filter_by(status=1).all()
        elif filter_by == 'treatment':
            all_users1 = User().query.filter(User.treatment.ilike(f'%{search_text}%')).filter_by(status=1).all()
        else:
            all_users1 = User().query.filter_by(status=1).all()

    # Pass the title and user1 variables to the template rendering function
    return render_template('patient/dash.html', title="Hospital Dashboard", user1=all_users1)



if __name__=="__main__":
     with app.app_context():
        db.create_all()

     app.run(debug=True)