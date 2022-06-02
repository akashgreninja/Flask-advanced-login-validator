
# required_docs=https://flask-login.readthedocs.io/en/latest/#your-user-class
# https://werkzeug.palletsprojects.com/en/1.0.x/utils/#module-werkzeug.security



from click import password_option
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user




app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    print (f'this is executed,{user_id}')
    return User.query.get(int(user_id))


app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html",logged_in=current_user.is_authenticated)


@app.route('/register',methods=["POST","GET"])
def register():
    form=User()
    if request.method =="POST":
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hashed_password=generate_password_hash(password=request.form.get('password'),method='pbkdf2:sha256',salt_length=8)
        new_user=User(
            email=request.form.get('email'),
            password=hashed_password,
            name=request.form.get('name')
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('secrets'))
    

    return render_template("register.html",logged_in=current_user.is_authenticated)


@app.route('/login',methods=["POST","GET"])
def login():
    if request.method=="POST":
        email=request.form["email"]
        password=request.form['password']
        
        the_object=User.query.filter_by(email=email).first()

        if not the_object:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))



        elif not check_password_hash(the_object.password,password):
            flash('password incorrect')
            return redirect(url_for('login'))

        else:
            login_user(the_object)
            return redirect(url_for('secrets'))
 




    return render_template("login.html",logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html",logged_in=current_user.is_authenticated)


@app.route('/logout')

def logout():
    logout_user()
    return redirect(url_for('home'))
   

# https://flask.palletsprojects.com/en/1.1.x/api/#flask.send_file
# x
@app.route('/download')
def download():
     return send_from_directory(directory='static',path="./files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
