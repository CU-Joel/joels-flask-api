from application import application
from flask import (
    request,
    render_template,
    redirect,
    url_for,
    jsonify,
    make_response,
)

from models import db, User, Ship
from flask_bootstrap import Bootstrap
from functools import wraps
import datetime
import os
import jwt
import uuid
from forms import LoginForm, RegisterForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
)


# Initialize the flask server
# application = Flask(__name__)

application.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY"
)  # Secret used for generating JWTs and in Flask CSRF


application.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "SQLALCHEMY_DATABASE_URI"
)
Bootstrap(application)
db.init_app(application)
login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def token_required(f):
    """Decorator that is wrapped around routes that require login preventing access unelss user is logged in"""

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]

        if not token:
            return jsonify({"message": "Missing Token"}), 401

        # Using JWT to decode token and if it is invalid, it will raise exception
        try:
            print(application.config["SECRET_KEY"])
            data = jwt.decode(
                token, application.config["SECRET_KEY"], algorithms=["HS256"]
            )

            current_user = User.query.filter_by(public_id=data["public_id"]).first()
        except:
            return jsonify({"message": "Invalid Token"}), 401

        # args
        return f(current_user, *args, **kwargs)

    return decorated


# Welcome page
@application.route("/")
def index():
    """Index page returns index.html"""
    return render_template("index.html")


@application.route("/login", methods=["GET", "POST"])
def login():
    """User login page for users that have already signed up"""
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if not user:
            return make_response(
                "Login Failed. User does not exist",
                401,
                {"WWW-Authenticate": 'Basic realm="Login Required"'},
            )

        elif check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            token = jwt.encode(
                {
                    "public_id": user.public_id,
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
                },
                application.config["SECRET_KEY"],
                algorithm="HS256",
            )
            return redirect(url_for("dashboard"))

        else:
            return make_response(
                "Login Failed",
                401,
                {"WWW-Authenticate": 'Basic realm="Login Required"'},
            )

    return render_template("login.html", form=form)


# Signup form submissions can be GET but are done as POST for security and performance reasons.
@application.route("/signup", methods=["GET", "POST"])
def signup():
    """Signup page which allows new users to signup, hashes and stores the password in the database,"""
    form = RegisterForm()
    # validate_on_submit() will return False when the page is loaded causing the render_template()
    # and then True when the form is submitted.
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method="sha256")
        new_user = User(
            public_id=str(uuid.uuid4()),
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
        )
        db.session.add(new_user)
        db.session.commit()

        return "<h1>New user has been created</h1>"

    return render_template("signup.html", form=form)


# Returns a JSON Web Token
@application.route("/gettoken", methods=["GET", "POST"])
def gettoken():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response(
            "Login Failed",
            401,
            {"WWW-Authenticate": 'Basic realm="Login Required"'},
        )
    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response(
            "Login Failed. User does not exist",
            401,
            {"WWW-Authenticate": 'Basic realm="Login Required"'},
        )

    if check_password_hash(user.password, auth.password):

        token = jwt.encode(
            {
                "public_id": user.public_id,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            },
            application.config["SECRET_KEY"],
            algorithm="HS256",
        )
        return jsonify({"token": token})

    else:
        return make_response(
            "Login Failed",
            401,
            {"WWW-Authenticate": 'Basic realm="Login Required"'},
        )


@application.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", name=current_user.username)


@application.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@application.route("/login_ships", methods=["GET"])
@login_required
def show_ships():
    """Return the existing ships from database in HTML format"""
    ships = Ship.query.all()
    output = []
    for ship in ships:
        ship_data = {"name": ship.name, "description": ship.description}
        output.append(ship_data)
    return render_template("ships.html", title="ships", ship_list=output)


@application.route("/ships", methods=["GET"])
@token_required
def get_ships(current_user):
    """Return the existing ships from database in JSON format"""
    ships = Ship.query.all()
    output = []
    for ship in ships:
        ship_data = {"name": ship.name, "description": ship.description}
        output.append(ship_data)
    return {"ships": output}


@application.route("/ships/<id>")
@token_required
def get_ship(current_user, id):
    ship = Ship.query.get_or_404(id)
    return {"name": ship.name, "description": ship.description}


@application.route("/ships", methods=["POST"])
@token_required
def add_ship(current_user):
    ship = Ship(name=request.json["name"], description=request.json["description"])
    db.session.add(ship)
    db.session.commit()
    return {"id": ship.id}


@application.route("/ships/<id>", methods=["DELETE"])
@token_required
def delete_ship(current_user, id):
    ship = Ship.query.get(id)
    if ship is None:
        return {"error": "not found"}
    db.session.delete(ship)
    db.session.commit()
    return {"message": "Don't get cocky!"}


@application.route("/show_token")
@login_required
def your_flask_funtion():
    uname = current_user.username
    user = User.query.filter_by(username=uname).first()
    token = jwt.encode(
        {
            "public_id": user.public_id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
        },
        application.config["SECRET_KEY"],
        algorithm="HS256",
    )
    return jsonify({"token": token})


if __name__ == "__main__":
    application.run(debug=True)
