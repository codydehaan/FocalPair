from datetime import datetime
import os
from werkzeug.utils import secure_filename
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import InputRequired, Length, Email, EqualTo
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    UserMixin,
    current_user,
)
from sqlalchemy.sql.expression import func

app = Flask(__name__)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["SECRET_KEY"] = "099dbc30d8d37bf441e87c3ec95a628c"
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'app.db')}"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

def allowed_file(filename):
    ext = filename.rsplit(".", 1)[1].lower()
    return "." in filename and ext in ALLOWED_EXTENSIONS

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # "client" or "photographer"


class PhotographerProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True)
    bio = db.Column(db.Text, nullable=True)
    style = db.Column(db.String(100), nullable=False)
    mood = db.Column(db.String(100), nullable=False)
    niche = db.Column(db.String(100), nullable=False)

    user = db.relationship("User", backref="profile")


class PortfolioImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    photographer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    image_path = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    photographer = db.relationship("User", backref="portfolio_images")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4)])
    confirm = PasswordField("Confirm Password", validators=[EqualTo("password")])
    role = SelectField(
        "I am a...", choices=[("client", "Client"), ("photographer", "Photographer")]
    )
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Password", validators=[InputRequired()])
    submit = SubmitField("Login")


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    photographer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    client = db.relationship("User", foreign_keys=[client_id], backref="likes_sent")
    photographer = db.relationship(
        "User", foreign_keys=[photographer_id], backref="likes_received"
    )


class ProfileForm(FlaskForm):
    bio = StringField("Short Bio", validators=[Length(max=500)])
    style = SelectField(
        "Style",
        choices=[
            ("documentary", "Documentary"),
            ("editorial", "Editorial"),
            ("fine art", "Fine Art"),
        ],
        validators=[InputRequired()],
    )
    mood = SelectField(
        "Mood",
        choices=[
            ("romantic", "Romantic"),
            ("moody", "Moody"),
            ("bright", "Bright & Airy"),
        ],
        validators=[InputRequired()],
    )
    niche = SelectField(
        "Niche",
        choices=[
            ("wedding", "Wedding"),
            ("family", "Family"),
            ("portrait", "Portrait"),
            ("landscape", "Landscape"),
            ("corporate", "Corporate"),
            ("product", "Product"),
            ("event", "Event"),
            ("pet", "Pet"),
            ("social", "Social"),
            ("news", "News"),
        ],
        validators=[InputRequired()],
    )
    portfolio = FileField("Upload Portfolio Images", validators=[FileAllowed(ALLOWED_EXTENSIONS, "Images only!")])  
    submit = SubmitField("Save Profile")



@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("That email is already registered. Please log in instead.", "warning")
            return redirect(url_for("login"))

        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        user = User(email=form.email.data, password=hashed_pw, role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash("Registered successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)



@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid login credentials.", "danger")
    return render_template("login.html", form=form)


@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "photographer" and not current_user.profile:
        return redirect(url_for("create_profile"))
    return render_template("dashboard.html")


@app.route("/create_profile", methods=["GET", "POST"])
@login_required
def create_profile():
    if current_user.role != "photographer":
        flash("Only photographers can create profiles.", "warning")
        return redirect(url_for("dashboard"))

    if current_user.profile:
        flash("Profile already exists.", "info")
        return redirect(url_for("dashboard"))

    form = ProfileForm()
    if form.validate_on_submit():
        profile = PhotographerProfile(
            user_id=current_user.id,
            bio=form.bio.data,
            style=form.style.data,
            mood=form.mood.data,
            niche=form.niche.data,
        )
        db.session.add(profile)
        db.session.commit()

        # Handle file upload
        file = form.portfolio.data
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(save_path)

            # Save record in PortfolioImage
            img = PortfolioImage(photographer_id=current_user.id, image_path=filename)
            db.session.add(img)
            db.session.commit()

            flash("Profile created successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("create_profile.html", form=form)


@app.route("/photographers", methods=["GET", "POST"])
@login_required
def photographers():
    if current_user.role != "client":
        flash("Only clients can view photographers.", "warning")
        return redirect(url_for("dashboard"))

    style_filter = request.args.get("style")
    mood_filter = request.args.get("mood")
    niche_filter = request.args.get("niche")

    query = PhotographerProfile.query

    if style_filter:
        query = query.filter_by(style=style_filter)
    if mood_filter:
        query = query.filter_by(mood=mood_filter)
    if niche_filter:
        query = query.filter_by(niche=niche_filter)

    photographers = query.all()

    styles = ["documentary", "editorial", "fine Art"]
    moods = ["romantic", "moody", "bright"]
    niche = [
        "wedding",
        "family",
        "portrait",
        "landscape",
        "corporate",
        "product",
        "event",
        "pet",
        "boudoir",
        "commercial",
        "real estate",
    ]

    return render_template(
        "photographers.html",
        photographers=photographers,
        styles=styles,
        moods=moods,
        niche=niche,
        selected_style=style_filter,
        selected_mood=mood_filter,
        selected_niche=niche_filter,
    )


@app.route("/edit_profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    # Only photographers can edit their profile
    if current_user.role != "photographer":
        flash("Only photographers can edit profiles.", "warning")
        return redirect(url_for("dashboard"))

    # Fetch the existing profile (or 404 if none)
    profile = PhotographerProfile.query.filter_by(user_id=current_user.id).first_or_404()

    # Build a form, pre-populating the fields
    form = ProfileForm(
        bio=profile.bio,
        style=profile.style,
        mood=profile.mood,
        niche=profile.niche
    )

    if form.validate_on_submit():
        # Update text fields
        profile.bio = form.bio.data
        profile.style = form.style.data
        profile.mood = form.mood.data
        profile.niche = form.niche.data
        db.session.commit()

        # Handle a new portfolio upload (if any)
        file = form.portfolio.data
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(save_path)

            # Record it
            img = PortfolioImage(photographer_id=current_user.id, image_path=filename)
            db.session.add(img)
            db.session.commit()

        flash("Profile updated!", "success")
        return redirect(url_for("dashboard"))

    return render_template("edit_profile.html", form=form, existing_images=current_user.portfolio_images)


@app.route("/discover")
@login_required
def discover():
    if current_user.role != "client":
        flash("Only clients can browse photographers.", "warning")
        return redirect(url_for("dashboard"))

    liked_photographer_ids = db.session.query(Like.photographer_id).filter_by(
        client_id=current_user.id
    )
    seen_ids = [id for (id,) in liked_photographer_ids]

    next_profile = (
        PhotographerProfile.query.filter(PhotographerProfile.user_id.notin_(seen_ids))
        .order_by(db.func.random())
        .first()
    )

    if not next_profile:
        return render_template("no_profiles.html")

    return render_template("discover.html", profile=next_profile)


@app.route("/like/<int:photographer_id>", methods=["POST"])
@login_required
def like_photographer(photographer_id):
    if current_user.role != "client":
        flash("Only clients can like photographers.", "warning")
        return redirect(url_for("dashboard"))

    new_like = Like(client_id=current_user.id, photographer_id=photographer_id)
    db.session.add(new_like)
    db.session.commit()
    return redirect(url_for("discover"))


@app.route("/pass/<int:photographer_id>", methods=["POST"])
@login_required
def pass_photographer(photographer_id):
    return redirect(url_for("discover"))


@app.route("/liked")
@login_required
def liked_profiles():
    if current_user.role != "client":
        flash("Only clients can view liked profiles.", "warning")
        return redirect(url_for("dashboard"))

    # current_user.likes_sent is the backref from your Like model
    likes = current_user.likes_sent  # list of Like objects

    # Pull the photographer profiles they liked
    liked_profiles = []
    for like in likes:
        prof = PhotographerProfile.query.filter_by(user_id=like.photographer_id).first()
        if prof:
            liked_profiles.append((prof, like.timestamp))

    return render_template("liked.html", liked_profiles=liked_profiles)



@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
