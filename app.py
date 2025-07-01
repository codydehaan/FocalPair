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
    """Return True if the file with the given filename has an extension that is
    one of the ones in ALLOWED_EXTENSIONS."""
    ext = filename.rsplit(".", 1)[1].lower()
    return "." in filename and ext in ALLOWED_EXTENSIONS

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # "client" or "photographer"


class PhotographerProfile(db.Model):
    """A photographer's profile."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True)
    bio = db.Column(db.Text, nullable=True)
    style = db.Column(db.String(100), nullable=False)
    mood = db.Column(db.String(100), nullable=False)
    niche = db.Column(db.String(100), nullable=False)

    user = db.relationship("User", backref="profile")


class PortfolioImage(db.Model):
    """An image uploaded by a photographer."""
    id = db.Column(db.Integer, primary_key=True)
    photographer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    image_path = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    photographer = db.relationship("User", backref="portfolio_images")


@login_manager.user_loader
"""
Load a User object from the user ID stored in the session."""
def load_user(user_id):
    """Return a User object given a user_id, or None if no user is found."""
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    """A form for registering a new user."""
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4)])
    confirm = PasswordField("Confirm Password", validators=[EqualTo("password")])
    role = SelectField(
        "I am a...", choices=[("client", "Client"), ("photographer", "Photographer")]
    )
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    """A form for logging in a user."""
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Password", validators=[InputRequired()])
    submit = SubmitField("Login")


class Like(db.Model):
    """A like from a client to a photographer."""
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    photographer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    client = db.relationship("User", foreign_keys=[client_id], backref="likes_sent")
    photographer = db.relationship(
        "User", foreign_keys=[photographer_id], backref="likes_received"
    )


class ProfileForm(FlaskForm):
    """A form for editing a photographer's profile."""
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
"""Show the homepage."""
def home():
    """Show the homepage."""
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
"""Handle user registration requests."""
def register():
    """
    Handle user registration requests.

    This function displays a registration form and processes form submissions
    to create a new user. If the registration is successful, the user will be
    redirected to the login page. If the email is already registered, a warning
    message is displayed, and the user is redirected to the login page.

    Returns:
        A rendered template for the registration page, or a redirect to the login page.
    """

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
    """
    Handle user login requests.

    This function displays a login form and processes form submissions to
    log in a user. If the login is successful, the user will be redirected
    to the dashboard page. If the email or password is invalid, a warning
    message is displayed, and the user is redirected to the login page.

    Returns:
        A rendered template for the login page, or a redirect to the dashboard page.
    """
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
    """
    Display the dashboard for the logged-in user.

    If the user is a photographer without a profile, redirect them to create a profile.
    Otherwise, render the dashboard page.

    Returns:
        A redirect to the create profile page if the user is a photographer without a profile.
        A rendered template for the dashboard page for all other users.
    """

    if current_user.role == "photographer" and not current_user.profile:
        return redirect(url_for("create_profile"))
    return render_template("dashboard.html")


@app.route("/create_profile", methods=["GET", "POST"])
@login_required
def create_profile():
    """
    Handle requests to create a photographer profile.

    This function allows photographers to create a profile by filling out a form with
    their bio, style, mood, and niche. Photographers can also upload portfolio images.
    If the form is submitted and validated, the profile and images are saved to the database.
    Only photographers without an existing profile can access this page.

    Returns:
        A redirect to the dashboard if the user is not a photographer or already has a profile.
        A redirect to the dashboard with a success message upon successful profile creation.
        A rendered template for the create profile page with the form otherwise.
    """

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
    """
    Handle requests to view photographers.

    This function displays a page with a list of all photographers in the database.
    Clients can filter the list by style, mood, and niche using the form.
    The list of photographers is paginated for easier viewing.

    Returns:
        A rendered template for the photographers page with the list of photographers.
    """
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
    """
    Handle requests to edit a photographer's profile.

    This function displays a page with a pre-populated form for the photographer to edit their profile.
    The form includes fields for bio, style, mood, and niche, as well as a file upload for adding new
    portfolio images.

    Returns:
        A rendered template for the edit profile page with the form pre-populated.
    """

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
    """Handle requests to browse photographers.

    This function displays a single photographer's profile, selected at random from all
    available profiles that the client has not yet seen. If the client has seen all
    available profiles, they're shown a "no more profiles" message.

    Returns:
        A rendered template for a single photographer's profile.
    """
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
    """Handle a client's request to like a photographer.

    This function is reached when a client submits a "like" vote for a photographer's profile.
    It creates a new Like record in the database and redirects the client back to the discover page.

    Returns:
        A redirect to the discover page.
    """
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
    """Handle a client's request to pass a photographer.

    This function is reached when a client submits a "pass" vote for a photographer's profile.
    It redirects the client back to the discover page, without creating a new Like record.

    Returns:
        A redirect to the discover page.
    """
    return redirect(url_for("discover"))


@app.route("/liked")
@login_required
def liked_profiles():
    """Handle a client's request to view their liked profiles.

    This function is reached when a client requests to view the profiles they have previously liked.
    It fetches the list of Like records for the current user, and for each one, fetches the corresponding
    PhotographerProfile record. It then passes a list of (profile, timestamp) tuples to the template.

    Returns:
        A rendered template for the liked profiles page.
    """
    
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
    """Handle a request to log out the user.

    This function is reached when a user submits a GET request to /logout.
    It logs the user out using Flask-Login and redirects them to the login page with a success message.

    Returns:
        A redirect to the login page.
    """
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
