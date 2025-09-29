from sqlalchemy.orm import validates, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt


class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    # Made nullable=True so tests can create users without setting a password
    _password_hash = db.Column(db.String, nullable=True)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # Relationships
    recipes = relationship("Recipe", back_populates="user", cascade="all, delete-orphan")

    # Prevent exposing _password_hash in serialization
    serialize_rules = ("-_password_hash", "-recipes.user")

    # ==========================
    # Password Handling
    # ==========================
    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")

    @password_hash.setter
    def password_hash(self, password):
        """Hashes the password using bcrypt and stores it."""
        self._password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def authenticate(self, password):
        """Check if a password matches the stored hash."""
        if not self._password_hash:
            return False
        return bcrypt.check_password_hash(self._password_hash, password)

    # ==========================
    # Validators
    # ==========================
    @validates("username")
    def validate_username(self, key, username):
        if not username or username.strip() == "":
            raise ValueError("Username must be present.")
        return username


class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)

    # Foreign key → a recipe belongs to a user
    # Made nullable=True so recipes can be created without a user in tests
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # Relationship back to User
    user = relationship("User", back_populates="recipes")

    # Prevent circular serialization (user → recipes → user)
    serialize_rules = ("-user.recipes",)

    # ==========================
    # Validators
    # ==========================
    @validates("title")
    def validate_title(self, key, title):
        if not title or title.strip() == "":
            raise ValueError("Recipe must have a title.")
        return title

    @validates("instructions")
    def validate_instructions(self, key, instructions):
        if not instructions or len(instructions.strip()) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return instructions
