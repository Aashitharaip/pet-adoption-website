from flask import Flask, render_template, request, redirect, session, url_for, flash
import bcrypt 
from functools import wraps

app = Flask(__name__, template_folder='templates')
app.secret_key = "webjfgerjkgfjervjkgrjvgjgjvgrjgbhjgrjhg"  # Replace with an environment variable for better security.

# Simulated database connection for demonstration (use SQLite or another DB in production).
class Database:
    def __init__(self):
        self.users = {}  # Example: {"email@example.com": {"password": hashed_password, "name": "John"}}
        self.pets = [{"id": 1, "name": "Dog", "price": 100}, {"id": 2, "name": "Cat", "price": 50}]

    def execute(self, query, params=()):
        # Placeholder for actual database execution. Simulate behavior as needed.
        if query.startswith("SELECT * FROM users"):
            email = params[0]
            return self.users.get(email)
        elif query.startswith("INSERT INTO users"):
            email, password = params
            self.users[email] = {"password": password}
            return True
        return None


db = Database()  # Simulated database.


# Authentication and PetStore classes.
class Auth:
    def register(self, request):
        email = request.form.get("email").strip()
        password = request.form.get("password").strip()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))

    def authenticate(self, request):
        email = request.form.get("email").strip()
        password = request.form.get("password").strip()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,))
        if user and bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8')):
            return email
        return None

    def get_user_details(self, email):
        return db.execute("SELECT * FROM users WHERE email = ?", (email,))

    def update_user_details(self, request):
        # Example: Update logic here.
        pass

    def delete_user_account(self):
        # Example: Delete logic here.
        pass


class PetStore:
    def get_pets(self):
        return db.pets

    def get_pet(self, pet_id):
        return next((pet for pet in db.pets if pet["id"] == pet_id), None)

    def buy_pet(self, pet_id):
        pet = self.get_pet(pet_id)
        return f"You bought {pet['name']} for ${pet['price']}."


# Login required decorator.
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user-token"):
            flash("You need to log in first.", "error")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    return render_template('index.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        Auth().register(request)
        flash("Customer registered successfully.")
        return redirect("/login")
    return render_template("auth/register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = Auth().authenticate(request)
        if email:
            session["user-token"] = email
            flash("Login successful!", "success")
            next_page = request.args.get("next")
            return redirect(next_page) if next_page else redirect("/pet-store")
        else:
            flash("Invalid email or password. Please try again.", "error")
    return render_template('auth/login.html')


@app.route("/pet-store")
@login_required
def pet_store():
    user = Auth().get_user_details(session.get("user-token"))
    pets = PetStore().get_pets()
    return render_template("store.html", pets=pets, user=user)


@app.route('/cart/<int:pet_id>')
@login_required
def cart(pet_id):
    customer = PetStore().buy_pet(pet_id)
    return render_template("cart.html", pet=PetStore().get_pet(pet_id), customer=customer)


@app.route('/update_user', methods=['GET', 'POST'])
@login_required
def update_user():
    auth = Auth()
    if request.method == "POST":
        auth.update_user_details(request)
        flash("User details updated successfully.", "success")
        return redirect(url_for('update_user'))
    user_details = auth.get_user_details(session.get("user-token"))
    return render_template('update_user.html', user_details=user_details)


@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    auth = Auth()
    if request.method == "POST":
        auth.delete_user_account()
        session.pop("user-token", None)
        flash("Account deleted successfully.", "success")
        return redirect(url_for('index'))
    user_details = auth.get_user_details(session.get("user-token"))
    return render_template('delete-account.html', user_details=user_details)


@app.route('/logout')
@login_required
def logout():
    session.pop("user-token", None)
    flash("You have been logged out.", "success")
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
