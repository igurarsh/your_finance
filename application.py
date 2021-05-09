import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import date
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Getting user current balance
    user = db.execute("SELECT cash FROM users WHERE id=:user_id",user_id=session["user_id"])
    if user is None:
        return apology("Something Went Wrong (:",400)
    usercash = user[0]["cash"]

    # Gettingh user stock information now
    info = db.execute("SELECT symbol,SUM(no_stocks) as total_shares FROM history WHERE user_id=:user_id GROUP BY symbol",user_id=session["user_id"])

    current_price={}
    for cur_pri in info:
        current_price[cur_pri["symbol"]]=lookup(cur_pri["symbol"])

    return render_template("index.html",info=info,cash_remaining=usercash,current_price=current_price)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # Checking User Enteries
        result_checks = is_provided("symbol") or is_provided("shares")
        if result_checks is not None:
            return result_checks
        try:
            share=int(request.form.get("shares"))
        except:
            return apology("Please provide valid number of shares")
        if share <= 0:
            return apology("Please provide valid number of shares")

        # Genrating stock information
        symbol = lookup(request.form.get("symbol"))
        if symbol == None:
            return apology("Invalid Symbol",400)
        price = symbol['price']
        try:
            rows = db.execute("Select cash from users WHERE id = :user_id",user_id=session["user_id"])
        except:
            return apology("Something went wrong :(",403)

        usercash = rows[0]["cash"]
        final_price = price*share

        if final_price > usercash:
            return apology("Insufficient Funds",400)
        # Inserting data for history
        today = date.today()
        try:
            insert = db.execute("INSERT INTO history (user_id,symbol,no_stocks,price,creat_date) VALUES (:user,:symbol,:nos,:price,:today)",
                user=session["user_id"],symbol=request.form.get("symbol"),nos=share,price=price,today=today)
        except:
            return apology("Something went wrong :(",403)

        # Updating user details
        new_balance=usercash-final_price
        try:
            update_sql = db.execute("UPDATE users SET cash = :balance",balance=new_balance)
        except:
            return apology("Something went wrong :(",403)
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    trans = db.execute("SELECT * from history WHERE user_id=:user_id",user_id=session["user_id"])
    return render_template("history.html",trans=trans)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username and password was submitted
        result_checks = is_provided("username") or is_provided("password")

        if result_checks is not None:
            return result_checks

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        result_check = is_provided("symbol")
        if result_check is not None:
            return result_check
        symbol = request.form.get("symbol").upper()
        stock = lookup(symbol)
        if stock == None:
            return apology("Invalid Symbol",400)
        return render_template("quoted.html",stock={
            'name': stock['name'],
            'symbol': stock['symbol'],
            'price': usd(stock['price'])
        })
    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Checking User request method
    if request.method == "POST":
        # Checking if the fields are provided
        result_checks = is_provided("username") or is_provided("password") or is_provided("confirmation")
        if result_checks != None:
            return result_checks
        # Now entering data into sql
        try:
            sqlen = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",username=request.form.get("username"),
                            hash=generate_password_hash(request.form.get("password")))
        except:
            return apology("Username already exists",403)

        if sqlen is None:
            return apology("Registration Error",403)
        session["user_id"] = sqlen
        return redirect("/")

    else:
        return render_template("register.html")

@app.route("/update", methods=["GET", "POST"])
@login_required
def change_password():
    """Change Password"""
    # Checking User request method
    if request.method == "POST":
        # Checking if the fields are provided
        result_checks = is_provided("old_password") or is_provided("new_password") or is_provided("new_confirm")
        if result_checks != None:
            return result_checks

        #Now checking the passwords Match
        old_info=db.execute("SELECT hash FROM users WHERE id=:user_id",user_id=session["user_id"])

        if check_password_hash(old_info[0]["hash"],request.form.get("old_password")) == False:
            return apology("Please make sure the old password is correct",403)

        new_password=request.form.get("new_password")
        new_confirm=request.form.get("new_confirm")

        if new_password != new_confirm:
            return apology("Please make sure you have entered same password",403)
        # Now entering data into sql
        try:
            sqlen = db.execute("UPDATE users SET hash = :hash WHERE id=:user_id",
                hash=generate_password_hash(request.form.get("new_confirm")),user_id=session["user_id"])
        except:
            return apology("Something Went Wrong Try Again",403)

        if sqlen is None:
            return redirect("/logout")
        return redirect("/logout")

    else:
        return render_template("update.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # Showing Stocks available for Sale
    # Getting user current balance
    user = db.execute("SELECT cash FROM users WHERE id=:user_id",user_id=session["user_id"])
    if user is None:
        return apology("Something Went Wrong (:",400)
    usercash = user[0]["cash"]

    # Gettingh user stock information now
    info = db.execute("SELECT symbol,SUM(no_stocks) as total_shares FROM history WHERE user_id=:user_id GROUP BY symbol",user_id=session["user_id"])

    current_price={}
    for cur_pri in info:
        current_price[cur_pri["symbol"]]=lookup(cur_pri["symbol"])

    # Code for selling stocks based on user selection
    if request.method == "POST":
        # Number of stocks user wanna sell
        units=int(request.form.get("units"))
        symbol=request.form.get("stocks")
        stock_info = lookup(request.form.get("stocks"))
        # Latest price of the stock selected by the user
        price = stock_info['price']
        if units <= 0:
            return apology("Please enter valid number of Stocks",400)

        stocks_checking = db.execute("SELECT SUM(no_stocks) as total_shares FROM history WHERE user_id=:user_id AND symbol=:symbol GROUP BY symbol"
                            ,user_id=session["user_id"],symbol=symbol)
        # Checking How many stocks user have
        available_stocks=stocks_checking[0]["total_shares"]
        if available_stocks<units:
            return apology("Not have enough stocks",400)

        total_price=units*price
        # Now updating data base after selling the stocks
        today = date.today()
        db.execute("UPDATE users SET cash = cash + :price WHERE id = :user_id", price=total_price, user_id=session["user_id"])
        db.execute("INSERT INTO history (user_id, symbol, no_stocks, price,creat_date) VALUES(:user_id, :symbol, :shares, :price, :date)",
                   user_id=session["user_id"],
                   symbol=request.form.get("stocks"),
                   shares=-units,
                   price=price,
                   date=today)
        #Getting Current price of the stock
        return render_template("sell.html",info=info,cash_remaining=usercash,current_price=current_price)

    # Normal rendering
    return render_template("sell.html",info=info,cash_remaining=usercash,current_price=current_price)

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

# Coustom code
def is_provided(field):
    if not request.form.get(field):
        return apology(f"Must provide {field}",403)
