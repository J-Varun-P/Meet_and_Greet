from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


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


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project.db")

db2 = SQL("sqlite:///movies.db")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    user = db.execute("SELECT * from users where id=:id", id = session["user_id"])
    name = user[0]["name"][0].upper() + user[0]["name"][1:].lower()
    from_email = user[0]["email"]
    if request.method == "GET":
        rows = db.execute("SELECT post.id, message, name, time from users join post on users.id = post.id")
        return render_template("index.html", name=name, rows=rows)
    else:
        to = request.form.get("id")
        #print(to, session["user_id"])
        if int(to) != session["user_id"]:
            time = request.form.get("time")
            user = db.execute("SELECT * from post where id=:id and time=:time", id=to, time=time)
            fro = session["user_id"]
            datetime = db.execute("SELECT datetime('now')")
            ack = 0
            db.execute("INSERT into inbox(from_user, to_user, message, time, from_name, from_email, ack) VALUES(:from_user, :to_user, :message, :time, :from_name, :from_email, :ack)", from_user=fro, to_user=to, message=user[0]["message"], time=datetime[0]["datetime('now')"], from_name=name, from_email=from_email, ack=ack)
        return redirect("/")


@app.route("/post", methods=["GET", "POST"])
@login_required
def post():
    user = db.execute("SELECT * from users where id=:id", id = session["user_id"])
    name =user[0]["name"][0].upper() + user[0]["name"][1:].lower()
    if request.method == "GET":
        return render_template("post.html", name=name)
    else:
        message = request.form.get("message")
        datetime = db.execute("SELECT datetime('now')")
        db.execute("INSERT into post(id, message, time) VALUES(:id, :message, :time)", id=session["user_id"], message=message, time=datetime[0]["datetime('now')"])
        return redirect("/")


@app.route("/history", methods=["GET", "POST"])
@login_required
def history():
    if request.method == "GET":
        user = db.execute("SELECT * from users where id=:id", id = session["user_id"])
        name =user[0]["name"][0].upper() + user[0]["name"][1:].lower()
        rows = db.execute("SELECT post.id, message, name, time from users join post on users.id = post.id and users.id=:id", id=session["user_id"])
        return render_template("history.html", name=name, rows=rows)
    else:
        time = request.form.get("time")
        db.execute("DELETE from post where id=:id and time=:time", id=session["user_id"], time=time)
        return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("name"):
            return "must provide username"

        # Ensure password was submitted
        elif not request.form.get("password"):
            return "must provide password"

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE name = :name",
                          name=request.form.get("name"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            return "invalid username and/or password"

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


@app.route("/inbox", methods=["GET", "POST"])
@login_required
def inbox():
    if request.method == "GET":
        user = db.execute("SELECT * from users where id=:id", id = session["user_id"])
        name =user[0]["name"][0].upper() + user[0]["name"][1:].lower()
        rows = db.execute("SELECT * from inbox where to_user=:to_user", to_user=session["user_id"])
        return render_template("inbox.html", name=name, rows=rows)
    else:
        time = request.form.get("time")
        from_user = request.form.get("id")
        db.execute("DELETE from inbox where to_user=:to_user and from_user = :from_user and time=:time", to_user=session["user_id"], from_user=from_user, time=time)
        return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        if not request.form.get("name"):
            return "must provide username"
        elif not request.form.get("email"):
            return "must provide email"
        elif not request.form.get("password"):
            return "must provide password"
        elif request.form.get("password") != request.form.get("password_c"):
            return "password and confirmation password don't match"

        rows = db.execute("SELECT * from users WHERE name = :name", name=request.form.get("name"))

        if len(rows) == 1:
            return "username taken, please select another one"
        else:
            password = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
            db.execute("INSERT into users(name, email, password) VALUES(:name, :email, :password)", name=request.form.get("name"), email=request.form.get("email"), password=password)
            #db.execute("INSERT into participants(username, valuation) VALUES(:username, :valuation)", username=request.form.get("username"), valuation=0)
            return redirect("/login")


@app.route("/acknowledge", methods=["GET", "POST"])
@login_required
def acknowledge():
    if request.method == "POST":
        user1 = db.execute("SELECT * from users where id=:id", id = session["user_id"])
        name = user1[0]["name"][0].upper() + user1[0]["name"][1:].lower()
        from_email = user1[0]["email"]
        to = request.form.get("id")
        message = request.form.get("message")
        fro = session["user_id"]
        datetime = db.execute("SELECT datetime('now')")
        ack = 1
        db.execute("INSERT into inbox(from_user, to_user, message, time, from_name, from_email, ack) VALUES(:from_user, :to_user, :message, :time, :from_name, :from_email, :ack)", from_user=fro, to_user=to, message=message, time=datetime[0]["datetime('now')"], from_name=name, from_email=from_email, ack=ack)
        return redirect("/")



@app.route("/movies", methods=["GET", "POST"])
@login_required
def movies():
    user = db.execute("SELECT * from users where id=:id", id = session["user_id"])
    name =user[0]["name"][0].upper() + user[0]["name"][1:].lower()
    checking = "False"
    if request.method == "GET":
        return render_template("movies.html", name=name)
    else:
        final = []
        name = request.form.get("name")
        if request.form.get("name") != '':
            names = name.split(",")
            checking = "False"
            actors = []
            temp = []
            for actor in names:
                actors.append(actor.strip())
            i = 0
            b1 = 0
            if request.form.get("birth") != "":
                birth = request.form.get("birth")
                birth_1 = birth.split(",")
                birth_2 = []
                for birth_3 in birth_1:
                    birth_2.append(birth_3.strip())
            #name = "Julia Roberts"
            for actor in actors:
                name = actor
                actor_count = 0
                if request.form.get("birth") == '':
                    name_id = db2.execute("SELECT distinct(directors.movie_id), person_id from directors join people join ratings where directors.person_id=people.id and ratings.movie_id=directors.movie_id and name=:name and votes >= 10000", name = actor)
                    name_id1 = db2.execute("SELECT distinct(stars.movie_id), person_id from stars join people join ratings where stars.person_id=people.id and ratings.movie_id=stars.movie_id and name=:name and votes >= 10000", name = actor)
                    if len(name_id1) > len(name_id):
                        actor_count = 1
                    person_id1 = db2.execute("SELECT distinct(person_id) from directors join people where directors.person_id=people.id and name=:name", name=actor)
                    person_id2 = db2.execute("SELECT distinct(person_id) from stars join people where stars.person_id=people.id and name=:name", name=actor)
                    if len(person_id1) != 0 and len(person_id2) != 0:
                        if person_id1[0]["person_id"] != person_id2[0]["person_id"]:
                            checking = "True"
                    elif len(name_id1) + len(name_id) > 1 and len(name_id) != 0 and len(name_id1) != 0:
                        checking = "True"
                else:
                    name_id = db2.execute("SELECT distinct(directors.movie_id) from directors join people join ratings where directors.person_id=people.id and ratings.movie_id=directors.movie_id and name=:name and birth=:birth and votes >= 10000", name = actor, birth=birth_2[b1])
                    name_id1 = db2.execute("SELECT distinct(stars.movie_id) from stars join people join ratings where stars.person_id=people.id and ratings.movie_id=stars.movie_id and name=:name and birth=:birth and votes >= 10000", name = actor, birth=birth_2[b1])
                    if len(name_id1) > len(name_id):
                        actor_count = 1
                if request.form.get("birth") == '':
                    if actor_count == 1:
                        rows = db2.execute("SELECT movies.title, year, rating from movies join stars join people join ratings where stars.movie_id = movies.id and ratings.movie_id=movies.id and stars.person_id = people.id and name=:name and votes >= 10000 order by year, rating DESC", name=name)
                    else:
                        rows = db2.execute("SELECT movies.title, year, rating from movies join directors join people join ratings where directors.movie_id = movies.id and ratings.movie_id=movies.id and directors.person_id = people.id and name=:name and votes >= 10000 order by year, rating DESC", name=name)
                else:
                    #birth = request.form.get("birth")
                    if actor_count == 1:
                        rows = db2.execute("SELECT movies.title, year, rating from movies join stars join people join ratings where stars.movie_id = movies.id and ratings.movie_id=movies.id and stars.person_id = people.id and name=:name and birth=:birth and votes >= 10000 order by year, rating DESC", name=name, birth=birth_2[b1])
                    else:
                        rows = db2.execute("SELECT movies.title, year, rating from movies join directors join people join ratings where directors.movie_id = movies.id and ratings.movie_id=movies.id and directors.person_id = people.id and name=:name and birth=:birth and votes >= 10000 order by year, rating DESC", name=name, birth=birth_2[b1])
                print(len(rows))
                for row in rows:
                    temp.append([row["title"], row["year"], row["rating"]])
                    if i == 0:
                        final.append([row["title"], row["year"], row["rating"]])
                print(len(final))
                i += 1
                j1 = 0
                n1 = len(final)
                if i > 1:
                    for j in range(0, n1):
                        if final[j1] not in temp:
                            final.remove(final[j1])
                        else:
                            j1 += 1
                temp.clear()
                b1 += 1
            if request.form.get("imdb") != "":
                if request.form.get("name") != "":
                    n1 = len(final)
                    j1 = 0
                    for j in range(0, n1):
                        if str(final[j1][2]) < request.form.get("imdb"):
                            final.remove(final[j1])
                        else:
                            j1 += 1
        elif request.form.get("imdb") != "":
            final = []
            rating = request.form.get("imdb", type=float)
            print(rating)
            rows = db2.execute("SELECT movies.title, year, rating from movies join ratings where ratings.movie_id=movies.id and rating >= :rating and votes >= 10000 order by year, rating DESC", rating=rating)
            for row in rows:
                final.append([row["title"], row["year"], row["rating"]])
        if len(final) == 0 and (request.form.get("year_start") != "" or request.form.get("year_end") != ""):
            if request.form.get("year_start") != "":
                year = request.form.get("year_start")
                rows = db2.execute("SELECT movies.title, year, rating from movies join ratings where ratings.movie_id=movies.id and year >= :year and votes >= 10000 order by year, rating DESC", year=year)
                for row in rows:
                    final.append([row["title"], row["year"], row["rating"]])
            else:
                year = request.form.get("year_end")
                rows = db2.execute("SELECT movies.title, year, rating from movies join ratings where ratings.movie_id=movies.id and year <= :year and votes >= 10000 order by year, rating DESC", year=year)
                for row in rows:
                    final.append([row["title"], row["year"], row["rating"]])
        if request.form.get("year_start") != "":
            if request.form.get("year_end") != "":
                n1 = len(final)
                j1 = 0
                for j in range(0, n1):
                    if str(final[j1][1]) < request.form.get("year_start") or str(final[j1][1]) > request.form.get("year_end"):
                        final.remove(final[j1])
                    else:
                        j1 += 1
            else:
                n1 = len(final)
                j1 = 0
                for j in range(0, n1):
                    if str(final[j1][1]) < request.form.get("year_start"):
                        final.remove(final[j1])
                    else:
                        j1 += 1
        elif request.form.get("year_end") != "":
            n1 = len(final)
            j1 = 0
            for j in range(0, n1):
                if str(final[j1][1]) > request.form.get("year_end"):
                    final.remove(final[j1])
                else:
                    j1 += 1
        return render_template("movie_rec.html", name=name, final=final, checking=checking)






