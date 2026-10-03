from flask import Flask, request, make_response, render_template_string, redirect
import jwt
import os

app = Flask(__name__)

SECRET = "princess1"

FLAG = "WHITESEC{jwt_w34k_s3cr3t_pwn3d}"

USERS = {"guest": "guest123"}

PAGE = """
<html>
<body style="font-family:monospace;background:#0b1a1a;color:#5eead4;padding:2rem">

<h2>WhiteSec Vault</h2>
{{ body|safe }}

</body>
</html>
"""


def page(body):
    return render_template_string(PAGE, body=body)


@app.route("/")
def index():
    return page(
        '<p>Members only. <a href="/login">Login</a> | '
        '<a href="/dashboard">Dashboard</a> | '
        '<a href="/admin">Admin</a></p>'
        '<p>Hint: guest credentials are guest / guest123</p>'
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")

        if USERS.get(u) == p:
            tok = jwt.encode(
                {"user": u, "role": "user"},
                SECRET,
                algorithm="HS256"
            )

            r = make_response(redirect("/dashboard"))
            r.set_cookie("session", tok)

            return r

        return page("<p>Invalid credentials.</p>"), 401

    return page(
        '<form method="post">'
        'user <input name="username"><br>'
        'pass <input name="password" type="password"><br>'
        '<button>Login</button>'
        '</form>'
    )


def current():
    tok = request.cookies.get("session")

    if not tok:
        return None

    try:
        return jwt.decode(
            tok,
            SECRET,
            algorithms=["HS256"]
        )
    except Exception:
        return None


@app.route("/dashboard")
def dashboard():
    c = current()

    if not c:
        return redirect("/login")

    return page(
        f"<p>Welcome, {c['user']}. Your role: {c['role']}.</p>"
        "<p>Nothing to see here unless you are an admin.</p>"
    )


@app.route("/admin")
def admin():
    c = current()

    if not c:
        return redirect("/login")

    if c.get("role") != "admin":
        return page("<p>403 - admins only.</p>"), 403

    return page(f"<p>Vault unlocked: {FLAG}</p>")


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )