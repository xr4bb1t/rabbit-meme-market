"""
Rabbit Meme Market - an INTENTIONALLY VULNERABLE, IDOR-only CTF lab (desi edition).

Inspired by the challenge-based style of OWASP crAPI, but web-based and focused purely on
Insecure Direct Object Reference (IDOR). Six CTF challenges cover every IDOR type. Each
victim object hides a funny FLAG{...} you only see when you access something that isn't yours.
Students can even sign up in their own name and hack each other.

  Vulnerable mode:   docker compose up --build        (or: python app.py)
  Fixed mode:        SECURE=1 docker compose up ...    (or: SECURE=1 python app.py)
  CTF board:         http://127.0.0.1:5000/ctf
  Reset the data:    http://127.0.0.1:5000/reset

Accounts:  alice / alice123   bob / bob123   admin / admin123   (ya khud ka bana le /signup se)

!! Intentionally insecure. Run on localhost only. Never deploy publicly. !!
"""

import os
import sqlite3
from functools import wraps
from flask import (Flask, g, session, request, redirect, url_for, Response,
                   render_template_string, jsonify, abort, flash)

DATABASE = os.path.join(os.path.dirname(__file__), "market.db")
SECURE = os.environ.get("SECURE", "0") == "1"      # flip to 1 to turn the fixes ON
HOST = os.environ.get("HOST", "127.0.0.1")         # Docker sets this to 0.0.0.0

app = Flask(__name__)
app.secret_key = "lab-only-not-a-real-secret"

# The six flags - desi meme edition. A student only sees one by exploiting that challenge.
FLAGS = {
    "c1": "FLAG{chalo_kuch_to_mila_bade_bhai}",
    "c2": "FLAG{aree_khaa_ab_kya_talaab_bana_du}",
    "c3": "FLAG{kya_faltu_chij_download_ki}",
    "c4": "FLAG{Bahut_paisa_bade_bhai}",
    "c5": "FLAG{wahh_yaar_yaha_tak_ki_line_hai}",
    "c6": "FLAG{FUNction_to_set}",
}
CHALLENGES = [
    ("c1", "Horizontal IDOR - order enumeration", "Horizontal",
     "GET /api/orders/<id>", "Teri order id choti hai. Bagal wali try kar."),
    ("c2", "Horizontal IDOR - profile via ?user_id=", "Horizontal",
     "GET /api/profile?user_id=<n>", "Jiska profile aata hai uski id URL me hi padi hai."),
    ("c3", "Download IDOR - invoice file", "Horizontal",
     "GET /api/files/download?file_id=<n>", "File number badal, dusre ki maang le."),
    ("c4", "Object-level IDOR - edit a listing you don't own", "Object-level",
     "POST /api/listings/<id>/price", "Apni listing padh sakta hai. Dusre ki likh sakta hai?"),
    ("c5", "Vertical IDOR - admin dashboard", "Vertical",
     "GET /api/admin/dashboard", "Admin-only page, role check gayab hai. Bas maang le."),
    ("c6", "Function-level IDOR - approve a listing (BFLA)", "Function-level",
     "POST /api/listings/<id>/approve", "Approve karna admin ka kaam hai. Check hai bhi ya nahi?"),
]


# ----------------------------------------------------------------------------
# Database
# ----------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript("""
        DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS listings; DROP TABLE IF EXISTS orders;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT,
            email TEXT, address TEXT, card_last4 TEXT);
        CREATE TABLE listings (id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT, art TEXT,
            price INTEGER, status TEXT);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, buyer_id INTEGER, item TEXT, amount INTEGER,
            ship_to TEXT, card_last4 TEXT, status TEXT);
    """)
    db.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?)", [
        (1, "alice", "alice123", "user",  "alice@email.com", "12 Carrot Lane, Warren City", "4242"),
        (2, "bob",   "bob123",   "user",  "bob@email.com",   "88 Burrow Road, Thumper Town", "7781"),
        (3, "admin", "admin123", "admin", "admin@rabbit.market", "1 HQ Plaza", "0001"),
    ])
    db.executemany("INSERT INTO listings VALUES (?,?,?,?,?,?)", [
        (1, 1, "Distracted Sigma Rabbit", "\U0001F430\U0001F5FF", 120, "live"),
        (2, 1, "Monday Wali Feeling",     "\U0001F430\U0001F635", 90,  "live"),
        (3, 2, "Trust Issues Hare",       "\U0001F407\U0001F576",  150, "live"),
        (4, 2, "Paisa Hi Paisa Hoga",     "\U0001F430\U0001F4B0", 200, "live"),
        (5, 3, "Admin Approved OG Meme",  "\U0001F430\u2705",      300, "live"),
        (6, 2, "Fresh Drop (review pending)", "\U0001F430\U0001F195", 175, "pending"),
    ])
    db.executemany("INSERT INTO orders VALUES (?,?,?,?,?,?,?)", [
        (1001, 1, "Trust Issues Hare",  150, "12 Carrot Lane, Warren City", "4242", "paid"),
        (1002, 2, "Distracted Sigma Rabbit", 120, "88 Burrow Road, Thumper Town", "7781", "paid"),
        (1003, 2, "Monday Wali Feeling",  90, "88 Burrow Road, Thumper Town", "7781", "shipped"),
    ])
    db.commit()
    db.close()


# ----------------------------------------------------------------------------
# Auth (authentication works; authorization is what's missing)
# ----------------------------------------------------------------------------
def current_user():
    uid = session.get("uid")
    return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() if uid else None


def login_required(f):
    @wraps(f)
    def wrap(*a, **k):
        if not current_user():
            if request.path.startswith("/api/"):
                abort(401)
            return redirect(url_for("login"))
        return f(*a, **k)
    return wrap


def deny_if_not_owner(owner_id):
    if SECURE:
        u = current_user()
        if not u or u["id"] != owner_id:
            abort(403)


def deny_if_not_admin():
    if SECURE:
        u = current_user()
        if not u or u["role"] != "admin":
            abort(403)


# ----------------------------------------------------------------------------
# Templates
# ----------------------------------------------------------------------------
BASE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>Rabbit Meme Market</title><style>
:root{--bg:#1b1b1b;--surface:#292929;--text:#ffffff;--muted:#808080;--accent:#ffa31a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,Segoe UI,Roboto,sans-serif;line-height:1.55}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header{display:flex;align-items:center;gap:18px;padding:14px 22px;background:var(--surface);border-bottom:2px solid var(--accent)}
header .logo{font-weight:800;font-size:19px}header .logo .a{color:var(--accent)}
header nav{display:flex;gap:16px;margin-left:auto;align-items:center;font-size:14px;flex-wrap:wrap}
header .who{color:var(--muted)}
.wrap{max-width:900px;margin:0 auto;padding:26px 22px 70px}
h1{font-size:26px;margin:0 0 6px}h2{font-size:19px;margin:26px 0 10px}
.muted{color:var(--muted)}
.banner{background:#2a2a2a;border:1px solid var(--accent);border-radius:10px;padding:10px 14px;color:var(--accent);font-size:13px;margin-bottom:14px}
.gyaan{background:var(--surface);border-left:3px solid var(--accent);border-radius:8px;padding:10px 14px;font-size:13px;color:var(--muted);margin-bottom:18px}
.gyaan b{color:var(--accent)}
.flash{background:var(--accent);color:#1b1b1b;border-radius:8px;padding:10px 14px;font-weight:600;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px}
.card{background:var(--surface);border:1px solid #3a3a3a;border-radius:12px;padding:16px}
.card .art{font-size:40px}.card .title{font-weight:700;margin:6px 0 2px}
.card .price{color:var(--accent);font-weight:700}
.card .seller{color:var(--muted);font-size:13px;margin-top:4px}
table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid #3a3a3a;border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:11px 14px;border-bottom:1px solid #3a3a3a;font-size:14px}
th{color:var(--muted);font-weight:600}tr:last-child td{border-bottom:none}
.btn{display:inline-block;background:var(--accent);color:#1b1b1b;font-weight:700;border:none;border-radius:9px;padding:9px 16px;cursor:pointer;font-size:14px}
.btn.ghost{background:transparent;color:var(--accent);border:1px solid var(--accent)}
.btn.danger{background:#808080;color:#1b1b1b}
input{background:#1b1b1b;border:1px solid #3a3a3a;color:#fff;border-radius:8px;padding:9px 11px;font-size:14px}
label{display:block;color:var(--muted);font-size:13px;margin:12px 0 4px}
code{background:#1b1b1b;border:1px solid #3a3a3a;border-radius:5px;padding:1px 6px;font-size:13px;color:var(--accent)}
.kv{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px dashed #3a3a3a}.kv:last-child{border:none}
.kv .k{color:var(--muted)}
.pill{display:inline-block;font-size:12px;font-weight:700;padding:2px 9px;border-radius:999px;background:var(--accent);color:#1b1b1b}
.pill.g{background:#808080}.pill.done{background:#2e7d32;color:#fff}
.flag{background:#1b1b1b;border:1px dashed var(--accent);color:var(--accent);border-radius:8px;padding:10px 12px;font-family:monospace;margin-top:10px;word-break:break-all;font-size:15px}
footer{color:var(--muted);font-size:12px;text-align:center;padding:30px 0}
</style></head><body>
<header><span class=logo>\U0001F430 Rabbit<span class=a>Meme</span>Market</span>
<nav><a href="/">Mandi</a>{% if user %}<a href="/account">Mera account</a>{% endif %}
{% if user and user['role']=='admin' %}<a href="/admin">Admin</a>{% endif %}
<a href="/ctf">Jugaad Zone ({{ solved_count }}/6)</a>
{% if user %}<span class=who>{{ user['username'] }}</span><a href="/logout">Nikal</a>
{% else %}<a href="/login">Log in</a><a href="/signup">Sign up</a>{% endif %}</nav></header>
<div class=wrap>
<div class=banner>\u26A0 Practice lab &mdash; jaan boojh ke vulnerable banaya hai. Mode:
{% if secure %}<b>SECURE (fix ON \U0001F512)</b>{% else %}<b>VULNERABLE (fix OFF \U0001F9A5)</b>{% endif %}. Sirf localhost pe chalana.</div>
{% with m=get_flashed_messages() %}{% if m %}<div class=flash>{{ m[0] }}</div>{% endif %}{% endwith %}
{{ content|safe }}</div>
<footer>Rabbit Meme Market &middot; sirf seekhne ke liye banaya &middot; asli jagah mat chalana warna bade bhai naraz \U0001F620</footer>
</body></html>"""


def page(inner, **ctx):
    solved = session.get("solved", [])
    html = render_template_string(inner, user=current_user(), secure=SECURE,
                                  solved_count=len(solved), **ctx)
    return render_template_string(BASE, content=html, user=current_user(), secure=SECURE,
                                  solved_count=len(solved))


# ----------------------------------------------------------------------------
# Public market + buying
# ----------------------------------------------------------------------------
@app.route("/")
def home():
    rows = get_db().execute(
        "SELECT l.*, u.username AS seller FROM listings l JOIN users u ON u.id=l.owner_id "
        "WHERE l.status='live' ORDER BY l.id").fetchall()
    inner = """
    <h1>\U0001F430 Meme Mandi</h1>
    <p class=muted>Sasta, tikau, aur thoda <i>illegal</i> \U0001F60F. Log in karke apna meme uthao,
    ya phir seedha <a href="/ctf">Jugaad Zone</a> me ghus ke bug maaro.</p>
    <div class=gyaan><b>Aaj ka gyaan:</b> &ldquo;Jo id dikhti hai, wo apni nahi hoti.&rdquo; &mdash; Bade Bhai \U0001F9D8</div>
    <div class=grid>{% for l in rows %}<div class=card>
      <div class=art>{{ l['art'] }}</div><div class=title>{{ l['title'] }}</div>
      <div class=price>{{ l['price'] }} coins</div>
      <div class=seller>by {{ l['seller'] }} &middot; #{{ l['id'] }}</div>
      {% if user %}<form method=post action="/buy/{{ l['id'] }}" style="margin-top:10px">
        <button class=btn>Le lo \U0001F6D2</button></form>{% endif %}
    </div>{% endfor %}</div>"""
    return page(inner, rows=rows)


@app.route("/buy/<int:lid>", methods=["POST"])
@login_required
def buy(lid):
    u = current_user()
    l = get_db().execute("SELECT * FROM listings WHERE id=?", (lid,)).fetchone()
    if not l:
        abort(404)
    db = get_db()
    cur = db.execute("INSERT INTO orders (buyer_id,item,amount,ship_to,card_last4,status) "
                     "VALUES (?,?,?,?,?,?)",
                     (u["id"], l["title"], l["price"], u["address"], u["card_last4"], "paid"))
    db.commit()
    flash("Order ho gaya boss! \U0001F389  (order #%d)" % cur.lastrowid)
    return redirect(url_for("account"))


# ----------------------------------------------------------------------------
# Auth + signup
# ----------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        row = get_db().execute("SELECT * FROM users WHERE username=? AND password=?",
                               (request.form.get("username"), request.form.get("password"))).fetchone()
        if row:
            session["uid"] = row["id"]
            flash("Wapas aa gaya, %s! \U0001F525" % row["username"])
            return redirect(url_for("account"))
        flash("Galat naam ya password bhai \U0001F614")
    inner = """
    <h1>Andar aao \U0001F6AA</h1><form method=post style="max-width:320px">
      <label>Username</label><input name=username autofocus>
      <label>Password</label><input name=password type=password>
      <div style="margin-top:16px"><button class=btn>Ghus jao</button></div></form>
    <p class=muted style="margin-top:18px">Ready-made accounts:
      <code>alice/alice123</code>, <code>bob/bob123</code>, <code>admin/admin123</code>
      &mdash; ya <a href="/signup">apna bana le</a>.</p>"""
    return page(inner)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        un = (request.form.get("username") or "").strip()
        pw = request.form.get("password") or ""
        if not un or not pw:
            flash("Naam aur password dono daal bhai \U0001F624")
        elif get_db().execute("SELECT 1 FROM users WHERE username=?", (un,)).fetchone():
            flash("Ye naam already liya hua hai, dusra soch \U0001F643")
        else:
            db = get_db()
            cur = db.execute(
                "INSERT INTO users (username,password,role,email,address,card_last4) VALUES (?,?,?,?,?,?)",
                (un, pw, "user", un + "@memer.market", "Apna Ghar, Internet Gali", "1337"))
            db.commit()
            session["uid"] = cur.lastrowid
            flash("Account ban gaya, welcome %s! Ab jaa, bug dhoond \U0001F430" % un)
            return redirect(url_for("ctf"))
    inner = """
    <h1>Naya banda? \U0001F195</h1>
    <p class=muted>Apne naam ka account bana le &mdash; phir class me ek dusre ko hack karna \U0001F608.</p>
    <form method=post style="max-width:320px">
      <label>Username (apna naam daal de)</label><input name=username autofocus>
      <label>Password</label><input name=password type=password>
      <div style="margin-top:16px"><button class=btn>Bana do account</button></div></form>"""
    return page(inner)


@app.route("/logout")
def logout():
    solved = session.get("solved", [])
    session.clear()
    session["solved"] = solved           # CTF progress bacha ke rakho
    return redirect(url_for("home"))


# ----------------------------------------------------------------------------
# My account (legitimate baseline views)
# ----------------------------------------------------------------------------
@app.route("/account")
@login_required
def account():
    u = current_user()
    db = get_db()
    orders = db.execute("SELECT * FROM orders WHERE buyer_id=? ORDER BY id", (u["id"],)).fetchall()
    listings = db.execute("SELECT * FROM listings WHERE owner_id=? ORDER BY id", (u["id"],)).fetchall()
    inner = """
    <h1>Scene kya hai, {{ user['username'] }}! \U0001F44B</h1>
    <div class=card style="max-width:420px">
      <div class=kv><span class=k>User id</span><span>{{ user['id'] }}</span></div>
      <div class=kv><span class=k>Email</span><span>{{ user['email'] }}</span></div>
      <div class=kv><span class=k>Address</span><span>{{ user['address'] }}</span></div>
      <div class=kv><span class=k>Card</span><span>&bull;&bull;&bull;&bull; {{ user['card_last4'] }}</span></div>
      <div class=kv><span class=k>Role</span><span>{{ user['role'] }}</span></div></div>
    <p class=muted style="margin-top:8px">Ye apni id yaad rakh &mdash; ab doosro ki id pe haath saaf kar \U0001F60F</p>
    <h2>Mere orders</h2>
    <table><tr><th>Order</th><th>Item</th><th>Amount</th><th>Invoice</th><th></th></tr>
    {% for o in orders %}<tr><td>#{{ o['id'] }}</td><td>{{ o['item'] }}</td>
      <td>{{ o['amount'] }} coins</td>
      <td><a href="/api/files/download?file_id={{ o['id'] }}">download</a></td>
      <td><a href="/order/{{ o['id'] }}">view</a></td></tr>{% endfor %}
    {% if not orders %}<tr><td colspan=5 class=muted>Abhi tak koi order nahi. Jaa kuch le aa.</td></tr>{% endif %}</table>
    <h2>Meri listings</h2>
    <table><tr><th>ID</th><th>Meme</th><th>Price</th><th>Status</th><th></th></tr>
    {% for l in listings %}<tr><td>#{{ l['id'] }}</td><td>{{ l['art'] }} {{ l['title'] }}</td>
      <td>{{ l['price'] }} coins</td><td>{{ l['status'] }}</td>
      <td><a href="/listing/{{ l['id'] }}">manage</a></td></tr>{% endfor %}
    {% if not listings %}<tr><td colspan=5 class=muted>Koi listing nahi (naye bande ho? koi na).</td></tr>{% endif %}</table>"""
    return page(inner, orders=orders, listings=listings)


# ----------------------------------------------------------------------------
# HTML views that mirror the vulnerable API (so you can test from the URL bar)
# ----------------------------------------------------------------------------
@app.route("/order/<int:oid>")
@login_required
def order_detail(oid):
    o = get_db().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not o:
        abort(404)
    deny_if_not_owner(o["buyer_id"])
    stolen = o["buyer_id"] != current_user()["id"]
    inner = """
    <p><a href="/account">&larr; Mera account</a></p><h1>Order #{{ o['id'] }}</h1>
    <div class=card style="max-width:440px">
      <div class=kv><span class=k>Item</span><span>{{ o['item'] }}</span></div>
      <div class=kv><span class=k>Amount</span><span>{{ o['amount'] }} coins</span></div>
      <div class=kv><span class=k>Ship to</span><span>{{ o['ship_to'] }}</span></div>
      <div class=kv><span class=k>Card</span><span>&bull;&bull;&bull;&bull; {{ o['card_last4'] }}</span></div>
      {% if stolen %}<div class=flag>\U0001F6A9 Le bhai, ye raha: {{ flag }}</div>{% endif %}</div>
    <p class=muted style="margin-top:12px">API: <code>GET /api/orders/{{ o['id'] }}</code></p>"""
    return page(inner, o=o, stolen=stolen, flag=FLAGS["c1"])


@app.route("/listing/<int:lid>")
@login_required
def listing_manage(lid):
    l = get_db().execute("SELECT * FROM listings WHERE id=?", (lid,)).fetchone()
    if not l:
        abort(404)
    inner = """
    <p><a href="/account">&larr; Mera account</a></p><h1>{{ l['art'] }} {{ l['title'] }}</h1>
    <p class=muted>Listing #{{ l['id'] }} &middot; owner id {{ l['owner_id'] }} &middot; status {{ l['status'] }}</p>
    <form method=post action="/api/listings/{{ l['id'] }}/price">
      <label>Price (coins)</label><input name=price value="{{ l['price'] }}">
      <div style="margin-top:14px"><button class=btn>Price set karo</button></div></form>
    <form method=post action="/api/listings/{{ l['id'] }}/delete" style="margin-top:14px">
      <button class="btn danger">Delete kardo</button></form>"""
    return page(inner, l=l)


@app.route("/admin")
@login_required
def admin():
    deny_if_not_admin()
    db = get_db()
    total = db.execute("SELECT COALESCE(SUM(amount),0) t FROM orders").fetchone()["t"]
    users = db.execute("SELECT id,username,role,email,card_last4 FROM users").fetchall()
    pend = db.execute("SELECT * FROM listings WHERE status='pending'").fetchall()
    stolen = current_user()["role"] != "admin"
    inner = """
    <h1>Admin dashboard \U0001F451</h1>
    <div class=card style="max-width:320px"><div class=kv><span class=k>Total sales</span>
      <span class=price>{{ total }} coins</span></div></div>
    {% if stolen %}<div class=flag>\U0001F6A9 Le bhai, ye raha: {{ flag }}</div>{% endif %}
    <h2>Saare customers (PII)</h2>
    <table><tr><th>ID</th><th>User</th><th>Role</th><th>Email</th><th>Card</th></tr>
    {% for u in users %}<tr><td>{{ u['id'] }}</td><td>{{ u['username'] }}</td><td>{{ u['role'] }}</td>
      <td>{{ u['email'] }}</td><td>&bull;&bull;&bull;&bull; {{ u['card_last4'] }}</td></tr>{% endfor %}</table>
    <h2>Pending listings (approval chahiye)</h2>
    <table><tr><th>ID</th><th>Meme</th><th>Owner</th><th></th></tr>
    {% for l in pend %}<tr><td>#{{ l['id'] }}</td><td>{{ l['title'] }}</td><td>{{ l['owner_id'] }}</td>
      <td><form method=post action="/api/listings/{{ l['id'] }}/approve"><button class=btn>Approve</button></form></td></tr>{% endfor %}
    {% if not pend %}<tr><td colspan=4 class=muted>Kuch pending nahi.</td></tr>{% endif %}</table>"""
    return page(inner, total=total, users=users, pend=pend, stolen=stolen, flag=FLAGS["c5"])


# ============================================================================
# VULNERABLE JSON API  (the main surface you swap ids on)
# ============================================================================

# C1 - Horizontal: read any order by id.  Signal: ?id= enumeration.
@app.route("/api/orders/<int:oid>")
@login_required
def api_order(oid):
    o = get_db().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not o:
        abort(404)
    deny_if_not_owner(o["buyer_id"])
    data = dict(o)
    if o["buyer_id"] != current_user()["id"]:
        data["flag"] = FLAGS["c1"]
    return jsonify(data)


# C2 - Horizontal (PII): read any profile.  Signal: ?user_id=.
@app.route("/api/profile")
@login_required
def api_profile():
    try:
        uid = int(request.args.get("user_id", current_user()["id"]))
    except ValueError:
        abort(400)
    row = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        abort(404)
    deny_if_not_owner(row["id"])
    data = dict(row)
    data.pop("password", None)
    if row["id"] != current_user()["id"]:
        data["flag"] = FLAGS["c2"]
    return jsonify(data)


# C3 - Download IDOR: fetch any invoice file.  Signal: file_id= download endpoint.
@app.route("/api/files/download")
@login_required
def api_download():
    try:
        fid = int(request.args.get("file_id", 0))
    except ValueError:
        abort(400)
    o = get_db().execute("SELECT * FROM orders WHERE id=?", (fid,)).fetchone()
    if not o:
        abort(404)
    deny_if_not_owner(o["buyer_id"])
    owner = get_db().execute("SELECT username FROM users WHERE id=?", (o["buyer_id"],)).fetchone()
    body = (
        "RABBIT MEME MARKET - INVOICE\n"
        "============================\n"
        "Invoice / file id : %d\n"
        "Customer          : %s\n"
        "Item              : %s\n"
        "Amount            : %d coins\n"
        "Ship to           : %s\n"
        "Card              : **** %s\n"
    ) % (o["id"], owner["username"], o["item"], o["amount"], o["ship_to"], o["card_last4"])
    if o["buyer_id"] != current_user()["id"]:
        body += "\n%s\n" % FLAGS["c3"]
    return Response(body, mimetype="text/plain",
                    headers={"Content-Disposition": "attachment; filename=invoice_%d.txt" % o["id"]})


# C4 - Object-level: change the price of any listing.
@app.route("/api/listings/<int:lid>/price", methods=["POST"])
@login_required
def api_set_price(lid):
    l = get_db().execute("SELECT * FROM listings WHERE id=?", (lid,)).fetchone()
    if not l:
        abort(404)
    deny_if_not_owner(l["owner_id"])
    raw = request.form.get("price")
    if raw is None and request.is_json:
        raw = request.json.get("price")
    try:
        price = int(raw)
    except (TypeError, ValueError):
        abort(400)
    db = get_db()
    db.execute("UPDATE listings SET price=? WHERE id=?", (price, lid))
    db.commit()
    stolen = l["owner_id"] != current_user()["id"]
    if request.form:
        flash(("Price set to %d. " % price) + (FLAGS["c4"] if stolen else ""))
        return redirect(url_for("listing_manage", lid=lid))
    out = {"id": lid, "price": price, "ok": True}
    if stolen:
        out["flag"] = FLAGS["c4"]
    return jsonify(out)


# Object-level bonus: delete any listing.
@app.route("/api/listings/<int:lid>/delete", methods=["POST"])
@login_required
def api_delete(lid):
    l = get_db().execute("SELECT * FROM listings WHERE id=?", (lid,)).fetchone()
    if not l:
        abort(404)
    deny_if_not_owner(l["owner_id"])
    stolen = l["owner_id"] != current_user()["id"]
    db = get_db()
    db.execute("DELETE FROM listings WHERE id=?", (lid,))
    db.commit()
    if request.form:
        flash("Listing #%d udaa diya. %s" % (lid, FLAGS["c4"] if stolen else ""))
        return redirect(url_for("account"))
    out = {"id": lid, "deleted": True}
    if stolen:
        out["flag"] = FLAGS["c4"]
    return jsonify(out)


# C5 - Vertical: admin-only dashboard, no role check.
@app.route("/api/admin/dashboard")
@login_required
def api_admin_dashboard():
    deny_if_not_admin()
    db = get_db()
    total = db.execute("SELECT COALESCE(SUM(amount),0) t FROM orders").fetchone()["t"]
    users = db.execute("SELECT id,username,role,email,card_last4 FROM users").fetchall()
    out = {"total_sales": total, "customers": [dict(u) for u in users]}
    if current_user()["role"] != "admin":
        out["flag"] = FLAGS["c5"]
    return jsonify(out)


# C6 - Function-level (BFLA): approve a listing - an admin-only action.
@app.route("/api/listings/<int:lid>/approve", methods=["POST"])
@login_required
def api_approve(lid):
    deny_if_not_admin()
    l = get_db().execute("SELECT * FROM listings WHERE id=?", (lid,)).fetchone()
    if not l:
        abort(404)
    db = get_db()
    db.execute("UPDATE listings SET status='live' WHERE id=?", (lid,))
    db.commit()
    stolen = current_user()["role"] != "admin"
    if request.form:
        flash("Listing #%d approve kar diya. %s" % (lid, FLAGS["c6"] if stolen else ""))
        return redirect(request.referrer or url_for("home"))
    out = {"id": lid, "status": "live", "approved": True}
    if stolen:
        out["flag"] = FLAGS["c6"]
    return jsonify(out)


# ----------------------------------------------------------------------------
# CTF board + flag submission
# ----------------------------------------------------------------------------
@app.route("/ctf", methods=["GET", "POST"])
def ctf():
    solved = set(session.get("solved", []))
    if request.method == "POST":
        sub = (request.form.get("flag") or "").strip()
        match = [cid for cid, fl in FLAGS.items() if fl == sub]
        if match:
            solved.add(match[0])
            session["solved"] = list(solved)
            flash("Ekdum sahi! %s ho gaya \U0001F389" % match[0])
        else:
            flash("Ye flag galat hai bhai, dobara dhoond \U0001F50D")
        return redirect(url_for("ctf"))
    inner = """
    <h1>\U0001F3F4\u200D\u2620\uFE0F Jugaad Zone</h1>
    <p class=muted>6 bug, 6 flag. Jo id apni nahi, wahi asli khazana \U0001F4B0. Bug maaro,
    <code>FLAG{...}</code> uthao, aur yaha daal do. Solved: <b>{{ solved|length }}/6</b>.</p>
    <form method=post style="display:flex;gap:10px;margin:14px 0 24px;max-width:520px">
      <input name=flag placeholder="FLAG{...}" style="flex:1">
      <button class=btn>Daal do</button></form>
    <table><tr><th>#</th><th>Challenge</th><th>Type</th><th>Kaha</th><th>Status</th></tr>
    {% for cid,title,typ,ep,hint in chals %}
    <tr><td>{{ loop.index }}</td>
      <td>{{ title }}<br><span class=muted style="font-size:12px">Hint: {{ hint }}</span></td>
      <td><span class="pill {{ 'g' if typ in ['Vertical','Function-level'] else '' }}">{{ typ }}</span></td>
      <td><code>{{ ep }}</code></td>
      <td>{% if cid in solved %}<span class="pill done">ho gaya \u2705</span>{% else %}<span class=muted>&mdash;</span>{% endif %}</td>
    </tr>{% endfor %}</table>
    <p class=muted style="margin-top:16px">Pro tip: log in as <code>alice</code> (ya khud ka account bana),
    phir <code>bob</code> aur admin ka maal utha. Burp ya seedha <code>curl</code>, dono chalega.</p>"""
    return page(inner, chals=CHALLENGES, solved=solved)


@app.route("/reset")
def reset():
    init_db()
    flash("Data reset kar diya. (CTF progress bacha hua hai \U0001F44D)")
    return redirect(url_for("ctf"))


@app.errorhandler(403)
def e403(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "oye! ye tera maal nahi hai (SECURE mode on hai)"}), 403
    return page("<h1>403 &mdash; Oye! \U0001F645</h1><p class=muted>Ye tera maal nahi hai bhai. "
                "Fix kaam kar raha hai \U0001F512 (SECURE=1).</p>"), 403


@app.errorhandler(401)
def e401(e):
    return jsonify({"error": "pehle login kar bhai"}), 401


if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        init_db()
    print("  Rabbit Meme Market |", "SECURE (fix ON)" if SECURE else "VULNERABLE (fix OFF)")
    print("  http://127.0.0.1:5000  |  alice/alice123  bob/bob123  admin/admin123  (ya /signup)")
    app.run(host=HOST, port=5000, debug=False)
