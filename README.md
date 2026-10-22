<!-- Palette: #ffa31a orange · #808080 grey · #292929 surface · #1b1b1b bg · #ffffff text -->

# 🐰 Rabbit Meme Market — IDOR CTF Lab

A **deliberately vulnerable** meme-marketplace you run locally to learn and practice
**IDOR** (Insecure Direct Object Reference). Inspired by the challenge-based style of
OWASP **crAPI**, but **not API-only** and focused on **one bug class done thoroughly** —
every type of IDOR, as a self-checking CTF.

Clone → `docker compose up` → open the browser → start hacking. No database to install,
no setup to fight with.

> ⚠️ **Intentionally insecure. Localhost only.** The container is bound to `127.0.0.1`.
> Never deploy this or put it on a shared network. Only test systems you own or are
> authorized to test.

---

## Quick start (Docker)

```bash
git clone https://github.com/xr4bb1t/rabbit-meme-market.git
cd rabbit-meme-market
docker compose up --build
```

Open **http://127.0.0.1:5000** and log in. That's it.

Prefer no Docker? It's a single Flask file:

```bash
pip install -r requirements.txt
python app.py
```

### Lab accounts

| User  | Password | Role  |
|-------|----------|-------|
| alice | alice123 | user  |
| bob   | bob123   | user  |
| admin | admin123 | admin |

**The whole game:** log in as `alice`, then reach `bob`'s (or the admin's) data.

Students can also **sign up in their own name** at `/signup` — which means in class they can
hack *each other's* accounts too (any id that isn't yours drops a flag). The UI is in
Hinglish/desi meme style, and the flags are funny on purpose.

---

## How the CTF works

Every challenge hides a `FLAG{...}` inside data that **isn't yours**. If you can see the
flag, you successfully performed the IDOR. Collect it, then paste it into the
**CTF board** at **http://127.0.0.1:5000/ctf** to mark the challenge solved (0/6 → 6/6).

Your own data never shows a flag — that's the point. Authentication lets you in; the
missing piece is the server checking the object is *yours*.

## The six challenges

| # | Type | Endpoint | Signal it teaches |
|---|------|----------|-------------------|
| 1 | **Horizontal** | `GET /api/orders/<id>` | `?id=` / id enumeration |
| 2 | **Horizontal (PII)** | `GET /api/profile?user_id=<n>` | `?user_id=` |
| 3 | **Horizontal (download)** | `GET /api/files/download?file_id=<n>` | `file_id=` download IDOR |
| 4 | **Object-level** | `POST /api/listings/<id>/price` | write to an object you don't own |
| 5 | **Vertical** | `GET /api/admin/dashboard` | reaching admin-only data |
| 6 | **Function-level (BFLA)** | `POST /api/listings/<id>/approve` | performing an admin-only action |

Full briefs (with concepts and hints) are in **[CHALLENGES.md](CHALLENGES.md)**. Solutions & fixes are kept privately by the instructor.

---

## The core technique

Keep **your own** session, swap in **someone else's id**, see if the server hands it over.

```bash
# log in as alice, keep the cookie
curl -c jar.txt -d "username=alice&password=alice123" http://127.0.0.1:5000/login

# your own order — fine
curl -b jar.txt http://127.0.0.1:5000/api/orders/1001

# bob's order — if this returns data (and a flag), that's the IDOR
curl -b jar.txt http://127.0.0.1:5000/api/orders/1002
```

Everything also works from **Burp Suite** / **ZAP** (intercept, change the id, forward)
and straight from the browser's address bar for the GET challenges.

---

## See the fix work

Run the **fixed** build and every attack above starts returning `403`, while your own
data still loads:

```bash
# Docker: edit SECURE in docker-compose.yml to 1, or:
SECURE=1 docker compose up --build

# or without Docker:
SECURE=1 python app.py
```

That side-by-side — attack works, flip `SECURE=1`, attack denied — is the clearest way to
*feel* what fixing an IDOR actually does: one ownership/role check tied back to the logged-in user.

## Reset

Deleted a listing or made a mess? Visit **http://127.0.0.1:5000/reset** (CTF progress is kept).

---

## Suggested tools

- **Browser DevTools / address bar** — enough for the GET challenges
- **curl** — scripts the whole thing (examples above)
- **Burp Suite Community** + the **Autorize** extension — load alice's cookie, browse as
  bob, and it auto-flags every endpoint that forgot to check ownership
- **DB Browser for SQLite** — open `market.db` and watch prices change, listings vanish,
  and roles flip as you exploit

New to this? Start with the free **PortSwigger Web Security Academy** access-control labs,
then come back here.

---

## Repo layout

```
rabbit-meme-market/
├── app.py               # the whole lab: app, DB seed, vulnerable endpoints, SECURE fixes
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── README.md
├── CHALLENGES.md        # CTF briefs + concepts (no spoilers)
└── LICENSE
```

## For instructors

- This public repo ships without solutions; keep your SOLUTIONS.md copy for grading.
- Flags are verifiable, so grading is "did they submit all six on `/ctf`."
- Run a class comparison: everyone exploits in vulnerable mode, then you redeploy with
  `SECURE=1` and they confirm their exploits now fail.

## License

MIT — see [LICENSE](LICENSE). Intentionally vulnerable; for education and authorized testing only.
