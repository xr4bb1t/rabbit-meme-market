# 🐰 CTF Challenges

Six challenges, every type of IDOR. Each hides a `FLAG{...}` inside data that isn't
yours — find it, then submit it on the **CTF board** (`/ctf`) to mark it solved.

**Before you start:** log in as `alice` / `alice123` — or **sign up in your own name** at
`/signup` (then you can also hack your classmates' accounts for extra fun). Visit **My
account** and note *your own* ids (your order numbers, your user id, your listing ids).
Those are your baseline — now go reach for `bob`'s, the admin's, or your neighbour's.

---

## What IDOR actually is (read this first)

Logging in answers *"who are you?"* — that's **authentication**. IDOR happens when the app
forgets the second question: *"are you allowed to touch **this specific object**?"* — that's
**authorization**. You're a normal, logged-in user asking for an object that belongs to
someone else, and nobody checks. One missing line:

```sql
-- vulnerable: hands the object to anyone who asks
SELECT * FROM orders WHERE id = :id
-- fixed: the object must also belong to the caller
SELECT * FROM orders WHERE id = :id AND owner_id = :current_user
```

The four shapes you'll meet here:

- **Horizontal** — reach another *normal user's* data (same power level as you).
- **Object-level** — not just read, but *edit or delete* something you don't own.
- **Vertical** — reach data or pages *above* your level (admin-only).
- **Function-level (BFLA)** — *perform an action* you shouldn't (approve, refund, promote).

---

## Challenge 1 — Horizontal IDOR: order enumeration
**Type:** Horizontal · **Where:** `GET /api/orders/<id>`

**Concept.** Order ids are sequential and shown right in the URL. If the server returns any
order by number without checking who owns it, you can walk the ids and read other people's
orders — names, addresses, card digits.

**Objective.** Read an order that isn't yours and grab the flag.
**Hint.** Your order id is small. What about the one next to it?

---

## Challenge 2 — Horizontal IDOR: profile via `?user_id=`
**Type:** Horizontal (PII) · **Where:** `GET /api/profile?user_id=<n>`

**Concept.** A classic signal: the object id sits in a query-string parameter like
`?user_id=`. The endpoint trusts whatever number you put there and returns that user's
profile. This is how account-wide PII leaks happen.

**Objective.** Pull another user's full profile.
**Hint.** The id of the user you get back is sitting in the query string. Change it.

---

## Challenge 3 — Download IDOR: invoice files
**Type:** Horizontal (file access) · **Where:** `GET /api/files/download?file_id=<n>`

**Concept.** Download endpoints are a favorite IDOR spot — `?file_id=`, `?doc=`,
`?attachment=`. The file is addressed by a number and the server streams it without
checking ownership, so changing the number downloads someone else's document.

**Objective.** Download an invoice that belongs to another user.
**Hint.** Files are numbered just like orders. Ask for one that isn't yours.

---

## Challenge 4 — Object-level IDOR: edit a listing you don't own
**Type:** Object-level (write) · **Where:** `POST /api/listings/<id>/price`

**Concept.** Reading isn't the only risk. Write actions (edit, delete) are often protected
on the *view* but not on the *action*. Here you can set the price of **any** listing — the
textbook "change one number, change someone else's data." Watch the method: a protected
`GET` often hides an unprotected `POST`/`PUT`/`DELETE`.

**Objective.** Change the price of a listing you don't own (try setting it to `1`). A delete
variant exists too: `POST /api/listings/<id>/delete`.
**Hint.** You can read your own listing page. Can you write to someone else's listing id?

---

## Challenge 5 — Vertical IDOR: the admin dashboard
**Type:** Vertical · **Where:** `GET /api/admin/dashboard`

**Concept.** Vertical means crossing a *privilege* boundary, not just reaching a peer. The
admin dashboard (total sales, every customer's PII) should require an admin role — but the
check is missing, so a normal user can just request it.

**Objective.** As `alice` (a normal user), read the admin dashboard.
**Hint.** It's an admin-only page that forgot to check your role. Just ask for it.

---

## Challenge 6 — Function-level IDOR / BFLA: approve a listing
**Type:** Function-level · **Where:** `POST /api/listings/<id>/approve`

**Concept.** Some endpoints aren't about *data* but about *actions* — approve, refund,
promote, disable. Approving a pending listing is an **admin** power. If the action doesn't
check your role, any user can perform it. In API terms this is **Broken Function Level
Authorization (BFLA)**.

**Objective.** As a normal user, approve the pending listing (id `6`) and take the flag.
**Hint.** Approving is an admin action. Is it actually checked, or just hidden behind a button?

---

## When you've got all six

Submit each flag on **`/ctf`**. At 6/6, redeploy the fixed build (`SECURE=1`) and try every
exploit again — they should all now return **403**. That's the lesson: the fix is one
ownership/role check per object, enforced on the server. See **SOLUTIONS.md** for the
walkthroughs and the exact fixes.
