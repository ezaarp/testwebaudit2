"""
vuln.py
Intentionally vulnerable: TAINTED SQL STRING (SQL Injection)
Use ONLY in local / isolated lab environment.
"""

from flask import Flask, request, Response
import sqlite3
import os

APP_DB = os.path.join(os.path.dirname(__file__), "vuln_db.sqlite")

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect(APP_DB)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        email TEXT,
        secret TEXT
    );
    """)
    # insert sample data if empty
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users(username, email, secret) VALUES (?, ?, ?)",
            [
                ("alice", "alice@example.local", "alice-secret"),
                ("bob", "bob@example.local", "bob-secret"),
                ("admin", "admin@example.local", "top-secret"),
            ]
        )
    conn.commit()
    conn.close()

@app.route("/")
def index():
    return (
        "Tiny vuln lab — endpoints:\n"
        "/user?username=<value>   (SQLi vulnerable)\n"
        "Example: /user?username=alice\n"
    ), 200, {"Content-Type": "text/plain"}

# ===== VULNERABLE ENDPOINT: tainted SQL string (DO NOT DO THIS IN REAL APPS) =====
@app.route("/user")
def user_lookup():
    username = request.args.get("username", "")
    if username == "":
        return Response("provide ?username=...\n", mimetype="text/plain")

    # VULNERABLE: direct string concatenation (SQL injection)
    query = "SELECT id, username, email, secret FROM users WHERE username = '" + username + "';"
    try:
        conn = sqlite3.connect(APP_DB)
        cur = conn.cursor()
        cur.execute(query)           # <-- tainted usage
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        return Response(f"DB error: {e}\n", mimetype="text/plain", status=500)

    out_lines = [f"Executed SQL: {query}", "", "Results:"]
    if not rows:
        out_lines.append("No rows found.")
    else:
        for r in rows:
            out_lines.append(f"id={r[0]} username={r[1]} email={r[2]} secret={r[3]}")
    return Response("\n".join(out_lines) + "\n", mimetype="text/plain")

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
