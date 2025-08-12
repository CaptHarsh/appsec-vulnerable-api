from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import sqlite3

app = FastAPI(title="Vulnerable FastAPI App", description="Intentionally insecure app", version="1.0.0")

# Simple DB init
def init_db():
    conn = sqlite3.connect("app.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    c.execute("INSERT OR IGNORE INTO users (id, username, password, role) VALUES (1, 'admin', 'adminpass', 'admin')")
    c.execute("INSERT OR IGNORE INTO users (id, username, password, role) VALUES (2, 'user1', 'pass1', 'user')")
    conn.commit()
    conn.close()

init_db()

@app.get("/")
def home():
    return {"message": "Welcome to the Vulnerable App"}

# Vulnerability 1: SQL Injection
@app.post("/login")
async def login(request: Request):
    data = await request.json()
    username = data.get("username")
    password = data.get("password")
    conn = sqlite3.connect("app.db")
    c = conn.cursor()
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print("Running query:", query)
    c.execute(query)
    result = c.fetchone()
    conn.close()
    if result:
        return {"status": "success", "user": result[1], "role": result[3]}
    return {"status": "fail"}

# Vulnerability 2: Stored XSS
comments = []

@app.post("/comment")
async def add_comment(request: Request):
    data = await request.json()
    comments.append(data.get("comment"))
    return {"status": "comment added"}

@app.get("/comments", response_class=HTMLResponse)
async def get_comments():
    # VULNERABLE: Rendering unsanitized HTML
    html = "<h1>Comments</h1>"
    for c in comments:
        html += f"<p>{c}</p>"
    return HTMLResponse(content=html)

# Vulnerability 3: IDOR
@app.get("/user/{user_id}")
async def get_user(user_id: int):
    # VULNERABLE: No auth check
    conn = sqlite3.connect("app.db")
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,))
    result = c.fetchone()
    conn.close()
    if result:
        return {"id": result[0], "username": result[1], "role": result[2]}
    return {"error": "User not found"}
