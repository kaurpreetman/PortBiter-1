from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse, PlainTextResponse
import sqlite3

app = FastAPI()


conn = sqlite3.connect(":memory:", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)")
cursor.execute("INSERT INTO users VALUES (1, 'admin', 'password')")
conn.commit()


@app.get("/")
def home():
    return {"message": "Vulnerable test server running"}


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    return f"<h1>Results for: {q}</h1>"  # No sanitization



@app.get("/login")
def login(username: str, password: str):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        result = cursor.execute(query).fetchone()
        if result:
            return {"status": "success", "user": username}
        return {"status": "failed"}
    except Exception as e:
        return {"error": str(e)}



@app.get("/.env", response_class=PlainTextResponse)
def env():
    return "SECRET_KEY=supersecret\nDB_PASSWORD=123456"


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    content = await file.read()
    return {
        "filename": file.filename,
        "size": len(content),
        "warning": "No validation performed!"
    }



@app.get("/headers")
def headers(request: Request):
    return dict(request.headers)



@app.get("/page1")
def page1():
    return {"next": "/page2"}

@app.get("/page2")
def page2():
    return {"next": "/search?q=test"}