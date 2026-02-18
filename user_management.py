import sqlite3 as sql
import time
import random
import bcrypt
import html

def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    
    # ✅ SECURE: Hash password BEFORE storing
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # ✅ SAFE: Parameterized query (already present - keep it!)
    cur.execute(
        "INSERT INTO users (username, password, dateOfBirth) VALUES (?, ?, ?)",
        (username, hashed_password, DoB)  # Store HASH, not plaintext
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    
    # ✅ SECURE: SINGLE parameterized query (fixes SQLi + auth logic)
    cur.execute(
        "SELECT password FROM users WHERE username = ?",  # Only fetch password hash
        (username,)
    )
    result = cur.fetchone()
    con.close()
    
    # ✅ SECURE: Verify password hash (fixes plaintext comparison)
    if result:
        stored_hash = result[0]  # Get stored hash from DB
        # bcrypt handles salt extraction automatically
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            # ✅ SUCCESS: Username exists AND password matches SAME user
            return True
    return False  # ❌ Either user doesn't exist OR password mismatch

def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    
    # ✅ SECURE: Parameterized query (fixes SQLi)
    cur.execute(
        "INSERT INTO feedback (feedback) VALUES (?)",
        (feedback,)  # ← Comma makes it a tuple!
    )
    con.commit()
    con.close()

def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    
    f = open("templates/partials/success_feedback.html", "w")
    for row in data:
        f.write("<p>\n")
        # ✅ SECURE: Escape HTML special characters
        f.write(html.escape(row[1]) + "\n")  # ← Critical XSS fix!
        f.write("</p>\n")
    f.close()
