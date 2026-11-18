import base64, hashlib, hmac, os, secrets, sqlite3, time
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

DB_PATH = os.getenv("DB_PATH", "campus.db")
SECRET = os.getenv("SECRET_KEY", "dev-secret-change-me")
ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

app = FastAPI(title="CampusLaunch API")
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=["*"], allow_headers=["*"])
bearer = HTTPBearer(auto_error=False)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, usn TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  college TEXT NOT NULL, department TEXT DEFAULT '', year INTEGER DEFAULT 1,
  skills TEXT DEFAULT '', interests TEXT DEFAULT '', role TEXT DEFAULT 'student',
  salt TEXT NOT NULL, pw TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS projects(
  id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL, description TEXT NOT NULL, category TEXT DEFAULT 'Other',
  technologies TEXT DEFAULT '', required_skills TEXT DEFAULT '', goals TEXT DEFAULT '',
  status TEXT DEFAULT 'Planning', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS members(
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT DEFAULT 'Member', joined_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(project_id,user_id));
CREATE TABLE IF NOT EXISTS requests(
  id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, status TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(project_id,user_id));
CREATE TABLE IF NOT EXISTS notifications(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL, is_read INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS activity(
  id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
"""


def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()


def make_token(uid, days):
    p = f"{uid}:{int(time.time() + days * 86400)}"
    sig = hmac.new(SECRET.encode(), p.encode(), "sha256").hexdigest()
    return base64.urlsafe_b64encode(f"{p}:{sig}".encode()).decode()


def read_token(t):
    try:
        uid, exp, sig = base64.urlsafe_b64decode(t.encode()).decode().split(":")
        good = hmac.new(SECRET.encode(), f"{uid}:{exp}".encode(), "sha256").hexdigest()
        if hmac.compare_digest(sig, good) and int(exp) > time.time():
            return int(uid)
    except Exception:
        pass
    return None


def connect():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    return c


def get_db():
    c = connect()
    try:
        yield c
        c.commit()
    finally:
        c.close()


def q(db, sql, p=()):
    return [dict(r) for r in db.execute(sql, p).fetchall()]


def notify(db, uid, text):
    db.execute("INSERT INTO notifications(user_id,text) VALUES(?,?)", (uid, text))


def log(db, text):
    db.execute("INSERT INTO activity(text) VALUES(?)", (text,))


def tokens(s):
    return {x.strip().lower() for x in (s or "").split(",") if x.strip()}


def optional_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer), db=Depends(get_db)):
    uid = read_token(creds.credentials) if creds else None
    if not uid:
        return None
    r = db.execute("SELECT id,usn,name,college,department,year,skills,interests,role FROM users WHERE id=?", (uid,)).fetchone()
    return dict(r) if r else None


def current_user(u=Depends(optional_user)):
    if not u:
        raise HTTPException(401, "Please sign in")
    return u


def admin_user(u=Depends(current_user)):
    if u["role"] != "admin":
        raise HTTPException(403, "Admins only")
    return u


# ---------- Seed data (admin, demo student, sample projects) ----------
def seed():
    c = connect()
    c.executescript(SCHEMA)
    if not c.execute("SELECT 1 FROM users").fetchone():
        coll = "Demo Institute of Technology"
        people = [
            ("ADMIN001", "Platform Admin", "admin123", "admin", "Administration", 4, "", ""),
            ("DEMO001", "Demo Student", "demo1234", "student", "Computer Science", 3, "Flutter, UI Design, Python", "Mobile, Web"),
            ("1XX21CS002", "Aarav Rao", "student123", "student", "Computer Science", 3, "Machine Learning, Python", "AI/ML"),
            ("1XX21EC010", "Meera Nair", "student123", "student", "Electronics", 3, "Arduino, Electronics", "IoT, Hardware"),
            ("1XX22IS005", "Kiran Shah", "student123", "student", "Information Science", 2, "React, UI Design", "Web"),
        ]
        ids = {}
        for usn, name, pw, role, dep, yr, sk, it in people:
            salt = secrets.token_hex(16)
            cur = c.execute("INSERT INTO users(usn,name,college,department,year,skills,interests,role,salt,pw) VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (usn, name, coll, dep, yr, sk, it, role, salt, hash_pw(pw, salt)))
            ids[usn] = cur.lastrowid
        projs = [
            ("DEMO001", "Campus Carpool", "Match students travelling the same route to save fuel and money.", "Mobile", "Flutter, Firebase", "Flutter, UI Design", "Launch beta to 100 students", "In Progress"),
            ("1XX21CS002", "Study Buddy Matcher", "Recommend study partners using course and skill similarity.", "AI/ML", "Python, scikit-learn", "Machine Learning, Python", "Working prototype in 6 weeks", "Planning"),
            ("1XX21EC010", "Smart Hostel Energy Monitor", "Sensors that track room power use and show live usage.", "IoT", "Arduino, MQTT", "Arduino, Electronics", "Deploy in one hostel block", "In Progress"),
            ("1XX22IS005", "Lost & Found Portal", "One place for students to report and recover lost items.", "Web", "React, Node", "React, UI Design", "Go live before the next semester", "Planning"),
        ]
        pid = []
        for owner, t, d, cat, tech, req, goals, st in projs:
            cur = c.execute("INSERT INTO projects(owner_id,title,description,category,technologies,required_skills,goals,status) VALUES(?,?,?,?,?,?,?,?)",
                            (ids[owner], t, d, cat, tech, req, goals, st))
            pid.append(cur.lastrowid)
            c.execute("INSERT INTO members(project_id,user_id,role) VALUES(?,?,'Lead')", (cur.lastrowid, ids[owner]))
            c.execute("INSERT INTO activity(text) VALUES(?)", (f"{dict((p[0], p[1]) for p in people)[owner]} created “{t}”",))
        c.execute("INSERT INTO members(project_id,user_id,role) VALUES(?,?,'Developer')", (pid[1], ids["DEMO001"]))
        c.execute("INSERT INTO members(project_id,user_id,role) VALUES(?,?,'Hardware')", (pid[0], ids["1XX21EC010"]))
        c.execute("INSERT INTO requests(project_id,user_id) VALUES(?,?)", (pid[0], ids["1XX22IS005"]))
        c.execute("INSERT INTO notifications(user_id,text) VALUES(?,?)", (ids["DEMO001"], "Kiran Shah requested to join “Campus Carpool”"))
        c.execute("INSERT INTO notifications(user_id,text) VALUES(?,?)", (ids["DEMO001"], "Welcome to CampusLaunch!"))
        c.execute("INSERT INTO activity(text) VALUES(?)", ("Demo Student joined “Study Buddy Matcher”",))
    c.commit()
    c.close()


seed()


# ---------- Schemas ----------
class Reg(BaseModel):
    usn: str = Field(min_length=3, max_length=30)
    name: str = Field(min_length=1, max_length=100)
    college: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=6, max_length=100)
    department: str = Field("", max_length=100)
    year: int = Field(1, ge=1, le=6)


class Login(BaseModel):
    usn: str
    password: str
    remember: bool = False


class Profile(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    college: Optional[str] = Field(None, min_length=1, max_length=200)
    department: Optional[str] = Field(None, max_length=100)
    year: Optional[int] = Field(None, ge=1, le=6)
    skills: Optional[str] = Field(None, max_length=300)
    interests: Optional[str] = Field(None, max_length=300)


class ProjectIn(BaseModel):
    title: str = Field(min_length=3, max_length=150)
    description: str = Field(min_length=10, max_length=5000)
    category: str = Field("Other", max_length=50)
    technologies: str = Field("", max_length=300)
    required_skills: str = Field("", max_length=300)
    goals: str = Field("", max_length=1000)
    status: str = Field("Planning", pattern="^(Planning|In Progress|Completed)$")


class RoleIn(BaseModel):
    role: str = Field(min_length=1, max_length=50)


# ---------- Auth & profile ----------
@app.post("/register", status_code=201)
def register(d: Reg, db=Depends(get_db)):
    usn = d.usn.strip().upper()
    if db.execute("SELECT 1 FROM users WHERE usn=?", (usn,)).fetchone():
        raise HTTPException(409, "USN already registered")
    salt = secrets.token_hex(16)
    cur = db.execute("INSERT INTO users(usn,name,college,department,year,salt,pw) VALUES(?,?,?,?,?,?,?)",
                     (usn, d.name, d.college, d.department, d.year, salt, hash_pw(d.password, salt)))
    notify(db, cur.lastrowid, "Welcome to CampusLaunch! Complete your profile to get project recommendations.")
    log(db, f"{d.name} joined CampusLaunch")
    return {"token": make_token(cur.lastrowid, 1)}


@app.post("/login")
def login(d: Login, db=Depends(get_db)):
    u = db.execute("SELECT id,salt,pw FROM users WHERE usn=?", (d.usn.strip().upper(),)).fetchone()
    if not u or not hmac.compare_digest(u["pw"], hash_pw(d.password, u["salt"])):
        raise HTTPException(401, "Wrong USN or password")
    return {"token": make_token(u["id"], 30 if d.remember else 1)}


@app.post("/demo")
def demo(db=Depends(get_db)):
    u = db.execute("SELECT id FROM users WHERE usn='DEMO001'").fetchone()
    if not u:
        raise HTTPException(404, "Demo account not found")
    return {"token": make_token(u["id"], 1)}


@app.get("/me")
def me(u=Depends(current_user), db=Depends(get_db)):
    u["unread"] = db.execute("SELECT COUNT(*) c FROM notifications WHERE user_id=? AND is_read=0", (u["id"],)).fetchone()["c"]
    return u


@app.put("/me")
def update_me(d: Profile, u=Depends(current_user), db=Depends(get_db)):
    data = d.model_dump(exclude_none=True)
    if data:
        db.execute(f"UPDATE users SET {','.join(k + '=?' for k in data)} WHERE id=?", (*data.values(), u["id"]))
    return {"ok": True}


# ---------- Projects ----------
@app.get("/projects")
def list_projects(q_: Optional[str] = Query(None, alias="q"), category: str = "", status: str = "", db=Depends(get_db)):
    sql = ("SELECT p.*, u.name owner_name, (SELECT COUNT(*) FROM members m WHERE m.project_id=p.id) member_count "
           "FROM projects p JOIN users u ON u.id=p.owner_id WHERE 1=1")
    p = []
    if q_:
        sql += " AND (p.title LIKE ? OR p.description LIKE ? OR p.technologies LIKE ? OR p.required_skills LIKE ?)"
        p += [f"%{q_}%"] * 4
    if category:
        sql += " AND p.category=?"; p.append(category)
    if status:
        sql += " AND p.status=?"; p.append(status)
    return q(db, sql + " ORDER BY p.id DESC", p)


@app.post("/projects", status_code=201)
def create_project(d: ProjectIn, u=Depends(current_user), db=Depends(get_db)):
    cur = db.execute("INSERT INTO projects(owner_id,title,description,category,technologies,required_skills,goals,status) VALUES(?,?,?,?,?,?,?,?)",
                     (u["id"], d.title, d.description, d.category, d.technologies, d.required_skills, d.goals, d.status))
    db.execute("INSERT INTO members(project_id,user_id,role) VALUES(?,?,'Lead')", (cur.lastrowid, u["id"]))
    log(db, f"{u['name']} created “{d.title}”")
    return {"id": cur.lastrowid}


def get_project(db, pid):
    p = db.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
    if not p:
        raise HTTPException(404, "Project not found")
    return dict(p)


@app.get("/projects/{pid}")
def project_detail(pid: int, u=Depends(optional_user), db=Depends(get_db)):
    p = get_project(db, pid)
    p["members"] = q(db, "SELECT u.id,u.name,u.department,u.skills,m.role FROM members m JOIN users u ON u.id=m.user_id WHERE m.project_id=? ORDER BY m.joined_at", (pid,))
    p["owner_name"] = next((m["name"] for m in p["members"] if m["id"] == p["owner_id"]), "")
    p["is_member"] = bool(u) and any(m["id"] == u["id"] for m in p["members"])
    r = db.execute("SELECT status FROM requests WHERE project_id=? AND user_id=?", (pid, u["id"])).fetchone() if u else None
    p["my_request"] = r["status"] if r else None
    return p


@app.put("/projects/{pid}")
def edit_project(pid: int, d: ProjectIn, u=Depends(current_user), db=Depends(get_db)):
    p = get_project(db, pid)
    if p["owner_id"] != u["id"] and u["role"] != "admin":
        raise HTTPException(403, "Only the owner can edit this project")
    db.execute("UPDATE projects SET title=?,description=?,category=?,technologies=?,required_skills=?,goals=?,status=? WHERE id=?",
               (d.title, d.description, d.category, d.technologies, d.required_skills, d.goals, d.status, pid))
    if d.status != p["status"]:
        for m in q(db, "SELECT user_id FROM members WHERE project_id=? AND user_id!=?", (pid, u["id"])):
            notify(db, m["user_id"], f"“{d.title}” is now {d.status}")
        log(db, f"“{d.title}” moved to {d.status}")
    return {"ok": True}


@app.delete("/projects/{pid}")
def delete_project(pid: int, u=Depends(current_user), db=Depends(get_db)):
    p = get_project(db, pid)
    if p["owner_id"] != u["id"] and u["role"] != "admin":
        raise HTTPException(403, "Only the owner or an admin can delete this project")
    for m in q(db, "SELECT user_id FROM members WHERE project_id=? AND user_id!=?", (pid, u["id"])):
        notify(db, m["user_id"], f"“{p['title']}” was removed")
    db.execute("DELETE FROM projects WHERE id=?", (pid,))
    return {"ok": True}


# ---------- Collaboration ----------
@app.post("/projects/{pid}/request", status_code=201)
def request_join(pid: int, u=Depends(current_user), db=Depends(get_db)):
    p = get_project(db, pid)
    if db.execute("SELECT 1 FROM members WHERE project_id=? AND user_id=?", (pid, u["id"])).fetchone():
        raise HTTPException(409, "You are already on this team")
    r = db.execute("SELECT status FROM requests WHERE project_id=? AND user_id=?", (pid, u["id"])).fetchone()
    if r and r["status"] == "pending":
        raise HTTPException(409, "Request already pending")
    if r:
        db.execute("UPDATE requests SET status='pending' WHERE project_id=? AND user_id=?", (pid, u["id"]))
    else:
        db.execute("INSERT INTO requests(project_id,user_id) VALUES(?,?)", (pid, u["id"]))
    notify(db, p["owner_id"], f"{u['name']} requested to join “{p['title']}”")
    return {"ok": True}


def decide(rid, accept, u, db):
    r = db.execute("SELECT r.*, p.owner_id, p.title FROM requests r JOIN projects p ON p.id=r.project_id WHERE r.id=?", (rid,)).fetchone()
    if not r:
        raise HTTPException(404, "Request not found")
    if r["owner_id"] != u["id"]:
        raise HTTPException(403, "Only the project owner can decide")
    if r["status"] != "pending":
        raise HTTPException(409, "Already decided")
    db.execute("UPDATE requests SET status=? WHERE id=?", ("accepted" if accept else "rejected", rid))
    if accept:
        db.execute("INSERT OR IGNORE INTO members(project_id,user_id) VALUES(?,?)", (r["project_id"], r["user_id"]))
        log(db, f"A new member joined “{r['title']}”")
    notify(db, r["user_id"], f"Your request to join “{r['title']}” was {'accepted' if accept else 'rejected'}")
    return {"ok": True}


@app.post("/requests/{rid}/accept")
def accept(rid: int, u=Depends(current_user), db=Depends(get_db)):
    return decide(rid, True, u, db)


@app.post("/requests/{rid}/reject")
def reject(rid: int, u=Depends(current_user), db=Depends(get_db)):
    return decide(rid, False, u, db)


@app.delete("/projects/{pid}/leave")
def leave(pid: int, u=Depends(current_user), db=Depends(get_db)):
    p = get_project(db, pid)
    if p["owner_id"] == u["id"]:
        raise HTTPException(400, "Owners can't leave; delete the project instead")
    db.execute("DELETE FROM members WHERE project_id=? AND user_id=?", (pid, u["id"]))
    db.execute("DELETE FROM requests WHERE project_id=? AND user_id=?", (pid, u["id"]))
    notify(db, p["owner_id"], f"{u['name']} left “{p['title']}”")
    return {"ok": True}


@app.put("/projects/{pid}/members/{uid}/role")
def set_role(pid: int, uid: int, d: RoleIn, u=Depends(current_user), db=Depends(get_db)):
    p = get_project(db, pid)
    if p["owner_id"] != u["id"]:
        raise HTTPException(403, "Only the owner can assign roles")
    if not db.execute("SELECT 1 FROM members WHERE project_id=? AND user_id=?", (pid, uid)).fetchone():
        raise HTTPException(404, "Not a team member")
    db.execute("UPDATE members SET role=? WHERE project_id=? AND user_id=?", (d.role, pid, uid))
    if uid != u["id"]:
        notify(db, uid, f"Your role in “{p['title']}” is now {d.role}")
    return {"ok": True}


# ---------- Dashboard & notifications ----------
@app.get("/dashboard")
def dashboard(u=Depends(current_user), db=Depends(get_db)):
    uid = u["id"]
    wanted = tokens(u["skills"]) | tokens(u["interests"])
    cand = q(db, "SELECT id,title,category,technologies,required_skills,status FROM projects "
                 "WHERE owner_id!=? AND id NOT IN (SELECT project_id FROM members WHERE user_id=?) ORDER BY id DESC", (uid, uid))
    for c in cand:
        c["score"] = len(wanted & (tokens(c["required_skills"]) | tokens(c["technologies"]) | tokens(c["category"])))
    return {
        "mine": q(db, "SELECT id,title,status,category FROM projects WHERE owner_id=? ORDER BY id DESC", (uid,)),
        "joined": q(db, "SELECT p.id,p.title,p.status,p.category,m.role FROM members m JOIN projects p ON p.id=m.project_id WHERE m.user_id=? AND p.owner_id!=? ORDER BY p.id DESC", (uid, uid)),
        "incoming": q(db, "SELECT r.id,p.id project_id,p.title,us.name,us.skills FROM requests r JOIN projects p ON p.id=r.project_id JOIN users us ON us.id=r.user_id WHERE p.owner_id=? AND r.status='pending' ORDER BY r.id DESC", (uid,)),
        "sent": q(db, "SELECT r.status,p.id project_id,p.title FROM requests r JOIN projects p ON p.id=r.project_id WHERE r.user_id=? AND r.status!='accepted' ORDER BY r.id DESC", (uid,)),
        "notifications": q(db, "SELECT id,text,is_read,created_at FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 10", (uid,)),
        "recommended": sorted(cand, key=lambda c: -c["score"])[:5],
        "activity": q(db, "SELECT text,created_at FROM activity ORDER BY id DESC LIMIT 8"),
    }


@app.post("/notifications/read")
def mark_read(u=Depends(current_user), db=Depends(get_db)):
    db.execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (u["id"],))
    return {"ok": True}


# ---------- Admin ----------
@app.get("/admin/stats")
def stats(a=Depends(admin_user), db=Depends(get_db)):
    n = lambda t, w="1=1": db.execute(f"SELECT COUNT(*) c FROM {t} WHERE {w}").fetchone()["c"]
    return {"students": n("users", "role='student'"), "projects": n("projects"), "pending_requests": n("requests", "status='pending'"),
            "memberships": n("members"), "by_status": q(db, "SELECT status, COUNT(*) count FROM projects GROUP BY status"),
            "activity": q(db, "SELECT text,created_at FROM activity ORDER BY id DESC LIMIT 10")}


@app.get("/admin/users")
def admin_users(a=Depends(admin_user), db=Depends(get_db)):
    return q(db, "SELECT id,usn,name,college,department,year,role,created_at, (SELECT COUNT(*) FROM projects p WHERE p.owner_id=users.id) projects FROM users ORDER BY id")


@app.delete("/admin/users/{uid}")
def admin_delete_user(uid: int, a=Depends(admin_user), db=Depends(get_db)):
    if uid == a["id"]:
        raise HTTPException(400, "You can't delete your own account")
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    return {"ok": True}
