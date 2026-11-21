import base64, hashlib, hmac, os, secrets, time
from contextlib import asynccontextmanager
from typing import Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field

load_dotenv()  # reads the .env file when running on your own computer
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set. Add your Neon connection string (see .env.example).")
SECRET = os.getenv("SECRET_KEY", "dev-secret-change-me")
ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

# A small pool of reusable database connections (faster than reconnecting every request)
pool = ConnectionPool(
    DATABASE_URL, min_size=1, max_size=5, open=False,
    check=ConnectionPool.check_connection,  # drops connections Neon closed while idle
    kwargs={"row_factory": dict_row, "prepare_threshold": None, "connect_timeout": 15},
)

TS = "TEXT DEFAULT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI')"
SCHEMA = f"""
CREATE TABLE IF NOT EXISTS users(
  id SERIAL PRIMARY KEY, usn TEXT UNIQUE NOT NULL, name TEXT NOT NULL, college TEXT NOT NULL,
  department TEXT DEFAULT '', year INTEGER DEFAULT 1, skills TEXT DEFAULT '', interests TEXT DEFAULT '',
  role TEXT DEFAULT 'student', salt TEXT NOT NULL, pw TEXT NOT NULL, created_at {TS});
CREATE TABLE IF NOT EXISTS projects(
  id SERIAL PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL, description TEXT NOT NULL, category TEXT DEFAULT 'Other',
  technologies TEXT DEFAULT '', required_skills TEXT DEFAULT '', goals TEXT DEFAULT '',
  status TEXT DEFAULT 'Planning', team_size INTEGER DEFAULT 5, location TEXT DEFAULT '',
  meeting_time TEXT DEFAULT '', roles_needed TEXT DEFAULT '', branch_restrictions TEXT DEFAULT '', created_at {TS});
CREATE TABLE IF NOT EXISTS members(
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT DEFAULT 'Member', joined_at {TS}, PRIMARY KEY(project_id, user_id));
CREATE TABLE IF NOT EXISTS requests(
  id SERIAL PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, status TEXT DEFAULT 'pending',
  created_at {TS}, UNIQUE(project_id, user_id));
CREATE TABLE IF NOT EXISTS notifications(
  id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL, is_read INTEGER DEFAULT 0, created_at {TS});
CREATE TABLE IF NOT EXISTS activity(
  id SERIAL PRIMARY KEY, text TEXT NOT NULL, created_at {TS});
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


# ---------- Database helpers ----------
def get_db():
    with pool.connection() as conn:  # commits on success, rolls back on error
        yield conn


def q(db, sql, p=()):
    return db.execute(sql, p).fetchall()


def insert(db, sql, p=()):
    return db.execute(sql + " RETURNING id", p).fetchone()["id"]


def notify(db, uid, text):
    db.execute("INSERT INTO notifications(user_id,text) VALUES(%s,%s)", (uid, text))


def log(db, text):
    db.execute("INSERT INTO activity(text) VALUES(%s)", (text,))


def tokens(s):
    return {x.strip().lower() for x in (s or "").split(",") if x.strip()}


bearer = HTTPBearer(auto_error=False)


def optional_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer), db=Depends(get_db)):
    uid = read_token(creds.credentials) if creds else None
    if not uid:
        return None
    return db.execute("SELECT id,usn,name,college,department,year,skills,interests,role FROM users WHERE id=%s", (uid,)).fetchone()


def current_user(u=Depends(optional_user)):
    if not u:
        raise HTTPException(401, "Please sign in")
    return u


def admin_user(u=Depends(current_user)):
    if u["role"] != "admin":
        raise HTTPException(403, "Admins only")
    return u


# ---------- Setup + sample data ----------
def seed(db):
    coll = "Demo Institute of Technology"
    admin_pw = os.getenv("ADMIN_PASSWORD", "admin123")
    people = [
        ("ADMIN001", "Platform Admin", admin_pw, "admin", "Administration", 4, "", ""),
        ("DEMO001", "Demo Student", "demo1234", "student", "Computer Science", 3, "Flutter, UI Design, Python", "Mobile, Web"),
        ("1XX21CS002", "Aarav Rao", "student123", "student", "Computer Science", 3, "Machine Learning, Python", "AI/ML"),
        ("1XX21EC010", "Meera Nair", "student123", "student", "Electronics", 3, "Arduino, Electronics", "IoT, Hardware"),
        ("1XX22IS005", "Kiran Shah", "student123", "student", "Information Science", 2, "React, UI Design", "Web"),
    ]
    ids, names = {}, {}
    for usn, name, pw, role, dep, yr, sk, it in people:
        salt = secrets.token_hex(16)
        ids[usn] = insert(db, "INSERT INTO users(usn,name,college,department,year,skills,interests,role,salt,pw) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                          (usn, name, coll, dep, yr, sk, it, role, salt, hash_pw(pw, salt)))
        names[usn] = name
    projs = [
        ("DEMO001", "Campus Carpool", "Match students travelling the same route to save fuel and money.", "Mobile", "Flutter, Firebase", "Flutter, UI Design", "Launch beta to 100 students", "In Progress",
         5, "Innovation Hub 204", "Tuesdays at 5 PM", "Frontend Dev (Flutter), UI/UX Designer (Figma)"),
        ("1XX21CS002", "Study Buddy Matcher", "Recommend study partners using course and skill similarity.", "AI/ML", "Python, scikit-learn", "Machine Learning, Python", "Working prototype in 6 weeks", "Planning",
         4, "Library West Wing", "Wednesdays at 4 PM", "ML Engineer, Backend Dev"),
        ("1XX21EC010", "Smart Hostel Energy Monitor", "Sensors that track room power use and show live usage.", "IoT", "Arduino, MQTT", "Arduino, Electronics", "Deploy in one hostel block", "In Progress",
         6, "Mech Lab 202", "Thursdays at 6 PM", "Hardware Designer (Arduino/IoT), Data Analyst"),
        ("1XX22IS005", "Lost & Found Portal", "One place for students to report and recover lost items.", "Web", "React, Node", "React, UI Design", "Go live before the next semester", "Planning",
         4, "Design Studio", "Fridays at 3 PM", "Frontend Dev (React), QA Tester"),
    ]
    pid = []
    for owner, t, d, cat, tech, req, goals, st, size, loc, when, roles in projs:
        p = insert(db, "INSERT INTO projects(owner_id,title,description,category,technologies,required_skills,goals,status,team_size,location,meeting_time,roles_needed) "
                       "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (ids[owner], t, d, cat, tech, req, goals, st, size, loc, when, roles))
        pid.append(p)
        db.execute("INSERT INTO members(project_id,user_id,role) VALUES(%s,%s,'Lead')", (p, ids[owner]))
        log(db, f"{names[owner]} created “{t}”")
    db.execute("INSERT INTO members(project_id,user_id,role) VALUES(%s,%s,'Developer')", (pid[1], ids["DEMO001"]))
    db.execute("INSERT INTO members(project_id,user_id,role) VALUES(%s,%s,'Hardware')", (pid[0], ids["1XX21EC010"]))
    db.execute("INSERT INTO requests(project_id,user_id) VALUES(%s,%s)", (pid[0], ids["1XX22IS005"]))
    notify(db, ids["DEMO001"], "Kiran Shah requested to join “Campus Carpool”")
    notify(db, ids["DEMO001"], "Welcome to CampusLaunch!")
    log(db, "Demo Student joined “Study Buddy Matcher”")


def init_db():
    with pool.connection() as db:
        db.execute(SCHEMA)
        if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            seed(db)  # sample data is only added to an empty database
        pw = os.getenv("ADMIN_PASSWORD")
        if pw:  # keeps the admin password in sync with the environment setting
            salt = secrets.token_hex(16)
            db.execute("UPDATE users SET salt=%s, pw=%s WHERE usn='ADMIN001'", (salt, hash_pw(pw, salt)))


@asynccontextmanager
async def lifespan(app):
    pool.open()
    init_db()
    yield
    pool.close()


app = FastAPI(title="CampusLaunch API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=["*"], allow_headers=["*"])


@app.get("/")
def health():
    return {"status": "ok"}


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
    team_size: int = Field(5, ge=2, le=50)
    location: str = Field("", max_length=150)
    meeting_time: str = Field("", max_length=100)
    roles_needed: str = Field("", max_length=300)
    branch_restrictions: str = Field("", max_length=200)


class RoleIn(BaseModel):
    role: str = Field(min_length=1, max_length=50)


# ---------- Auth & profile ----------
@app.post("/register", status_code=201)
def register(d: Reg, db=Depends(get_db)):
    usn = d.usn.strip().upper()
    if db.execute("SELECT 1 FROM users WHERE usn=%s", (usn,)).fetchone():
        raise HTTPException(409, "USN already registered")
    salt = secrets.token_hex(16)
    uid = insert(db, "INSERT INTO users(usn,name,college,department,year,salt,pw) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                 (usn, d.name, d.college, d.department, d.year, salt, hash_pw(d.password, salt)))
    notify(db, uid, "Welcome to CampusLaunch! Complete your profile to get project recommendations.")
    log(db, f"{d.name} joined CampusLaunch")
    return {"token": make_token(uid, 1)}


@app.post("/login")
def login(d: Login, db=Depends(get_db)):
    u = db.execute("SELECT id,salt,pw FROM users WHERE usn=%s", (d.usn.strip().upper(),)).fetchone()
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
    u["unread"] = db.execute("SELECT COUNT(*) AS c FROM notifications WHERE user_id=%s AND is_read=0", (u["id"],)).fetchone()["c"]
    return u


@app.put("/me")
def update_me(d: Profile, u=Depends(current_user), db=Depends(get_db)):
    data = d.model_dump(exclude_none=True)
    if data:
        db.execute(f"UPDATE users SET {','.join(k + '=%s' for k in data)} WHERE id=%s", (*data.values(), u["id"]))
    return {"ok": True}


# ---------- Projects ----------
@app.get("/projects")
def list_projects(q_: Optional[str] = Query(None, alias="q"), category: str = "", status: str = "", db=Depends(get_db)):
    sql = ("SELECT p.*, u.name AS owner_name, u.department AS owner_department, u.year AS owner_year, "
           "(SELECT COUNT(*) FROM members m WHERE m.project_id=p.id) AS member_count "
           "FROM projects p JOIN users u ON u.id=p.owner_id WHERE 1=1")
    p = []
    if q_:
        sql += " AND (p.title ILIKE %s OR p.description ILIKE %s OR p.technologies ILIKE %s OR p.required_skills ILIKE %s)"
        p += [f"%{q_}%"] * 4
    if category:
        sql += " AND p.category=%s"; p.append(category)
    if status:
        sql += " AND p.status=%s"; p.append(status)
    return q(db, sql + " ORDER BY p.id DESC", p)


@app.post("/projects", status_code=201)
def create_project(d: ProjectIn, u=Depends(current_user), db=Depends(get_db)):
    pid = insert(db, "INSERT INTO projects(owner_id,title,description,category,technologies,required_skills,goals,status,team_size,location,meeting_time,roles_needed,branch_restrictions) "
                     "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                 (u["id"], d.title, d.description, d.category, d.technologies, d.required_skills, d.goals, d.status,
                  d.team_size, d.location, d.meeting_time, d.roles_needed, d.branch_restrictions))
    db.execute("INSERT INTO members(project_id,user_id,role) VALUES(%s,%s,'Lead')", (pid, u["id"]))
    log(db, f"{u['name']} created “{d.title}”")
    return {"id": pid}


def get_project(db, pid):
    p = db.execute("SELECT * FROM projects WHERE id=%s", (pid,)).fetchone()
    if not p:
        raise HTTPException(404, "Project not found")
    return p


@app.get("/projects/{pid}")
def project_detail(pid: int, u=Depends(optional_user), db=Depends(get_db)):
    p = get_project(db, pid)
    p["members"] = q(db, "SELECT u.id,u.name,u.department,u.skills,m.role FROM members m JOIN users u ON u.id=m.user_id WHERE m.project_id=%s ORDER BY m.joined_at, u.id", (pid,))
    p["owner_name"] = next((m["name"] for m in p["members"] if m["id"] == p["owner_id"]), "")
    p["is_member"] = bool(u) and any(m["id"] == u["id"] for m in p["members"])
    r = db.execute("SELECT status FROM requests WHERE project_id=%s AND user_id=%s", (pid, u["id"])).fetchone() if u else None
    p["my_request"] = r["status"] if r else None
    return p


@app.put("/projects/{pid}")
def edit_project(pid: int, d: ProjectIn, u=Depends(current_user), db=Depends(get_db)):
    p = get_project(db, pid)
    if p["owner_id"] != u["id"] and u["role"] != "admin":
        raise HTTPException(403, "Only the owner can edit this project")
    db.execute("UPDATE projects SET title=%s,description=%s,category=%s,technologies=%s,required_skills=%s,goals=%s,status=%s,"
               "team_size=%s,location=%s,meeting_time=%s,roles_needed=%s,branch_restrictions=%s WHERE id=%s",
               (d.title, d.description, d.category, d.technologies, d.required_skills, d.goals, d.status,
                d.team_size, d.location, d.meeting_time, d.roles_needed, d.branch_restrictions, pid))
    if d.status != p["status"]:
        for m in q(db, "SELECT user_id FROM members WHERE project_id=%s AND user_id!=%s", (pid, u["id"])):
            notify(db, m["user_id"], f"“{d.title}” is now {d.status}")
        log(db, f"“{d.title}” moved to {d.status}")
    return {"ok": True}


@app.delete("/projects/{pid}")
def delete_project(pid: int, u=Depends(current_user), db=Depends(get_db)):
    p = get_project(db, pid)
    if p["owner_id"] != u["id"] and u["role"] != "admin":
        raise HTTPException(403, "Only the owner or an admin can delete this project")
    for m in q(db, "SELECT user_id FROM members WHERE project_id=%s AND user_id!=%s", (pid, u["id"])):
        notify(db, m["user_id"], f"“{p['title']}” was removed")
    db.execute("DELETE FROM projects WHERE id=%s", (pid,))
    return {"ok": True}


# ---------- Collaboration ----------
@app.post("/projects/{pid}/request", status_code=201)
def request_join(pid: int, u=Depends(current_user), db=Depends(get_db)):
    p = get_project(db, pid)
    if db.execute("SELECT 1 FROM members WHERE project_id=%s AND user_id=%s", (pid, u["id"])).fetchone():
        raise HTTPException(409, "You are already on this team")
    if db.execute("SELECT COUNT(*) AS c FROM members WHERE project_id=%s", (pid,)).fetchone()["c"] >= p["team_size"]:
        raise HTTPException(400, "This team is full")
    r = db.execute("SELECT status FROM requests WHERE project_id=%s AND user_id=%s", (pid, u["id"])).fetchone()
    if r and r["status"] == "pending":
        raise HTTPException(409, "Request already pending")
    if r:
        db.execute("UPDATE requests SET status='pending' WHERE project_id=%s AND user_id=%s", (pid, u["id"]))
    else:
        db.execute("INSERT INTO requests(project_id,user_id) VALUES(%s,%s)", (pid, u["id"]))
    notify(db, p["owner_id"], f"{u['name']} requested to join “{p['title']}”")
    return {"ok": True}


def decide(rid, accept, u, db):
    r = db.execute("SELECT r.id, r.project_id, r.user_id, r.status, p.owner_id, p.title, p.team_size "
                   "FROM requests r JOIN projects p ON p.id=r.project_id WHERE r.id=%s", (rid,)).fetchone()
    if not r:
        raise HTTPException(404, "Request not found")
    if r["owner_id"] != u["id"]:
        raise HTTPException(403, "Only the project owner can decide")
    if r["status"] != "pending":
        raise HTTPException(409, "Already decided")
    if accept and db.execute("SELECT COUNT(*) AS c FROM members WHERE project_id=%s", (r["project_id"],)).fetchone()["c"] >= r["team_size"]:
        raise HTTPException(400, "Team is full")
    db.execute("UPDATE requests SET status=%s WHERE id=%s", ("accepted" if accept else "rejected", rid))
    if accept:
        db.execute("INSERT INTO members(project_id,user_id) VALUES(%s,%s) ON CONFLICT DO NOTHING", (r["project_id"], r["user_id"]))
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
    db.execute("DELETE FROM members WHERE project_id=%s AND user_id=%s", (pid, u["id"]))
    db.execute("DELETE FROM requests WHERE project_id=%s AND user_id=%s", (pid, u["id"]))
    notify(db, p["owner_id"], f"{u['name']} left “{p['title']}”")
    return {"ok": True}


@app.put("/projects/{pid}/members/{uid}/role")
def set_role(pid: int, uid: int, d: RoleIn, u=Depends(current_user), db=Depends(get_db)):
    p = get_project(db, pid)
    if p["owner_id"] != u["id"]:
        raise HTTPException(403, "Only the owner can assign roles")
    if not db.execute("SELECT 1 FROM members WHERE project_id=%s AND user_id=%s", (pid, uid)).fetchone():
        raise HTTPException(404, "Not a team member")
    db.execute("UPDATE members SET role=%s WHERE project_id=%s AND user_id=%s", (d.role, pid, uid))
    if uid != u["id"]:
        notify(db, uid, f"Your role in “{p['title']}” is now {d.role}")
    return {"ok": True}


# ---------- Dashboard & notifications ----------
@app.get("/dashboard")
def dashboard(u=Depends(current_user), db=Depends(get_db)):
    uid = u["id"]
    wanted = tokens(u["skills"]) | tokens(u["interests"])
    cand = q(db, "SELECT id,title,category,technologies,required_skills,status FROM projects "
                 "WHERE owner_id!=%s AND id NOT IN (SELECT project_id FROM members WHERE user_id=%s) ORDER BY id DESC", (uid, uid))
    for c in cand:
        c["score"] = len(wanted & (tokens(c["required_skills"]) | tokens(c["technologies"]) | tokens(c["category"])))
    return {
        "mine": q(db, "SELECT id,title,status,category FROM projects WHERE owner_id=%s ORDER BY id DESC", (uid,)),
        "joined": q(db, "SELECT p.id,p.title,p.status,p.category,m.role FROM members m JOIN projects p ON p.id=m.project_id WHERE m.user_id=%s AND p.owner_id!=%s ORDER BY p.id DESC", (uid, uid)),
        "incoming": q(db, "SELECT r.id,p.id AS project_id,p.title,us.name,us.skills FROM requests r JOIN projects p ON p.id=r.project_id JOIN users us ON us.id=r.user_id WHERE p.owner_id=%s AND r.status='pending' ORDER BY r.id DESC", (uid,)),
        "sent": q(db, "SELECT r.status,p.id AS project_id,p.title FROM requests r JOIN projects p ON p.id=r.project_id WHERE r.user_id=%s AND r.status!='accepted' ORDER BY r.id DESC", (uid,)),
        "notifications": q(db, "SELECT id,text,is_read,created_at FROM notifications WHERE user_id=%s ORDER BY id DESC LIMIT 10", (uid,)),
        "recommended": sorted(cand, key=lambda c: -c["score"])[:5],
        "activity": q(db, "SELECT text,created_at FROM activity ORDER BY id DESC LIMIT 8"),
    }


@app.post("/notifications/read")
def mark_read(u=Depends(current_user), db=Depends(get_db)):
    db.execute("UPDATE notifications SET is_read=1 WHERE user_id=%s", (u["id"],))
    return {"ok": True}


# ---------- Admin ----------
@app.get("/admin/stats")
def stats(a=Depends(admin_user), db=Depends(get_db)):
    n = lambda t, w="TRUE": db.execute(f"SELECT COUNT(*) AS c FROM {t} WHERE {w}").fetchone()["c"]
    return {"students": n("users", "role='student'"), "projects": n("projects"), "pending_requests": n("requests", "status='pending'"),
            "memberships": n("members"), "by_status": q(db, "SELECT status, COUNT(*) AS count FROM projects GROUP BY status"),
            "activity": q(db, "SELECT text,created_at FROM activity ORDER BY id DESC LIMIT 10")}


@app.get("/admin/users")
def admin_users(a=Depends(admin_user), db=Depends(get_db)):
    return q(db, "SELECT id,usn,name,college,department,year,role,created_at, "
                 "(SELECT COUNT(*) FROM projects p WHERE p.owner_id=users.id) AS projects FROM users ORDER BY id")


@app.delete("/admin/users/{uid}")
def admin_delete_user(uid: int, a=Depends(admin_user), db=Depends(get_db)):
    if uid == a["id"]:
        raise HTTPException(400, "You can't delete your own account")
    db.execute("DELETE FROM users WHERE id=%s", (uid,))
    return {"ok": True}
