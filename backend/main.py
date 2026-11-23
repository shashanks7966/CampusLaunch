import base64, hashlib, hmac, json, os, re, secrets, time
from urllib.parse import quote, urlencode
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
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
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")   # public address of THIS backend
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5500").rstrip("/")  # public address of the website
PROVIDERS = {
    "google": dict(auth="https://accounts.google.com/o/oauth2/v2/auth", token="https://oauth2.googleapis.com/token",
                   info="https://openidconnect.googleapis.com/v1/userinfo", scope="openid email profile"),
    "github": dict(auth="https://github.com/login/oauth/authorize", token="https://github.com/login/oauth/access_token",
                   info="https://api.github.com/user", scope="read:user"),
    "linkedin": dict(auth="https://www.linkedin.com/oauth/v2/authorization", token="https://www.linkedin.com/oauth/v2/accessToken",
                     info="https://api.linkedin.com/v2/userinfo", scope="openid profile email"),
}

# A small pool of reusable database connections (faster than reconnecting every request)
pool = ConnectionPool(
    DATABASE_URL, min_size=1, max_size=5, open=False,
    check=ConnectionPool.check_connection,  # drops connections Neon closed while idle
    kwargs={"row_factory": dict_row, "prepare_threshold": None, "connect_timeout": 15},
)

TS = "TEXT DEFAULT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI')"
SCHEMA = f"""
CREATE TABLE IF NOT EXISTS users(
  id SERIAL PRIMARY KEY, usn TEXT UNIQUE, name TEXT NOT NULL, college TEXT NOT NULL,
  department TEXT DEFAULT '', year INTEGER DEFAULT 1, skills TEXT DEFAULT '', interests TEXT DEFAULT '',
  email TEXT DEFAULT '', phone TEXT DEFAULT '', role TEXT DEFAULT 'student', salt TEXT NOT NULL, pw TEXT NOT NULL, created_at {TS});
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
CREATE TABLE IF NOT EXISTS social_accounts(
  id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL, provider_id TEXT NOT NULL, created_at {TS}, UNIQUE(provider, provider_id));
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
    return db.execute("SELECT id,usn,name,college,department,year,skills,interests,email,phone,role, "
                      "(SELECT COUNT(*) FROM notifications n WHERE n.user_id=users.id AND n.is_read=0) AS unread FROM users WHERE id=%s", (uid,)).fetchone()


def current_user(u=Depends(optional_user)):
    if not u:
        raise HTTPException(401, "Please sign in")
    return u


def student_user(u=Depends(current_user)):
    if not u["usn"] or not u["college"] or not (u["email"] or u["phone"]):
        raise HTTPException(403, "Please add your USN, college and a phone number or email in your profile first")
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


SAMPLE_CONTACTS = {"DEMO001": "demo@campuslaunch.example", "1XX21CS002": "aarav@campuslaunch.example",
                   "1XX21EC010": "meera@campuslaunch.example", "1XX22IS005": "kiran@campuslaunch.example"}


def init_db():
    with pool.connection() as db:
        db.execute(SCHEMA)
        for t in ("users", "projects", "members", "requests", "notifications", "activity", "social_accounts"):
            db.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")  # keeps Supabase's public web API away from these tables
        db.execute("ALTER TABLE users ALTER COLUMN usn DROP NOT NULL")  # upgrade for existing databases
        for col in ("projects(owner_id)", "members(user_id)", "requests(user_id)", "requests(project_id)", "notifications(user_id)", "social_accounts(user_id)"):
            db.execute(f"CREATE INDEX IF NOT EXISTS idx_{col.replace('(', '_').replace(')', '')} ON {col}")  # keeps lookups fast as data grows
        if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            seed(db)  # sample data is only added to an empty database
        db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT DEFAULT ''")  # upgrade for existing databases
        db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT DEFAULT ''")
        for usn, mail in SAMPLE_CONTACTS.items():  # sample accounts get a contact so the demo keeps working
            db.execute("UPDATE users SET email=%s WHERE usn=%s AND COALESCE(email,'')='' AND COALESCE(phone,'')=''", (mail, usn))
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


@app.api_route("/", methods=["GET", "HEAD"])  # monitors often check with HEAD; this keeps them from seeing an error
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
    email: str = Field("", max_length=200)
    phone: str = Field("", max_length=30)


class Login(BaseModel):
    usn: str
    password: str
    remember: bool = False


class Profile(BaseModel):
    usn: Optional[str] = Field(None, min_length=3, max_length=30)
    email: Optional[str] = Field(None, max_length=200)
    phone: Optional[str] = Field(None, max_length=30)
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
def clean_contact(email, phone):
    email = (email or "").strip().lower()
    phone = re.sub(r"[\s\-()]", "", phone or "")
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(400, "Enter a valid email address")
    if phone and not re.fullmatch(r"\+?\d{7,15}", phone):
        raise HTTPException(400, "Enter a valid phone number (7 to 15 digits, may start with +)")
    return email, phone


@app.post("/register", status_code=201)
def register(d: Reg, db=Depends(get_db)):
    usn = d.usn.strip().upper()
    email, phone = clean_contact(d.email, d.phone)
    if not (email or phone):
        raise HTTPException(400, "Please add a phone number or email so project owners can reach you")
    if db.execute("SELECT 1 FROM users WHERE usn=%s", (usn,)).fetchone():
        raise HTTPException(409, "USN already registered")
    salt = secrets.token_hex(16)
    uid = insert(db, "INSERT INTO users(usn,name,college,department,year,email,phone,salt,pw) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                 (usn, d.name, d.college, d.department, d.year, email, phone, salt, hash_pw(d.password, salt)))
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
    return u


@app.put("/me")
def update_me(d: Profile, u=Depends(current_user), db=Depends(get_db)):
    data = d.model_dump(exclude_none=True)
    if "usn" in data:  # students can correct their USN, as long as nobody else has it
        new = data["usn"].strip().upper()
        if new == u["usn"]:
            data.pop("usn")
        elif db.execute("SELECT 1 FROM users WHERE usn=%s AND id!=%s", (new, u["id"])).fetchone():
            raise HTTPException(409, "That USN is already registered")
        else:
            data["usn"] = new
    if "email" in data or "phone" in data:
        email, phone = clean_contact(data.get("email", u["email"]), data.get("phone", u["phone"]))
        if not (email or phone):
            raise HTTPException(400, "Keep at least one contact detail (phone or email)")
        data["email"], data["phone"] = email, phone
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
def create_project(d: ProjectIn, u=Depends(student_user), db=Depends(get_db)):
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
    p["members"] = q(db, "SELECT u.id,u.name,u.department,u.skills,u.email,u.phone,m.role FROM members m JOIN users u ON u.id=m.user_id WHERE m.project_id=%s ORDER BY m.joined_at, u.id", (pid,))
    p["owner_name"] = next((m["name"] for m in p["members"] if m["id"] == p["owner_id"]), "")
    p["is_member"] = bool(u) and any(m["id"] == u["id"] for m in p["members"])
    if not (p["is_member"] or (u and u["role"] == "admin")):  # contact details are only shown to teammates
        for m in p["members"]:
            m.pop("email", None); m.pop("phone", None)
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
def request_join(pid: int, u=Depends(student_user), db=Depends(get_db)):
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
def _rows(inner):
    return f"(SELECT COALESCE(json_agg(x), '[]'::json) FROM ({inner}) x)"


DASHBOARD_SQL = "SELECT " + ", ".join([
    _rows("SELECT id,title,status,category FROM projects WHERE owner_id=%(u)s ORDER BY id DESC") + " AS mine",
    _rows("SELECT p.id,p.title,p.status,p.category,m.role FROM members m JOIN projects p ON p.id=m.project_id "
          "WHERE m.user_id=%(u)s AND p.owner_id!=%(u)s ORDER BY p.id DESC") + " AS joined",
    _rows("SELECT r.id,p.id AS project_id,p.title,us.name,us.skills,us.email,us.phone FROM requests r "
          "JOIN projects p ON p.id=r.project_id JOIN users us ON us.id=r.user_id "
          "WHERE p.owner_id=%(u)s AND r.status='pending' ORDER BY r.id DESC") + " AS incoming",
    _rows("SELECT r.status,p.id AS project_id,p.title FROM requests r JOIN projects p ON p.id=r.project_id "
          "WHERE r.user_id=%(u)s AND r.status!='accepted' ORDER BY r.id DESC") + " AS sent",
    _rows("SELECT id,text,is_read,created_at FROM notifications WHERE user_id=%(u)s ORDER BY id DESC LIMIT 10") + " AS notifications",
    _rows("SELECT text,created_at FROM activity ORDER BY id DESC LIMIT 8") + " AS activity",
    _rows("SELECT id,title,category,technologies,required_skills,status FROM projects WHERE owner_id!=%(u)s "
          "AND id NOT IN (SELECT project_id FROM members WHERE user_id=%(u)s) ORDER BY id DESC") + " AS cand",
])


@app.get("/dashboard")
def dashboard(u=Depends(current_user), db=Depends(get_db)):
    d = db.execute(DASHBOARD_SQL, {"u": u["id"]}).fetchone()  # everything in a single trip to the database
    wanted = tokens(u["skills"]) | tokens(u["interests"])
    cand = d.pop("cand")
    for c in cand:
        c["score"] = len(wanted & (tokens(c["required_skills"]) | tokens(c["technologies"]) | tokens(c["category"])))
    d["recommended"] = sorted(cand, key=lambda c: -c["score"])[:5]
    return d


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
    return q(db, "SELECT id,usn,name,college,department,year,email,phone,role,created_at, "
                 "(SELECT COUNT(*) FROM projects p WHERE p.owner_id=users.id) AS projects FROM users ORDER BY id")


@app.delete("/admin/users/{uid}")
def admin_delete_user(uid: int, a=Depends(admin_user), db=Depends(get_db)):
    if uid == a["id"]:
        raise HTTPException(400, "You can't delete your own account")
    db.execute("DELETE FROM users WHERE id=%s", (uid,))
    return {"ok": True}


# ---------- Sign in with Google / GitHub / LinkedIn ----------
def sign(data, ttl):
    body = base64.urlsafe_b64encode(json.dumps({**data, "e": int(time.time() + ttl)}).encode()).decode()
    return body + "." + hmac.new(SECRET.encode(), body.encode(), "sha256").hexdigest()


def unsign(s):
    try:
        body, sig = s.rsplit(".", 1)
        if hmac.compare_digest(sig, hmac.new(SECRET.encode(), body.encode(), "sha256").hexdigest()):
            d = json.loads(base64.urlsafe_b64decode(body.encode()))
            if d["e"] > time.time():
                return d
    except Exception:
        pass
    return None


def creds(p):
    return os.getenv(f"{p.upper()}_CLIENT_ID"), os.getenv(f"{p.upper()}_CLIENT_SECRET")


def enabled():
    return [p for p in PROVIDERS if all(creds(p))]  # only providers whose keys you have set


def check_provider(p):
    if p not in enabled():
        raise HTTPException(404, "This sign-in option is not set up")


def back(fragment):
    return RedirectResponse(f"{FRONTEND_URL}/#{fragment}")


@app.get("/auth/providers")
def providers():
    return {"enabled": enabled()}


@app.get("/auth/linked")
def linked(u=Depends(current_user), db=Depends(get_db)):
    return {"linked": [r["provider"] for r in q(db, "SELECT provider FROM social_accounts WHERE user_id=%s", (u["id"],))]}


@app.post("/auth/{provider}/link")
def link_ticket(provider: str, u=Depends(current_user)):
    check_provider(provider)  # a short-lived ticket proves who is connecting the account
    return {"url": f"{BACKEND_URL}/auth/{provider}/login?ticket={sign({'u': u['id'], 'k': 'link'}, 300)}"}


@app.get("/auth/{provider}/login")
def oauth_login(provider: str, ticket: str = ""):
    check_provider(provider)
    link_uid = 0
    if ticket:
        t = unsign(ticket)
        if not t or t.get("k") != "link":
            raise HTTPException(400, "This link expired. Go back and try again.")
        link_uid = t["u"]
    nonce = secrets.token_urlsafe(16)
    state = sign({"p": provider, "n": nonce, "l": link_uid}, 600)
    cid, _ = creds(provider)
    params = {"client_id": cid, "redirect_uri": f"{BACKEND_URL}/auth/{provider}/callback",
              "response_type": "code", "scope": PROVIDERS[provider]["scope"], "state": state}
    resp = RedirectResponse(PROVIDERS[provider]["auth"] + "?" + urlencode(params))
    resp.set_cookie("oauth_nonce", nonce, max_age=600, httponly=True, samesite="lax", secure=BACKEND_URL.startswith("https"))
    return resp


@app.get("/auth/{provider}/callback")
def oauth_callback(provider: str, request: Request, code: str = "", state: str = "", error: str = "", db=Depends(get_db)):
    check_provider(provider)
    st = unsign(state) if state else None
    if error or not code or not st or st.get("p") != provider or not hmac.compare_digest(st["n"], request.cookies.get("oauth_nonce", "")):
        return back("error=" + quote("Sign-in was cancelled or expired. Please try again."))
    cid, secret = creds(provider)
    cfg = PROVIDERS[provider]
    try:
        with httpx.Client(timeout=15) as h:
            tok = h.post(cfg["token"], headers={"Accept": "application/json"}, data={
                "grant_type": "authorization_code", "code": code, "client_id": cid, "client_secret": secret,
                "redirect_uri": f"{BACKEND_URL}/auth/{provider}/callback"}).json()
            at = tok.get("access_token")
            info = h.get(cfg["info"], headers={"Authorization": f"Bearer {at}", "Accept": "application/json"}).json() if at else {}
        pid = str(info.get("sub") or info.get("id") or "")
        name = (info.get("name") or info.get("login") or "New Student")[:100]
        email = str(info.get("email") or "")[:200]
        email = email.lower() if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) else ""
        if not pid:
            raise ValueError("no id")
    except Exception:
        return back("error=" + quote(f"Could not complete sign-in with {provider.title()}."))
    row = db.execute("SELECT user_id FROM social_accounts WHERE provider=%s AND provider_id=%s", (provider, pid)).fetchone()
    link_uid = st.get("l", 0)
    if link_uid:  # connecting an extra login method to an existing account
        if row and row["user_id"] != link_uid:
            return back("error=" + quote("That account is already connected to another student."))
        if not row:
            db.execute("INSERT INTO social_accounts(user_id,provider,provider_id) VALUES(%s,%s,%s)", (link_uid, provider, pid))
        resp = back("linked=" + provider)
    else:
        new = row is None
        if new:  # first social login: create the account, USN and college are added afterwards
            salt = secrets.token_hex(16)
            uid = insert(db, "INSERT INTO users(name,college,email,salt,pw) VALUES(%s,'',%s,%s,%s)", (name, email, salt, hash_pw(secrets.token_urlsafe(32), salt)))
            db.execute("INSERT INTO social_accounts(user_id,provider,provider_id) VALUES(%s,%s,%s)", (uid, provider, pid))
            notify(db, uid, "Welcome to CampusLaunch! Add your USN and college to start joining projects.")
            log(db, f"{name} joined CampusLaunch")
        else:
            uid = row["user_id"]
        resp = back(f"token={make_token(uid, 7)}&new={int(new)}")
    db.commit()
    resp.delete_cookie("oauth_nonce")
    return resp
