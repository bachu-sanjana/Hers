import hashlib, sqlite3, time, io, os
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Header, Request
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles

os.makedirs("uploads", exist_ok=True)
db = sqlite3.connect("sakshya.db", check_same_thread=False)
db.execute("create table if not exists inc(id integer primary key, ts text, kind text, who text, note text, fname text, file_hash text, prev text, chain text)")
db.execute("create table if not exists cfg(k text primary key, v text)")
app = FastAPI()
S = {}  # session token -> "real" | "duress"
K = ["id", "ts", "kind", "who", "note", "fname", "file_hash", "prev", "chain"]

H = lambda b: hashlib.sha256(b).hexdigest()
def cfg(k):
    r = db.execute("select v from cfg where k=?", (k,)).fetchone(); return r and r[0]
def setcfg(k, v):
    db.execute("insert or replace into cfg values(?,?)", (k, v)); db.commit()
def mode(t):
    if t not in S: raise HTTPException(401, "Locked")
    return S[t]
def rows(): return db.execute("select " + ",".join(K) + " from inc order by id").fetchall()
def link(prev, fh, ts, kind, who, note): return H("|".join([prev, fh, ts, kind, who, note]).encode())

@app.get("/api/status")
def status(): return {"setup": cfg("pin") is not None}

def ph(pin, salt): return hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 200000).hex()

@app.post("/api/login")
def login(pin: str = Form(...)):
    if not cfg("pin"): raise HTTPException(400, "Not set up")
    h = ph(pin, cfg("salt"))
    m = "real" if h == cfg("pin") else "duress" if h == cfg("duress") else None
    if not m: raise HTTPException(403, "Wrong PIN")
    t = os.urandom(16).hex(); S[t] = m; return {"token": t}

@app.post("/api/setup")
def setup(pin: str = Form(...), duress: str = Form(...)):
    if cfg("pin"): raise HTTPException(400, "Already set up")
    if not pin or pin == duress: raise HTTPException(400, "PINs must be set and different")
    salt = os.urandom(16).hex(); setcfg("salt", salt)
    setcfg("pin", ph(pin, salt)); setcfg("duress", ph(duress, salt))
    return login(pin)

@app.get("/api/incidents")
def incidents(x_token: str = Header("")):
    if mode(x_token) == "duress": return []
    return [dict(zip(K, r)) for r in rows()]

@app.post("/api/incidents")
async def add(file: UploadFile = File(...), kind: str = Form(...), who: str = Form(""),
              note: str = Form(""), client_hash: str = Form(""), x_token: str = Header("")):
    m = mode(x_token); data = await file.read(); fh = H(data)
    if client_hash and client_hash != fh: raise HTTPException(400, "Hash mismatch")
    if m == "duress": return {"ok": True}  # decoy: looks saved, stores nothing
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()) + " UTC"
    r = rows(); prev = r[-1][8] if r else "GENESIS"
    ch = link(prev, fh, ts, kind, who, note)
    cur = db.execute("insert into inc(ts,kind,who,note,fname,file_hash,prev,chain) values(?,?,?,?,?,?,?,?)",
                     (ts, kind, who, note, file.filename, fh, prev, ch)); db.commit()
    open(f"uploads/{cur.lastrowid}", "wb").write(data)
    return {"ok": True}

@app.get("/api/audit")
def audit(x_token: str = Header("")):
    if mode(x_token) == "duress": return {"chain_ok": True, "files": []}
    prev, ok, res = "GENESIS", True, []
    for id, ts, kind, who, note, fn, fh, pv, ch in rows():
        l = pv == prev and link(pv, fh, ts, kind, who, note) == ch
        p = f"uploads/{id}"
        f = os.path.exists(p) and H(open(p, "rb").read()) == fh
        ok &= l; prev = ch
        res.append({"id": id, "link_ok": l, "file_ok": f})
    return {"chain_ok": ok, "files": res}

@app.post("/api/verify")  # public: only answers "does this file match a record?"
async def verify(file: UploadFile = File(...)):
    h = H(await file.read())
    r = db.execute("select id,ts,kind from inc where file_hash=?", (h,)).fetchone()
    if r: return {"status": "verified", "hash": h, "incident": r[0], "ts": r[1], "kind": r[2]}
    s = db.execute("select id from inc where fname=?", (file.filename,)).fetchone()
    return {"status": "modified" if s else "unknown", "hash": h}

@app.get("/api/report")
def report(request: Request, x_token: str = Header("")):
    R = [] if mode(x_token) == "duress" else rows()
    import qrcode
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, Spacer, Image
    from reportlab.lib.styles import getSampleStyleSheet
    st = getSampleStyleSheet(); buf = io.BytesIO(); qb = io.BytesIO()
    qrcode.make(str(request.base_url) + "verify.html").save(qb, "PNG"); qb.seek(0)
    head = R[-1][8] if R else "-"
    el = [Paragraph("Sakshya - Evidence Integrity Report", st["Title"]),
          Paragraph(f"Generated {time.strftime('%Y-%m-%d %H:%M')} UTC | Incidents: {len(R)}<br/>Chain head: <font size=7>{head}</font>", st["Normal"]),
          Spacer(1, 12)]
    data = [["#", "Time", "Type", "Person", "File SHA-256"]] + \
           [[r[0], r[1], r[2], r[3], Paragraph(f"<font size=6>{r[6]}</font>", st["Normal"])] for r in R]
    el += [Table(data, repeatRows=1, style=[("GRID", (0, 0), (-1, -1), .5, "grey"), ("FONTSIZE", (0, 0), (-1, -1), 7)]),
           Spacer(1, 12), Paragraph("Scan to verify a file:", st["Normal"]), Image(qb, 100, 100)]
    SimpleDocTemplate(buf, pagesize=A4).build(el); buf.seek(0)
    return StreamingResponse(buf, media_type="application/pdf")

app.mount("/", StaticFiles(directory="static", html=True))
