import os
import re
import json
import time
import secrets
import sqlite3
from functools import wraps
from contextlib import closing
from datetime import datetime, timezone
from flask import Flask, request, jsonify, g

app = Flask(__name__)
DB_PATH = os.environ.get("KINLY_DB_PATH", os.path.join(os.path.dirname(__file__), "kinly.sqlite3"))

def connect_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with closing(connect_db()) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL UNIQUE,
            token TEXT NOT NULL UNIQUE,
            family_code TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            token TEXT NOT NULL UNIQUE,
            family_code TEXT NOT NULL,
            device_name TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS device_locations (
            device_id TEXT PRIMARY KEY,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            accuracy REAL,
            recorded_at TEXT NOT NULL,
            received_at TEXT NOT NULL,
            FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_devices_family ON devices(family_code);
        CREATE TABLE IF NOT EXISTS locations (
            user_id INTEGER PRIMARY KEY,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            accuracy REAL,
            recorded_at TEXT NOT NULL,
            received_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_users_family ON users(family_code);
        """)
        db.commit()

init_db()

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def bearer_token():
    value = request.headers.get("Authorization", "")
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return ""

def current_user():
    token = bearer_token()
    if not token:
        return None
    with closing(connect_db()) as db:
        return db.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()

def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return jsonify({"ok": False, "error": "Authentication required"}), 401
        g.user = user
        return fn(*args, **kwargs)
    return wrapper

@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "Sumo Family Tracker V3", "time": now_iso()})

def current_device():
    token = bearer_token()
    if not token:
        return None
    with closing(connect_db()) as db:
        return db.execute("SELECT * FROM devices WHERE token = ?", (token,)).fetchone()

def device_auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        device = current_device()
        if device is None:
            return jsonify({"ok": False, "error": "Device registration required"}), 401
        g.device = device
        return fn(*args, **kwargs)
    return wrapper

@app.post("/api/device/register")
def register_device():
    data = request.get_json(silent=True) or {}
    device_id = str(data.get("device_id", "")).strip()
    with closing(connect_db()) as db:
        row = db.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone() if device_id else None
        display_name = str(data.get("name", "User")).strip()
        if len(display_name) < 2 or len(display_name) > 40:
            return jsonify({"ok": False, "error": "Enter a name between 2 and 40 characters."}), 400
        if row:
            token = row["token"]
            code = row["family_code"]
            did = row["id"]
            db.execute("UPDATE devices SET device_name=? WHERE id=?", (display_name, did))
        else:
            did = secrets.token_urlsafe(18)
            token = secrets.token_urlsafe(32)
            code = "PUBLIC"
            db.execute("INSERT INTO devices(id, token, family_code, device_name, created_at) VALUES(?,?,?,?,?)",
                       (did, token, code, display_name, now_iso()))
        db.commit()
    return jsonify({"ok": True, "device_id": did, "token": token, "device_name": display_name})

@app.post("/api/location")
@device_auth_required
def update_device_location():
    data = request.get_json(silent=True) or {}
    try:
        lat = float(data.get("latitude")); lon = float(data.get("longitude"))
        accuracy = float(data.get("accuracy", 0))
        stamp = int(data.get("timestamp", int(time.time() * 1000)))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "Invalid location payload"}), 400
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return jsonify({"ok": False, "error": "Coordinates out of range"}), 400
    with closing(connect_db()) as db:
        db.execute("""INSERT INTO device_locations(device_id,latitude,longitude,accuracy,recorded_at,received_at)
            VALUES(?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET latitude=excluded.latitude,
            longitude=excluded.longitude,accuracy=excluded.accuracy,recorded_at=excluded.recorded_at,
            received_at=excluded.received_at""",
            (g.device["id"], lat, lon, accuracy, datetime.fromtimestamp(stamp/1000, timezone.utc).isoformat(), now_iso()))
        db.commit()
    return jsonify({"ok": True})

@app.get("/api/people")
def all_people():
    # People appear here only after explicitly entering a name and enabling location sharing.
    with closing(connect_db()) as db:
        rows = db.execute("""SELECT d.id,d.device_name,l.latitude,l.longitude,l.accuracy,l.recorded_at
            FROM devices d JOIN device_locations l ON l.device_id=d.id
            ORDER BY l.received_at DESC""").fetchall()
    return jsonify({"ok": True, "members": [
        {"id": r["id"], "name": r["device_name"], "latitude": r["latitude"],
         "longitude": r["longitude"], "accuracy": r["accuracy"],
         "recorded_at": r["recorded_at"], "has_location": True}
        for r in rows
    ]})

@app.get("/api/device/family")
@device_auth_required
def device_family():
    with closing(connect_db()) as db:
        rows = db.execute("""SELECT d.id,d.device_name,l.latitude,l.longitude,l.accuracy,l.recorded_at
            FROM devices d LEFT JOIN device_locations l ON l.device_id=d.id
            WHERE d.family_code=? ORDER BY d.created_at""", (g.device["family_code"],)).fetchall()
    return jsonify({"ok": True, "family_code": g.device["family_code"], "members": [
        {"id":r["id"],"name":r["device_name"],"latitude":r["latitude"],"longitude":r["longitude"],
         "accuracy":r["accuracy"],"recorded_at":r["recorded_at"],"has_location":r["latitude"] is not None}
        for r in rows]})

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    phone = re.sub(r"\s+", "", str(data.get("phone", "")))
    family_code = str(data.get("family_code", "")).strip().upper()

    if len(name) < 2 or len(name) > 60:
        return jsonify({"ok": False, "error": "Enter a name between 2 and 60 characters."}), 400
    if not re.fullmatch(r"\+?[0-9]{8,15}", phone):
        return jsonify({"ok": False, "error": "Enter a valid phone number (8–15 digits, optional +)."}), 400
    if family_code and not re.fullmatch(r"[A-Z0-9]{6,10}", family_code):
        return jsonify({"ok": False, "error": "Family code must be 6–10 letters or numbers."}), 400

    with closing(connect_db()) as db:
        user = db.execute("SELECT * FROM users WHERE phone = ?", (phone,)).fetchone()
        if user:
            # This simple no-OTP flow is intentionally not identity-proofing.
            if user["name"].casefold() != name.casefold():
                return jsonify({"ok": False, "error": "This phone number is already registered with a different name."}), 409
            if family_code and family_code != user["family_code"]:
                return jsonify({"ok": False, "error": "This phone number already belongs to a different family."}), 409
            token = user["token"]
            family_code = user["family_code"]
            user_id = user["id"]
        else:
            if not family_code:
                family_code = secrets.token_hex(4).upper()[:8]
            else:
                exists = db.execute("SELECT 1 FROM users WHERE family_code = ? LIMIT 1", (family_code,)).fetchone()
                if not exists:
                    return jsonify({"ok": False, "error": "That family code does not exist. Ask the family owner for the correct code."}), 404
            token = secrets.token_urlsafe(32)
            created_at = now_iso()
            cur = db.execute(
                "INSERT INTO users(name, phone, token, family_code, created_at) VALUES(?,?,?,?,?)",
                (name, phone, token, family_code, created_at)
            )
            user_id = cur.lastrowid
        db.commit()

    return jsonify({
        "ok": True,
        "token": token,
        "user": {"id": user_id, "name": name, "phone": phone},
        "family_code": family_code,
        "message": "Signed in"
    })

@app.get("/api/me")
@auth_required
def me():
    u = g.user
    return jsonify({"ok": True, "user": {"id": u["id"], "name": u["name"], "phone": u["phone"]}, "family_code": u["family_code"]})

@app.post("/api/location")
@auth_required
def update_location():
    data = request.get_json(silent=True) or {}
    try:
        lat = float(data.get("latitude"))
        lon = float(data.get("longitude"))
        accuracy = float(data.get("accuracy", 0))
        timestamp_ms = int(data.get("timestamp", int(time.time() * 1000)))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "Invalid location payload"}), 400
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return jsonify({"ok": False, "error": "Coordinates out of range"}), 400
    recorded_at = datetime.fromtimestamp(timestamp_ms / 1000, timezone.utc).isoformat()
    with closing(connect_db()) as db:
        db.execute("""
            INSERT INTO locations(user_id, latitude, longitude, accuracy, recorded_at, received_at)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(user_id) DO UPDATE SET
                latitude=excluded.latitude,
                longitude=excluded.longitude,
                accuracy=excluded.accuracy,
                recorded_at=excluded.recorded_at,
                received_at=excluded.received_at
        """, (g.user["id"], lat, lon, accuracy, recorded_at, now_iso()))
        db.commit()
    return jsonify({"ok": True, "message": "Location updated"})

@app.get("/api/family/locations")
@auth_required
def family_locations():
    with closing(connect_db()) as db:
        rows = db.execute("""
            SELECT u.id, u.name, u.phone, l.latitude, l.longitude, l.accuracy, l.recorded_at, l.received_at
            FROM users u LEFT JOIN locations l ON l.user_id = u.id
            WHERE u.family_code = ?
            ORDER BY u.name COLLATE NOCASE
        """, (g.user["family_code"],)).fetchall()
    members = []
    for row in rows:
        members.append({
            "id": row["id"], "name": row["name"], "phone": row["phone"],
            "latitude": row["latitude"], "longitude": row["longitude"],
            "accuracy": row["accuracy"], "recorded_at": row["recorded_at"],
            "received_at": row["received_at"],
            "has_location": row["latitude"] is not None
        })
    return jsonify({"ok": True, "members": members, "family_code": g.user["family_code"]})

@app.post("/api/logout")
@auth_required
def logout():
    # Revoke current token; the user can sign in again with name/phone under this prototype flow.
    with closing(connect_db()) as db:
        db.execute("UPDATE users SET token = ? WHERE id = ?", (secrets.token_urlsafe(32), g.user["id"]))
        db.commit()
    return jsonify({"ok": True})

DASHBOARD = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sumo Family Tracker</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>
:root{--wine:#8a004f;--pink:#c2185b;--ink:#28232a;--muted:#77717a;--bg:#faf7f9;--line:#eee5eb}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--ink)}
header{background:#fff;border-bottom:1px solid var(--line);padding:16px 22px;display:flex;align-items:center;justify-content:space-between;gap:12px}
.brand{font-size:23px;font-weight:850;letter-spacing:.08em;color:var(--wine)}.subtitle{font-size:12px;color:var(--muted);margin-top:2px}
main{max-width:1440px;margin:auto;padding:18px;display:grid;grid-template-columns:320px 1fr;gap:18px}
.panel{background:#fff;border:1px solid var(--line);border-radius:18px;overflow:hidden;box-shadow:0 6px 22px #4d123008}
.panel-head{padding:18px;border-bottom:1px solid var(--line)}h2{font-size:17px;margin:0 0 4px}.muted{color:var(--muted);font-size:12px}
#members{padding:10px}.member{padding:13px;border:1px solid var(--line);border-radius:12px;margin-bottom:9px;cursor:pointer}.member:hover{border-color:#d7a5c0;background:#fffafd}
.avatar{display:inline-flex;width:36px;height:36px;align-items:center;justify-content:center;border-radius:50%;background:#f8e8f0;color:var(--wine);font-weight:800;margin-right:10px}.member-row{display:flex;align-items:center}.member-name{font-weight:700}.status{font-size:11px;color:var(--muted);margin-top:4px}
.map-panel{min-height:560px;display:flex;flex-direction:column}.map-top{padding:16px 18px;display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.family-code{font-size:12px;background:#fff1f7;color:var(--wine);padding:8px 10px;border-radius:9px;font-weight:700}
#map{height:calc(100vh - 190px);min-height:480px;width:100%;background:#f1edf0}
button{border:0;border-radius:10px;padding:10px 14px;background:var(--wine);color:#fff;font-weight:700;cursor:pointer}button.secondary{background:#f8e8f0;color:var(--wine)}
footer{padding:12px 18px;color:var(--muted);font-size:11px;border-top:1px solid var(--line)}
@media(max-width:820px){main{grid-template-columns:1fr;padding:10px;gap:10px}.map-panel{min-height:430px}#map{height:54vh;min-height:360px}header{padding:13px 15px}.panel-head{padding:14px}}

.person-map-icon{background:transparent;border:0}
.person-map-marker{display:flex;flex-direction:column;align-items:center;gap:3px;min-width:54px;transform:translateY(-2px)}
.person-map-initial{width:42px;height:42px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:#8a004f;color:#fff;border:3px solid #fff;box-shadow:0 3px 12px rgba(35,12,25,.32);font-size:18px;font-weight:850;line-height:1}
.person-map-name{max-width:110px;padding:2px 7px;border-radius:7px;background:#fff;color:#28232a;border:1px solid #eadde5;box-shadow:0 2px 7px rgba(35,12,25,.16);font-size:11px;font-weight:750;line-height:1.25;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
</style>
</head><body>
<header><div><div class="brand">KINLY</div><div class="subtitle">Family Tracker · Stay connected</div></div><button class="secondary" onclick="copyCode()">Copy family code</button></header>
<main>
<section class="panel"><div class="panel-head"><h2>Everyone</h2><div class="muted">Latest shared locations</div></div><div id="members"><p class="muted">Loading people sharing…</p></div><footer>Only invited people sharing with your family code appear here.</footer></section>
<section class="panel map-panel"><div class="map-top"><div><h2>Live map</h2><div class="muted" id="mapstatus">Waiting for location updates</div></div><div class="family-code" id="familyCode">Everyone sharing</div></div><div id="map"></div><footer>Locations update when a member's device sends a new GPS fix. Background delivery depends on permissions, device settings and connectivity.</footer></section>
</main>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const token=localStorage.getItem('sumo_token')||'';

const api=(path,opts={})=>fetch(path,{...opts,headers:{'Content-Type':'application/json',...(opts.headers||{})}});
const map=L.map('map').setView([20.0,0.0],2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:19,attribution:'&copy; OpenStreetMap'}).addTo(map);
const markers={};
function escapeHtml(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function ago(t){if(!t)return 'No location received yet';const d=Math.max(0,Math.floor((Date.now()-new Date(t).getTime())/1000));if(d<60)return `Updated ${d}s ago`;if(d<3600)return `Updated ${Math.floor(d/60)}m ago`;return `Updated ${Math.floor(d/3600)}h ago`;}
async function refresh(){
try{const r=await api('/api/people');const data=await r.json();if(!data.ok)throw new Error(data.error||'Could not load locations');
const members=data.members||[];document.getElementById('members').innerHTML=members.map(m=>`<div class="member" onclick="focusMember(${m.id})"><div class="member-row"><span class="avatar">${escapeHtml((m.name||'?').slice(0,1).toUpperCase())}</span><div><div class="member-name">${escapeHtml(m.name)}${m.id===Number(localStorage.getItem('kinly_user_id'))?' (You)':''}</div><div class="status">${m.has_location?ago(m.recorded_at):'Waiting for first location'}</div></div></div></div>`).join('')||'<p class="muted">No people sharing yet.</p>';
let valid=[];for(const m of members){if(m.has_location){valid.push([m.latitude,m.longitude]);const popup=`<b>${escapeHtml(m.name)}</b><br>${escapeHtml(ago(m.recorded_at))}`;
const initial=escapeHtml((m.name||'?').trim().charAt(0).toUpperCase()||'?');
const icon=L.divIcon({className:'person-map-icon',html:`<div class="person-map-marker"><div class="person-map-initial">${initial}</div><div class="person-map-name">${escapeHtml(m.name||'Unknown')}</div></div>`,iconSize:[110,66],iconAnchor:[55,42],popupAnchor:[0,-42]});
if(markers[m.id]){markers[m.id].setLatLng([m.latitude,m.longitude]).setIcon(icon).setPopupContent(popup);}else{markers[m.id]=L.marker([m.latitude,m.longitude],{icon}).addTo(map).bindPopup(popup);}}
else if(markers[m.id]){map.removeLayer(markers[m.id]);delete markers[m.id];}}
if(valid.length){if(!window.didFit){map.fitBounds(valid,{padding:[30,30],maxZoom:15});window.didFit=true;}document.getElementById('mapstatus').textContent=`${valid.length} member(s) sharing a location`;}else{document.getElementById('mapstatus').textContent='No GPS updates received yet';}
}catch(e){document.getElementById('mapstatus').textContent='Could not refresh locations';console.error(e);}}
function focusMember(id){if(markers[id]){map.setView(markers[id].getLatLng(),16);markers[id].openPopup();}}

refresh();setInterval(refresh,3000);
</script></body></html>
"""

@app.get("/")
def dashboard():
    return DASHBOARD

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
