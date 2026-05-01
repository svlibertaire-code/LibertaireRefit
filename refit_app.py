#!/usr/bin/env python3
"""Libertaire Refit Manager — PostgreSQL-backed mobile web app"""

import os
import secrets
import bcrypt
import logging
import json
from datetime import datetime
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify, g
from functools import wraps

import psycopg2
from psycopg2.extras import RealDictCursor
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Audit logging ──
audit_log = logging.getLogger('refit.audit')
audit_log.setLevel(logging.INFO)
_fh = logging.FileHandler(os.path.join(BASE_DIR, 'audit.log'))
_fh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
audit_log.addHandler(_fh)
DATABASE_URL = os.environ.get(
    'DATABASE_URL',
    'postgresql://refit:refit@localhost:5432/refit'
)

# ── Config ──
PORT = int(os.environ.get('PORT', 8080))
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
# Password hash (bcrypt) — set via env var or use default
PASSWORD_HASH = os.environ.get(
    'PASSWORD_HASH',
    '$2b$12$8oIYt3KP3hv1Upkq0M0Esu7.6bO9b22hZnLhCuIeEckxYXLi.XPFm'
)
# HTTPS config
CERT_PATH = os.environ.get('CERT_PATH', os.path.join(BASE_DIR, 'certs', 'cert.pem'))
KEY_PATH = os.environ.get('KEY_PATH', os.path.join(BASE_DIR, 'certs', 'key.pem'))
USE_HTTPS = os.environ.get('USE_HTTPS', 'true').lower() == 'true'

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ── Session cookie security ──
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=USE_HTTPS,  # Only set Secure flag when HTTPS is active
    PERMANENT_SESSION_LIFETIME=3600,  # 1 hour
)

# ── Rate limiting ──
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "60 per hour"],
    storage_uri="memory://",
    key_prefix="refit",
)

# ── Security headers ──
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self';"
    )
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ── Cache-Control for sensitive pages ──
@app.after_request
def add_cache_control(response):
    """Prevent caching of authenticated pages."""
    if request.path.startswith('/task/') or request.path.startswith('/item/') or request.path.startswith('/compartment/') or request.path == '/':
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

# ── DB helpers ──
class PostgresDB:
    """Wrapper to make psycopg2 connection act like sqlite3 connection."""
    def __init__(self, connection):
        self._conn = connection

    def execute(self, sql, params=None):
        cur = self._conn.cursor()
        cur.execute(sql, params or ())
        return cur

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        db = g._database = PostgresDB(conn)
    return db

@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query(sql, args=(), one=False):
    try:
        cur = get_db().execute(sql, args)
        rv = cur.fetchall()
        cur.close()
        return (rv[0] if rv else None) if one else rv
    except psycopg2.Error as e:
        app.logger.exception("Query failed: %s", e)
        raise

def execute(sql, args=()):
    db = get_db()
    try:
        cur = db.execute(sql, args)
        db.commit()
        # For INSERT with RETURNING id, get the returned value
        try:
            row = cur.fetchone()
            cur.close()
            return row['id'] if row else None
        except psycopg2.ProgrammingError:
            cur.close()
            return None
    except psycopg2.Error as e:
        app.logger.exception("Execute failed: %s", e)
        try:
            db._conn.rollback()
        except Exception:
            pass
        raise

# ── CSRF protection ──
@app.before_request
def check_csrf():
    """Reject cross-origin POST/PUT/DELETE to API endpoints.
    Browsers block custom headers (X-Requested-With) cross-origin,
    so requiring it prevents CSRF on JSON endpoints.
    Form POSTs to /login, /logout, /task/new, /task/<id>, /item/<id>
    are same-origin only (SameSite=Lax cookie) so they're safe."""
    if request.method in ('POST', 'PUT', 'DELETE') and request.path.startswith('/api/'):
        if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
            return jsonify(ok=False, error='CSRF check failed'), 403

# ── Error handlers ──
@app.errorhandler(404)
def not_found(e):
    return render_template_string(BASE_TEMPLATE, page='error',
        content='<div style="text-align:center;padding:40px 20px;"><div style="font-size:48px;margin-bottom:16px;">🔍</div><div style="font-size:18px;font-weight:700;">Page not found</div></div>'), 404

@app.errorhandler(500)
def server_error(e):
    app.logger.exception("Server error: %s", e)
    return render_template_string(BASE_TEMPLATE, page='error',
        content='<div style="text-align:center;padding:40px 20px;"><div style="font-size:48px;margin-bottom:16px;">⚠️</div><div style="font-size:18px;font-weight:700;">Something went wrong</div></div>'), 500

@app.errorhandler(403)
def forbidden(e):
    return render_template_string(BASE_TEMPLATE, page='error',
        content='<div style="text-align:center;padding:40px 20px;"><div style="font-size:48px;margin-bottom:16px;">🚫</div><div style="font-size:18px;font-weight:700;">Access denied</div></div>'), 403

@app.errorhandler(429)
def rate_limited(e):
    return render_template_string(BASE_TEMPLATE, page='error',
        content='<div style="text-align:center;padding:40px 20px;"><div style="font-size:48px;margin-bottom:16px;">⏳</div><div style="font-size:18px;font-weight:700;">Too many requests</div><div style="color:var(--text2);margin-top:8px;">Please slow down and try again.</div></div>'), 429

# ── Auth ──
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ── Templates ──
BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
<meta name="theme-color" content="#0d1117">
<link rel="icon" type="image/svg+xml" href="/static/icon.svg">
<link rel="apple-touch-icon" href="/static/icon.svg">
<title>Libertaire Refit</title>
<script>
(function(){
  var origFetch=window.fetch;
  window.fetch=function(url,opts){
    opts=opts||{};
    if(opts.method&&opts.method!=='GET'){
      opts.headers=opts.headers||{};
      if(typeof opts.headers==='object'&&!opts.headers['X-Requested-With']){
        opts.headers['X-Requested-With']='XMLHttpRequest';
      }
    }
    return origFetch.call(this,url,opts);
  };
})();
</script>
<script>
(function(){
  var saved = localStorage.getItem('theme');
  var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  var theme = saved || (prefersDark ? 'dark' : 'light');
  if(theme === 'light') document.documentElement.setAttribute('data-theme','light');
})();
</script>
<style>
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --surface2: #21262d;
  --surface1: #1c2128;
  --border: #30363d;
  --text: #e6edf3;
  --text1: #c9d1d9;
  --text2: #8b949e;
  --accent: #58a6ff;
  --blue: #58a6ff;
  --green: #3fb950;
  --orange: #d29922;
  --red: #f85149;
  --purple: #bc8cff;
}
html[data-theme="light"] {
  --bg: #f6f8fa;
  --surface: #ffffff;
  --surface2: #f3f4f6;
  --surface1: #eaecef;
  --border: #d0d7de;
  --text: #24292f;
  --text1: #57606a;
  --text2: #6e7781;
  --accent: #0969da;
  --blue: #0969da;
  --green: #1a7f37;
  --orange: #9a6700;
  --red: #cf222e;
  --purple: #8250df;
}
* { margin:0; padding:0; box-sizing:border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: var(--bg); color: var(--text);
  font-size: 15px; line-height: 1.5;
  -webkit-text-size-adjust: 100%;
}
a { color: var(--blue); text-decoration: none; }
nav {
  background: var(--surface); border-bottom: 1px solid var(--border);
  padding: 10px 12px; display: flex; gap: 12px; align-items: center;
  position: sticky; top: 0; z-index: 10; overflow-x: auto;
}
nav a { color: var(--text2); font-weight: 600; font-size: 13px; padding: 6px 0; white-space: nowrap; }
nav a.active { color: var(--blue); border-bottom: 2px solid var(--blue); }
nav .brand { color: var(--text); font-size: 16px; margin-right: auto; font-weight: 700; }
.container { padding: 12px 16px; max-width: 900px; margin: 0 auto; }

/* Stats */
.stats { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
.stat {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; padding: 8px 10px; flex: 1; min-width: 70px; text-align: center;
}
.stat .num { font-size: 22px; font-weight: 700; }
.stat .label { font-size: 10px; color: var(--text2); text-transform: uppercase; }

/* Cards */
.card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; margin-bottom: 8px; padding: 12px 14px;
}
.card-title { font-weight: 600; margin-bottom: 4px; font-size: 14px; }
.card-meta { font-size: 12px; color: var(--text2); }

/* Badges */
.badge {
  display: inline-block; padding: 4px 10px; border-radius: 10px;
  font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px;
  min-height: 28px;
}
.badge-done { background: #1a3a2a; color: var(--green); }
.badge-progress { background: #2a2a1a; color: var(--orange); }
.badge-ready { background: #1a2a3a; color: var(--blue); }
.badge-toplan { background: var(--surface2); color: var(--text2); }
.badge-critical { background: #3a1a1a; color: var(--red); }
.badge-high { background: #2a2a1a; color: var(--orange); }
.badge-medium { background: #1a2a3a; color: var(--blue); }
.badge-low { background: var(--surface2); color: var(--text2); }
.badge-bought { background: #1a3a2a; color: var(--green); }
.badge-tobuy { background: #3a1a1a; color: var(--red); }
.badge-ordered { background: #2a2a1a; color: var(--orange); }
html[data-theme="light"] .badge-done { background: #dafbe1; color: #116329; }
html[data-theme="light"] .badge-progress { background: #fff8c5; color: #7a5e00; }
html[data-theme="light"] .badge-ready { background: #ddf4ff; color: #0550ae; }
html[data-theme="light"] .badge-critical { background: #ffebe9; color: #82071e; }
html[data-theme="light"] .badge-high { background: #fff8c5; color: #7a5e00; }
html[data-theme="light"] .badge-medium { background: #ddf4ff; color: #0550ae; }
html[data-theme="light"] .badge-bought { background: #dafbe1; color: #116329; }
html[data-theme="light"] .badge-tobuy { background: #ffebe9; color: #82071e; }
html[data-theme="light"] .badge-ordered { background: #fff8c5; color: #7a5e00; }

/* Tappable */
.tap { cursor: pointer; user-select: none; -webkit-tap-highlight-color: transparent; }
.tap:active { opacity: 0.6; }

/* Filters */
.filters { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 12px; }
.filter-btn {
  padding: 5px 10px; border-radius: 14px; font-size: 12px; font-weight: 600;
  background: var(--surface2); color: var(--text2); border: 1px solid var(--border);
  cursor: pointer; user-select: none;
}
.filter-btn.active { background: var(--blue); color: #fff; border-color: var(--blue); }

/* Table */
.table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; padding: 6px 8px; color: var(--text2); font-size: 11px;
     text-transform: uppercase; border-bottom: 1px solid var(--border); white-space: nowrap; }
td { padding: 6px 8px; border-bottom: 1px solid var(--border); }

/* Login */
.login-form { max-width: 300px; margin: 60px auto; text-align: center; }
.login-form input {
  width: 100%; padding: 12px; margin: 8px 0; border-radius: 8px;
  border: 1px solid var(--border); background: var(--surface);
  color: var(--text); font-size: 16px;
}
.login-form button {
  width: 100%; padding: 12px; border-radius: 8px; border: none;
  background: var(--blue); color: #fff; font-size: 16px; font-weight: 600; cursor: pointer;
}

/* Section titles */
.section-title { font-size: 12px; color: var(--text2); text-transform: uppercase;
                letter-spacing: 0.5px; margin: 16px 0 8px; font-weight: 600; }
.cost { font-variant-numeric: tabular-nums; }

/* Compartment grid */
.comp-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; }
.comp-card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; padding: 12px; text-align: center;
}
.comp-card .name { font-weight: 600; font-size: 13px; margin-bottom: 4px; }
.comp-card .counts { font-size: 11px; color: var(--text2); }

/* Timeline */
.timeline { position: relative; padding-left: 20px; }
.timeline::before {
  content: ''; position: absolute; left: 6px; top: 0; bottom: 0;
  width: 2px; background: var(--border);
}
.tl-item { position: relative; margin-bottom: 12px; }
.tl-dot {
  position: absolute; left: -18px; top: 2px; width: 12px; height: 12px;
  border-radius: 50%; background: var(--surface2); border: 2px solid var(--border);
}
.tl-dot.done { background: var(--green); border-color: var(--green); }
.tl-dot.active { background: var(--orange); border-color: var(--orange); }
.tl-dot.milestone { background: var(--red); border-color: var(--red); width: 14px; height: 14px; left: -19px; }
.tl-content { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; }
.tl-date { font-size: 11px; color: var(--text2); }

/* Progress bar */
.progress-bar { height: 6px; background: var(--surface2); border-radius: 3px; overflow: hidden; margin-top: 6px; }
.progress-fill { height: 100%; background: var(--green); border-radius: 3px; }

/* Forms */
input, textarea, select {
  width: 100%; padding: 10px; margin: 4px 0 12px;
  border-radius: 6px; border: 1px solid var(--border);
  background: var(--surface); color: var(--text); font-size: 14px;
}
button.submit {
  padding: 10px 16px; border-radius: 6px; border: none;
  background: var(--blue); color: #fff; font-weight: 600; cursor: pointer;
}

/* Toast */
.toast {
  position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
  background: var(--green); color: #fff; padding: 10px 20px; border-radius: 8px;
  font-weight: 600; font-size: 14px; z-index: 100;
  animation: fadeout 2s forwards;
}
@keyframes fadeout { 0%,70% { opacity:1; } 100% { opacity:0; } }

/* Notes / log */
.log-entry {
  border-left: 3px solid var(--blue); padding-left: 10px; margin: 8px 0;
  font-size: 13px;
}
.log-time { font-size: 11px; color: var(--text2); }
</style>
</head>
<body>
<nav>
  <span class="brand">⚓ Libertaire</span>
  <a href="/" class="{{'active' if page=='dashboard'}}">Home</a>
  <a href="/tasks" class="{{'active' if page=='tasks'}}">Tasks</a>
  <a href="/compartments" class="{{'active' if page=='compartments'}}">Spaces</a>
  <a href="/schedule" class="{{'active' if page=='schedule'}}">Plan</a>
  <a href="/inventory" class="{{'active' if page=='inventory'}}">Gear</a>
  <a href="/wiring" class="{{'active' if page=='wiring'}}">Wiring</a>
  <a href="/plumbing" class="{{'active' if page=='plumbing'}}">Plumbing</a>
  <a href="/settings" class="{{'active' if page=='settings'}}" style="margin-left:auto;">⚙</a>
</nav>
<div class="container">
{{ content|safe }}
</div>
</body>
</html>
"""

# ── Jinja filters ──
@app.template_filter('badge_class')
def badge_class(s):
    mapping = {
        'Done': 'done', 'In progress': 'progress', 'Ready': 'ready', 'To plan': 'toplan',
        'Critical': 'critical', 'High': 'high', 'Medium': 'medium', 'Low': 'low',
        'Bought': 'bought', 'To buy': 'tobuy', 'Ordered': 'ordered',
        'Before foam': 'high', 'After foam': 'medium',
    }
    return mapping.get(s, 'toplan')

# ── Routes ──

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        pw = request.form.get('password', '').encode('utf-8')
        if bcrypt.checkpw(pw, PASSWORD_HASH.encode('utf-8')):
            session['logged_in'] = True
            audit_log.info('LOGIN success ip=%s', request.remote_addr)
            return redirect(url_for('dashboard'))
        audit_log.info('LOGIN failed ip=%s', request.remote_addr)
        return render_template_string(BASE_TEMPLATE, page='login',
            content='<div class="login-form"><div style="font-size:40px;margin-bottom:16px;">⚓</div><div style="font-size:20px;font-weight:700;margin-bottom:24px;">Libertaire Refit</div><div style="color:var(--red);margin-bottom:12px;">Wrong password</div><form method="POST"><input type="password" name="password" placeholder="Password" autofocus><button type="submit">Enter</button></form></div>')
    return render_template_string(BASE_TEMPLATE, page='login',
        content='<div class="login-form"><div style="font-size:40px;margin-bottom:16px;">⚓</div><div style="font-size:20px;font-weight:700;margin-bottom:24px;">Libertaire Refit</div><form method="POST"><input type="password" name="password" placeholder="Password" autofocus><button type="submit">Enter</button></form></div>')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

# ── Dashboard ──
@app.route('/')
@login_required
def dashboard():
    counts = query("""
        SELECT status, COUNT(*) as n FROM tasks GROUP BY status
    """)
    c = {r['status']: r['n'] for r in counts}
    
    inv = query("""
        SELECT purchase_status, COUNT(*) as n, SUM(total_cost) as cost
        FROM inventory GROUP BY purchase_status
    """)
    total_to_buy = sum(r['cost'] or 0 for r in inv if r['purchase_status'] == 'To buy')
    bought_count = sum(r['n'] for r in inv if r['purchase_status'] == 'Bought')
    
    # Compartment progress
    comp_progress = query("""
        SELECT c.id, c.name,
               COUNT(t.id) as total,
               SUM(CASE WHEN t.status = 'Done' THEN 1 ELSE 0 END) as done
        FROM compartments c
        LEFT JOIN tasks t ON t.compartment_id = c.id
        GROUP BY c.id
        HAVING COUNT(t.id) > 0
        ORDER BY c.sort_order
    """)
    
    # Overall progress
    total_tasks = sum(c.values())
    overall_pct = int((c.get('Done', 0) / total_tasks) * 100) if total_tasks else 0

    content = """
<div style="text-align:center; padding: 16px 0 12px;">
  <div style="font-size: 26px; font-weight: 700;">LIBERTAIRE</div>
  <div style="color: var(--text2); font-size: 12px;">54' steel · 65,000 nm · Refit → 2027</div>
</div>

<!-- Overall Progress -->
<div class="card" style="margin-bottom:12px;">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
    <span style="font-weight:600;">Overall Progress</span>
    <span style="font-weight:700; color:var(--green);">""" + str(overall_pct) + """%</span>
  </div>
  <div class="progress-bar" style="height:8px;"><div class="progress-fill" style="width:""" + str(overall_pct) + """%"></div></div>
  <div style="font-size:12px; color:var(--text2); margin-top:4px;">""" + str(c.get('Done',0)) + """ of """ + str(total_tasks) + """ tasks complete</div>
</div>

<div class="stats">
  <div class="stat"><div class="num" style="color:var(--green)">""" + str(c.get('Done',0)) + """</div><div class="label">Done</div></div>
  <div class="stat"><div class="num" style="color:var(--orange)">""" + str(c.get('In progress',0)) + """</div><div class="label">Active</div></div>
  <div class="stat"><div class="num" style="color:var(--blue)">""" + str(c.get('Ready',0)) + """</div><div class="label">Ready</div></div>
  <div class="stat"><div class="num" style="color:var(--text2)">""" + str(c.get('To plan',0)) + """</div><div class="label">To Plan</div></div>
</div>

<div class="stats">
  <div class="stat"><div class="num cost" style="color:var(--red)">€""" + str(int(total_to_buy)) + """</div><div class="label">To Buy</div></div>
  <div class="stat"><div class="num cost" style="color:var(--green)">""" + str(bought_count) + """</div><div class="label">Bought</div></div>
</div>

<div class="section-title">Spaces Progress</div>
<div class="comp-grid">
"""
    for cp in comp_progress:
        pct = int((cp['done'] / cp['total']) * 100) if cp['total'] else 0
        content += """
  <div class="comp-card tap" onclick="location.href='/compartment/""" + str(cp['id']) + """'">
    <div class="name">""" + cp['name'] + """</div>
    <div class="progress-bar"><div class="progress-fill" style="width:""" + str(pct) + """%"></div></div>
    <div class="counts">""" + str(cp['done']) + """/""" + str(cp['total']) + """ done</div>
  </div>
"""
    content += """
</div>

"""
    return render_template_string(BASE_TEMPLATE, page='dashboard', content=content)

# ── Tasks ──
@app.route('/tasks')
@login_required
def tasks_page():
    status_filter = request.args.get('status', 'all')
    phase_filter = request.args.get('phase', 'all')
    comp_filter = request.args.get('comp', 'all')
    
    sql = """
        SELECT t.*, c.name as compartment, s.name as system, s.color as system_color, i.item as gear
        FROM tasks t
        LEFT JOIN compartments c ON t.compartment_id = c.id
        LEFT JOIN systems s ON t.system_id = s.id
        LEFT JOIN inventory i ON t.inventory_id = i.id
        WHERE 1=1
    """
    args = []
    if status_filter != 'all':
        sql += " AND t.status = %s"
        args.append(status_filter)
    if phase_filter != 'all':
        sql += " AND t.phase = %s"
        args.append(phase_filter)
    if comp_filter != 'all':
        sql += " AND c.name = %s"
        args.append(comp_filter)
    sql += " ORDER BY CASE t.priority WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END, t.id"
    
    tasks = query(sql, args)
    
    counts = query("SELECT status, COUNT(*) as n FROM tasks GROUP BY status")
    c = {r['status']: r['n'] for r in counts}
    
    comps = query("SELECT name FROM compartments ORDER BY sort_order")
    
    # Searchable task list
    content = """
<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
  <div style="font-size:18px; font-weight:700;">Tasks</div>
  <a href="/task/new" class="submit" style="padding:8px 14px; font-size:13px; text-decoration:none;">+ New Task</a>
</div>

<div style="margin-bottom:12px;">
  <input type="text" id="task-search" placeholder="Search tasks..." style="margin:0;" oninput="filterTasks()">
</div>

<div class="filters" id="status-filters">
  <span class="filter-btn """ + ('active' if status_filter=='all' else '') + """" onclick="setFilter('status','all')">All (""" + str(sum(c.values())) + """)</span>
  <span class="filter-btn """ + ('active' if status_filter=='In progress' else '') + """" onclick="setFilter('status','In progress')">Active (""" + str(c.get('In progress',0)) + """)</span>
  <span class="filter-btn """ + ('active' if status_filter=='Ready' else '') + """" onclick="setFilter('status','Ready')">Ready (""" + str(c.get('Ready',0)) + """)</span>
  <span class="filter-btn """ + ('active' if status_filter=='To plan' else '') + """" onclick="setFilter('status','To plan')">To Plan (""" + str(c.get('To plan',0)) + """)</span>
  <span class="filter-btn """ + ('active' if status_filter=='Done' else '') + """" onclick="setFilter('status','Done')">Done (""" + str(c.get('Done',0)) + """)</span>
</div>

<div class="filters" id="phase-filters">
  <span class="filter-btn """ + ('active' if phase_filter=='all' else '') + """" onclick="setFilter('phase','all')">All phases</span>
  <span class="filter-btn """ + ('active' if phase_filter=='Before foam' else '') + """" onclick="setFilter('phase','Before foam')">Before Foam</span>
  <span class="filter-btn """ + ('active' if phase_filter=='After foam' else '') + """" onclick="setFilter('phase','After foam')">After Foam</span>
</div>

<div class="filters">
  <span class="filter-btn """ + ('active' if comp_filter=='all' else '') + """" onclick="setFilter('comp','all')">All spaces</span>
"""
    for comp in comps:
        content += """  <span class="filter-btn """ + ('active' if comp_filter==comp['name'] else '') + """" onclick="setFilter('comp','""" + comp['name'] + """')">""" + comp['name'] + """</span>\n"""
    content += "</div>\n"
    
    for t in tasks:
        phase_badge = ""
        if t['phase']:
            phase_badge = '<span class="badge" style="background:var(--surface2);color:var(--text2);">' + t['phase'] + '</span>'
        content += """
<div class="card task-card" style="position:relative; padding-bottom:28px;">
  <div style="display:flex; justify-content:space-between; align-items:start; gap:8px;">
    <div style="flex:1;">
      <div class="card-title">""" + t['name'] + """</div>
      <div class="card-meta">""" + (t['compartment'] or '—') + """ · <span style="color:""" + (t['system_color'] or 'var(--text2)') + """">""" + (t['system'] or '—') + """</span>""" + (' · <span style="color:var(--accent);">⚙ ' + t['gear'] + '</span>' if t.get('gear') else '') + """</div>
    </div>
    <span class="badge badge-""" + badge_class(t['status']) + """ tap" data-task-id=\"""" + str(t['id']) + """" data-status=\"""" + t['status'] + """">""" + t['status'] + """</span>
  </div>
  <div style="margin-top:6px; display:flex; gap:6px; flex-wrap:wrap; align-items:center;">
    """ + ('<span class="badge badge-' + badge_class(t['priority']) + '" style="display:none;">' + t['priority'] + '</span>' if t['status'] == 'Done' else '<span class="badge badge-' + badge_class(t['priority']) + '">' + t['priority'] + '</span>') + """
    """ + phase_badge + """
    """ + ('<span style="font-size:12px; color:var(--text2);">📅 ' + (t['planned_start'] or '?') + ' → ' + (t['planned_end'] or '?') + '</span>' if t['planned_start'] or t['planned_end'] else '') + """
    <span style="font-size:11px; color:var(--text2);" class="rel-time" data-ts=""" + str(t['updated_at'].timestamp() if t['updated_at'] else 0) + """></span>
  </div>
  <a href="/task/""" + str(t['id']) + """" style="position:absolute; bottom:10px; right:14px; font-size:12px;">Details →</a>
</div>
"""
    
    content += """
<script>
function setFilter(key, val) {
  var url = new URL(location.href);
  url.searchParams.set(key, val);
  location.href = url.toString();
}
var statusOrder = ['To plan', 'Ready', 'In progress', 'Done'];
document.addEventListener('click', function(e) {
  var el = e.target.closest('.tap[data-task-id]');
  if (!el) return;
  e.preventDefault();
  e.stopPropagation();
  var id = el.dataset.taskId;
  var cur = el.dataset.status;
  var next = statusOrder[(statusOrder.indexOf(cur) + 1) % statusOrder.length];
  el.style.opacity = '0.5';
  fetch('/api/task/' + id, {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({status: next})
  }).then(function(r) { if(r.ok) location.reload(); });
});
function filterTasks() {
  var q = document.getElementById('task-search').value.toLowerCase();
  var cards = document.querySelectorAll('.task-card');
  for (var i = 0; i < cards.length; i++) {
    var text = cards[i].textContent.toLowerCase();
    cards[i].style.display = text.indexOf(q) !== -1 ? '' : 'none';
  }
}
function updateRelTimes() {
  var els = document.querySelectorAll('.rel-time');
  for (var i = 0; i < els.length; i++) {
    var ts = parseFloat(els[i].dataset.ts);
    if (!ts) continue;
    var sec = Math.floor((Date.now()/1000) - ts);
    var txt;
    if (sec < 60) txt = 'just now';
    else if (sec < 3600) txt = Math.floor(sec/60) + 'm ago';
    else if (sec < 86400) txt = Math.floor(sec/3600) + 'h ago';
    else txt = Math.floor(sec/86400) + 'd ago';
    els[i].textContent = txt;
  }
}
setInterval(updateRelTimes, 60000);
updateRelTimes();
</script>
"""
    return render_template_string(BASE_TEMPLATE, page='tasks', content=content)

# ── New task ──
@app.route('/task/new', methods=['GET', 'POST'])
@login_required
def new_task():
    compartments = query("SELECT id, name FROM compartments ORDER BY sort_order")
    systems = query("SELECT id, name FROM systems ORDER BY name")
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        compartment_id = request.form.get('compartment_id', type=int)
        system_id = request.form.get('system_id', type=int)
        status = request.form.get('status', 'To plan')
        phase = request.form.get('phase', '')
        priority = request.form.get('priority', 'Medium')
        notes = request.form.get('notes', '').strip()
        inventory_id = request.form.get('inventory_id', type=int)
        
        planned_start = request.form.get('planned_start', '').strip() or None
        planned_end = request.form.get('planned_end', '').strip() or None
        
        if name:
            task_id = execute("""
                INSERT INTO tasks (name, compartment_id, system_id, status, phase, priority, notes, planned_start, planned_end, inventory_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (name, compartment_id, system_id, status, phase, priority, notes, planned_start, planned_end, inventory_id))
            return redirect('/task/' + str(task_id))
    
    comp_options = ""
    for comp in compartments:
        comp_options += f'<option value="{comp["id"]}">{comp["name"]}</option>'
    
    sys_options = ""
    for sys in systems:
        sys_options += f'<option value="{sys["id"]}">{sys["name"]}</option>'
    
    status_options = ""
    for st in ['To plan', 'Ready', 'In progress', 'Done']:
        status_options += f'<option value="{st}">{st}</option>'
    
    phase_options = '<option value="">—</option>'
    for ph in ['Before foam', 'After foam']:
        phase_options += f'<option value="{ph}">{ph}</option>'
    
    priority_options = ""
    for pr in ['Critical', 'High', 'Medium', 'Low']:
        selected = ' selected' if pr == 'Medium' else ''
        priority_options += f'<option value="{pr}"{selected}>{pr}</option>'
    
    new_inv = query("SELECT id, item FROM inventory ORDER BY item")
    new_inv_options = '<option value="">—</option>'
    for inv in new_inv:
        new_inv_options += f'<option value="{inv["id"]}">{inv["item"]}</option>'
    
    content = f"""
<div style="margin-bottom:12px;">
  <a href="/tasks" style="font-size:13px;">← Back to tasks</a>
</div>

<form method="POST" id="task-form">
<div class="card">
  <div style="font-size:18px; font-weight:700; margin-bottom:12px;">New Task</div>
  
  <label style="font-size:12px; color:var(--text2);">Name</label>
  <input type="text" name="name" placeholder="What needs to be done?" required autofocus>
  
  <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
    <div>
      <label style="font-size:12px; color:var(--text2);">Space</label>
      <select name="compartment_id">{comp_options}</select>
    </div>
    <div>
      <label style="font-size:12px; color:var(--text2);">System</label>
      <select name="system_id">{sys_options}</select>
    </div>
  </div>
  
  <label style="font-size:12px; color:var(--text2);">Related Gear</label>
  <select name="inventory_id">{new_inv_options}</select>
  
  <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:8px;">
    <div>
      <label style="font-size:12px; color:var(--text2);">Status</label>
      <select name="status">{status_options}</select>
    </div>
    <div>
      <label style="font-size:12px; color:var(--text2);">Phase</label>
      <select name="phase">{phase_options}</select>
    </div>
    <div>
      <label style="font-size:12px; color:var(--text2);">Priority</label>
      <select name="priority">{priority_options}</select>
    </div>
  </div>
  
  <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
    <div>
      <label style="font-size:12px; color:var(--text2);">Planned Start</label>
      <input type="date" name="planned_start">
    </div>
    <div>
      <label style="font-size:12px; color:var(--text2);">Planned End</label>
      <input type="date" name="planned_end">
    </div>
  </div>

  <label style="font-size:12px; color:var(--text2);">Notes</label>
  <textarea name="notes" rows="3" placeholder="Technical details, decisions, blockers..."></textarea>

  <div style="display:flex; gap:8px;">
    <button type="submit" class="submit" style="flex:1;">Create Task</button>
    <button type="button" class="submit" style="background:var(--surface2); color:var(--text);" onclick="location.href='/tasks'">Cancel</button>
  </div>
</div>
</form>
"""
    return render_template_string(BASE_TEMPLATE, page='tasks', content=content)

# ── Task detail + edit ──
@app.route('/task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def task_detail(task_id):
    task = query("""
        SELECT t.*, c.name as compartment, s.name as system
        FROM tasks t
        LEFT JOIN compartments c ON t.compartment_id = c.id
        LEFT JOIN systems s ON t.system_id = s.id
        WHERE t.id = %s
    """, [task_id], one=True)
    
    if not task:
        return redirect(url_for('tasks_page'))
    
    # Load dropdown data
    compartments = query("SELECT id, name FROM compartments ORDER BY sort_order")
    systems = query("SELECT id, name FROM systems ORDER BY name")
    
    if request.method == 'POST':
        # Update task fields
        new_name = request.form.get('name', '').strip()
        new_compartment_id = request.form.get('compartment_id', type=int)
        new_system_id = request.form.get('system_id', type=int)
        new_status = request.form.get('status', '')
        new_phase = request.form.get('phase', '')
        new_priority = request.form.get('priority', '')
        new_notes = request.form.get('notes', '').strip()
        new_planned_start = request.form.get('planned_start', '').strip() or None
        new_planned_end = request.form.get('planned_end', '').strip() or None
        new_inventory_id = request.form.get('inventory_id', type=int)
        
        if new_name:
            execute("""
                UPDATE tasks SET
                    name = %s,
                    compartment_id = %s,
                    system_id = %s,
                    status = %s,
                    phase = %s,
                    priority = %s,
                    notes = %s,
                    planned_start = %s,
                    planned_end = %s,
                    inventory_id = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (new_name, new_compartment_id, new_system_id, new_status, new_phase, new_priority, new_notes, new_planned_start, new_planned_end, new_inventory_id, task_id))
        
        # Add log entry if provided
        entry = request.form.get('log_entry', '').strip()
        if entry:
            execute("INSERT INTO logs (task_id, entry) VALUES (%s,%s)", (task_id, entry))
        
        return redirect('/task/' + str(task_id) + '?saved=1')
    
    logs = query("SELECT * FROM logs WHERE task_id = %s ORDER BY created_at DESC", [task_id])
    
    # Related inventory (same compartment + system)
    related_inv = query("""
        SELECT * FROM inventory
        WHERE compartment_id = %s AND system_id = %s
        ORDER BY purchase_status
    """, [task['compartment_id'], task['system_id']])
    
    # Build dropdown options
    comp_options = ""
    for comp in compartments:
        selected = ' selected' if comp['id'] == task['compartment_id'] else ''
        comp_options += f'<option value="{comp["id"]}"{selected}>{comp["name"]}</option>'
    
    sys_options = ""
    for sys in systems:
        selected = ' selected' if sys['id'] == task['system_id'] else ''
        sys_options += f'<option value="{sys["id"]}"{selected}>{sys["name"]}</option>'
    
    status_options = ""
    for st in ['To plan', 'Ready', 'In progress', 'Done']:
        selected = ' selected' if st == task['status'] else ''
        status_options += f'<option value="{st}"{selected}>{st}</option>'
    
    phase_options = '<option value="">—</option>'
    for ph in ['Before foam', 'After foam']:
        selected = ' selected' if ph == task['phase'] else ''
        phase_options += f'<option value="{ph}"{selected}>{ph}</option>'
    
    priority_options = ""
    for pr in ['Critical', 'High', 'Medium', 'Low']:
        selected = ' selected' if pr == task['priority'] else ''
        priority_options += f'<option value="{pr}"{selected}>{pr}</option>'
    
    content = f"""
<div style="margin-bottom:12px;">
  <a href="/tasks" style="font-size:13px;">← Back to tasks</a>
</div>

{'<div id="save-banner" style="background:var(--green);color:#111;padding:10px 14px;border-radius:8px;margin-bottom:12px;font-size:13px;font-weight:600;text-align:center;">✓ Changes saved</div>' if request.args.get('saved') else ''}

<form method="POST" id="task-form">
<div class="card">
  <div style="font-size:18px; font-weight:700; margin-bottom:12px;">Edit Task</div>
  
  <label style="font-size:12px; color:var(--text2);">Name</label>
  <input type="text" name="name" value="{task['name']}" required>
  
  <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
    <div>
      <label style="font-size:12px; color:var(--text2);">Space</label>
      <select name="compartment_id">{comp_options}</select>
    </div>
    <div>
      <label style="font-size:12px; color:var(--text2);">System</label>
      <select name="system_id">{sys_options}</select>
    </div>
  </div>
  
  <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:8px;">
    <div>
      <label style="font-size:12px; color:var(--text2);">Status</label>
      <select name="status">{status_options}</select>
    </div>
    <div>
      <label style="font-size:12px; color:var(--text2);">Phase</label>
      <select name="phase">{phase_options}</select>
    </div>
    {'<div><label style="font-size:12px; color:var(--text2);">Priority</label><select name="priority">{priority_options}</select></div>' if task['status'] != 'Done' else f'<div><label style="font-size:12px; color:var(--text2);">Priority</label><select name="priority" disabled><option>{task["priority"]}</option></select></div>'}
  </div>
  
  <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
    <div>
      <label style="font-size:12px; color:var(--text2);">Planned Start</label>
      <input type="date" name="planned_start" value="{task['planned_start'] or ''}">
    </div>
    <div>
      <label style="font-size:12px; color:var(--text2);">Planned End</label>
      <input type="date" name="planned_end" value="{task['planned_end'] or ''}">
    </div>
  </div>
  
  <label style="font-size:12px; color:var(--text2);">Notes</label>
  <textarea name="notes" rows="3" placeholder="Technical details, decisions, blockers...">{task['notes'] or ''}</textarea>
  
  <div style="display:flex; gap:8px;">
    <button type="submit" class="submit" style="flex:1;">Save Changes</button>
    <button type="button" class="submit" style="background:var(--red); color:#fff;" onclick="showDeleteModal()">Delete</button>
    <button type="button" class="submit" style="background:var(--surface2); color:var(--text);" onclick="history.back()">Cancel</button>
  </div>
</div>

<!-- Delete Confirmation Modal -->
<div id="delete-modal" style="display:none; position:fixed; top:0; left:0; right:0; bottom:0; background:rgba(0,0,0,0.8); z-index:100; align-items:center; justify-content:center;">
  <div style="background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:20px; max-width:300px; width:90%; text-align:center;">
    <div style="font-size:18px; font-weight:700; margin-bottom:8px; color:var(--red);">Delete Task?</div>
    <div style="color:var(--text2); font-size:13px; margin-bottom:16px;">This cannot be undone.</div>
    <div style="display:flex; gap:8px;">
      <button onclick="confirmDelete()" style="flex:1; padding:10px; border-radius:6px; border:none; background:var(--red); color:#fff; font-weight:600; cursor:pointer;">Delete</button>
      <button onclick="hideDeleteModal()" style="flex:1; padding:10px; border-radius:6px; border:none; background:var(--surface2); color:var(--text); font-weight:600; cursor:pointer;">Cancel</button>
    </div>
  </div>
</div>

<script>
var task_id = """ + str(task_id) + """;
function showDeleteModal() { document.getElementById('delete-modal').style.display = 'flex'; }
function hideDeleteModal() { document.getElementById('delete-modal').style.display = 'none'; }
function confirmDelete() {
  fetch("/api/task/" + task_id + "/delete", {"method": "POST"})
    .then(function(r) { if(r.ok) location.href = "/tasks"; });
}
function deleteLog(id){
  if(!confirm('Delete this log entry?'))return;
  fetch('/api/log/'+id+'/delete',{method:'POST'})
    .then(function(r){if(r.ok)document.getElementById('log-'+id).remove();});
}
function uploadPhoto(id,input){
  if(!input.files[0])return;
  var fd=new FormData();fd.append('photo',input.files[0]);
  fetch('/api/log/'+id+'/photo',{method:'POST',body:fd})
    .then(function(r){ if(!r.ok) throw new Error('HTTP '+r.status); return r.json(); })
    .then(function(d){
      if(d.ok) location.reload();
      else alert('Upload failed: '+(d.error||'unknown'));
    }).catch(function(e){alert('Upload error: '+e.message);});
}
</script>

<div class="section-title">Activity Log</div>
"""
    for log in logs:
        photo_html = ''
        if log.get('photo_url'):
            photo_html = f'<img src="{log["photo_url"]}" style="max-width:100%;border-radius:8px;margin-top:6px;" onclick="window.open(this.src)">'
        content += f"""
<div class="log-entry" id="log-{log['id']}">
  <div style="display:flex;justify-content:space-between;align-items:start;">
    <div style="flex:1;">{log['entry']}</div>
    <div style="display:flex;gap:4px;align-items:center;">
      <label style="cursor:pointer;font-size:14px;" title="Add photo">
        📷<input type="file" accept="image/*" style="display:none;" form="" onchange="uploadPhoto({log['id']},this)">
      </label>
      <span style="cursor:pointer;font-size:14px;" title="Delete" onclick="deleteLog({log['id']})">🗑️</span>
    </div>
  </div>
  <div class="log-time">{log['created_at']}</div>
  {photo_html}
</div>
"""
    
    content += """
<div style="margin-top:12px;">
  <textarea name="log_entry" rows="2" placeholder="Add note: what you did, problem found, item ordered..."></textarea>
  <button type="submit" class="submit">Add Log Entry</button>
</div>
</form>
"""
    # Gear picker
    inventory = query("SELECT id, item FROM inventory ORDER BY item")
    current_inv = task.get('inventory_id')
    inv_opts = '<option value="">— none —</option>'
    for inv in inventory:
        sel = ' selected' if inv['id'] == current_inv else ''
        inv_opts += f'<option value="{inv["id"]}"{sel}>{inv["item"]}</option>'
    
    current_gear_name = ''
    if current_inv:
        gi = [i for i in inventory if i['id'] == current_inv]
        if gi:
            current_gear_name = gi[0]['item']
    
    content += f"""
<div class="section-title">Linked Gear</div>
<div class="card">
  <select id="task-gear" onchange="setTaskGear(this.value)" style="margin:0;">{inv_opts}</select>
  <span id="gear-saved" style="font-size:12px;color:var(--green);margin-left:8px;"></span>
</div>
<script>
function setTaskGear(val){{
  fetch('/api/task/{task_id}',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{inventory_id:val||null}})}})
  .then(function(r){{
    var el=document.getElementById('gear-saved');
    if(r.ok){{el.textContent='✓ Saved';setTimeout(function(){{el.textContent='';}},1500);}}
    else el.textContent='Error';
  }});
}}
</script>
"""
    
    if related_inv:
        content += '<div class="section-title">Related Gear (same space & system)</div>\n'
        for item in related_inv:
            cost_line = ""
            if item['total_cost']:
                cost_line = '<div class="cost" style="color:var(--red);">€' + str(item['total_cost']) + '</div>'
            url_line = ""
            if item['url']:
                url_line = '<div><a href="' + item['url'] + '" target="_blank" style="font-size:12px;">🔗 Link</a></div>'
            content += """
<div class="card">
  <div style="display:flex; justify-content:space-between;">
    <div class="card-title">""" + item['item'] + """</div>
    <span class="badge badge-""" + badge_class(item['purchase_status']) + """ tap" data-id=\"""" + str(item['id']) + """" data-status=\"""" + item['purchase_status'] + """">""" + item['purchase_status'] + """</span>
  </div>
  """ + cost_line + url_line + """
</div>
"""
    content += """
<script>
var purchaseOrder=['To buy','Ordered','Bought'];
document.addEventListener('click',function(e){var el=e.target.closest('.tap[data-id]');if(!el)return;e.preventDefault();e.stopPropagation();var id=el.dataset.id;var cur=el.dataset.status;var next=purchaseOrder[(purchaseOrder.indexOf(cur)+1)%purchaseOrder.length];el.style.opacity='0.5';fetch('/api/inventory/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:next})}).then(function(r){if(r.ok){el.textContent=next;el.dataset.status=next;el.className='badge badge-'+next.toLowerCase().replace(' ','')+' tap';el.style.opacity='1';}else{el.style.opacity='1';alert('Error');}}).catch(function(){el.style.opacity='1';alert('Network error');});});
</script>
"""
    return render_template_string(BASE_TEMPLATE, page='tasks', content=content)

# ── Compartments overview ──
@app.route('/compartments')
@login_required
def compartments_page():
    edit = request.args.get('edit', '0') == '1'
    comps = query("""
        SELECT c.*,
               COUNT(t.id) as total_tasks,
               SUM(CASE WHEN t.status = 'Done' THEN 1 ELSE 0 END) as done_tasks,
               SUM(CASE WHEN t.status = 'In progress' THEN 1 ELSE 0 END) as active_tasks,
               COUNT(i.id) as gear_count,
               SUM(CASE WHEN i.purchase_status = 'To buy' THEN i.total_cost ELSE 0 END) as pending_cost,
               (SELECT COUNT(*) FROM cables cb WHERE cb.compartment_id = c.id) as cable_count
        FROM compartments c
        LEFT JOIN tasks t ON t.compartment_id = c.id
        LEFT JOIN inventory i ON i.compartment_id = c.id
        GROUP BY c.id
        ORDER BY c.sort_order
    """)
    
    if edit:
        content = """
<div style="display:flex; justify-content:space-between; align-items:center; padding:12px 0;">
  <div style="font-size:20px; font-weight:700;">Edit Spaces</div>
  <a href="/compartments" class="submit" style="padding:6px 12px; font-size:13px; text-decoration:none;">Done</a>
</div>
<div style="font-size:12px; color:var(--text2); margin-bottom:12px;">Rename, reorder or delete. Changes save on blur.</div>
"""
        for comp in comps:
            refs = []
            if comp['total_tasks']: refs.append(str(comp['total_tasks']) + ' tasks')
            if comp['cable_count']: refs.append(str(comp['cable_count']) + ' cables')
            if comp['gear_count']: refs.append(str(comp['gear_count']) + ' gear')
            ref_text = ', '.join(refs) if refs else 'No references'
            cid = str(comp['id'])
            has_refs = comp['total_tasks'] or comp['cable_count'] or comp['gear_count']
            
            content += """
<div class="card" style="margin-bottom:8px;">
  <div style="display:flex; align-items:center; gap:8px;">
    <input class="comp-name" data-id=\"""" + cid + """\" value=\"""" + comp['name'].replace('"', '&quot;') + """\" style="flex:1; font-size:14px; font-weight:600; padding:6px 8px;">
    <input class="comp-sort" data-id=\"""" + cid + """\" type="number" value=\"""" + str(comp['sort_order'] or 0) + """\" style="width:45px; padding:6px; font-size:13px; text-align:center;" title="Sort order">
  </div>
  <input class="comp-desc" data-id=\"""" + cid + """\" value=\"""" + (comp['description'] or '').replace('"', '&quot;') + """\" placeholder="Description (optional)" style="width:100%; padding:6px 8px; font-size:12px; margin-top:4px; color:var(--text2);">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-top:6px;">
    <span style="font-size:11px; color:var(--text2);">""" + ref_text + """</span>
"""
            if not has_refs:
                content += """
    <button onclick="deleteComp(""" + cid + """)" style="background:var(--red); color:white; border:none; padding:4px 10px; border-radius:6px; font-size:11px; cursor:pointer;">Delete</button>
"""
            content += """
  </div>
</div>
"""
        content += """
<div style="text-align:center; margin-top:16px;">
  <button class="submit" onclick="addComp()" style="padding:8px 16px;">+ Add Space</button>
</div>
<script>
function saveComp(id, fields) {
  fetch('/api/compartment/' + id, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(fields)
  });
}
var compNameEls = document.querySelectorAll('.comp-name');
for(var i=0;i<compNameEls.length;i++){
  compNameEls[i].addEventListener('blur', function(el){return function(){saveComp(el.dataset.id, {name: el.value});};}(compNameEls[i]));
}
var compSortEls = document.querySelectorAll('.comp-sort');
for(var i=0;i<compSortEls.length;i++){
  compSortEls[i].addEventListener('blur', function(el){return function(){saveComp(el.dataset.id, {sort_order: parseInt(el.value) || 0});};}(compSortEls[i]));
}
var compDescEls = document.querySelectorAll('.comp-desc');
for(var i=0;i<compDescEls.length;i++){
  compDescEls[i].addEventListener('blur', function(el){return function(){saveComp(el.dataset.id, {description: el.value});};}(compDescEls[i]));
}
function addComp() {
  fetch('/api/compartment/new', {method: 'POST'}).then(function(res){if(res.ok) location.reload();});
}
function deleteComp(id) {
  if (!confirm('Delete this space?')) return;
  fetch('/api/compartment/' + id, {method: 'DELETE'}).then(function(res){
    if(res.ok) location.reload();
    else { res.json().then(function(d){alert(d.error || 'Cannot delete');}); }
  });
}
</script>
"""
    else:
        content = """
<div style="display:flex; justify-content:space-between; align-items:center; padding:12px 0;">
  <div>
    <div style="font-size:20px; font-weight:700;">Boat Spaces</div>
    <div style="color:var(--text2); font-size:12px;">Tap a space to see tasks & gear</div>
  </div>
  <a href="/compartments?edit=1" style="font-size:20px; text-decoration:none; color:var(--text2);" title="Edit spaces">\u270f\ufe0f</a>
</div>
<div class="comp-grid">
"""
        for comp in comps:
            pct = int((comp['done_tasks'] / comp['total_tasks']) * 100) if comp['total_tasks'] else 0
            pending = ""
            if comp['pending_cost']:
                pending = '\u00b7 \u20ac' + str(int(comp['pending_cost']))
            content += """
<div class="comp-card tap" onclick="location.href='/compartment/""" + str(comp['id']) + """'">
  <div class="name">""" + comp['name'] + """</div>
  <div class="progress-bar"><div class="progress-fill" style=\"width:""" + str(pct) + """%"></div></div>
  <div class="counts">
    """ + str(comp['done_tasks']) + """/""" + str(comp['total_tasks']) + """ tasks """ + pending + """
  </div>
  <div style="font-size:11px; color:var(--text2); margin-top:4px;">""" + (comp['description'] or '') + """</div>
</div>
"""
        content += "</div>"
    
    return render_template_string(BASE_TEMPLATE, page='compartments', content=content)



# ── Compartment CRUD API ──
@app.route('/api/compartment/new', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def new_compartment():
    rid = execute("INSERT INTO compartments (name, sort_order) VALUES ('New space', 99) RETURNING id")
    return jsonify(ok=True, id=rid)

# ── Input sanitization helper ──
def sanitize_text(text, max_len=500):
    if text is None:
        return None
    text = str(text).strip()
    if len(text) > max_len:
        text = text[:max_len]
    # Remove control chars except normal whitespace
    text = ''.join(ch for ch in text if ord(ch) >= 32 or ch in '\n\r\t')
    return text

@app.route('/api/compartment/<int:comp_id>', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def update_compartment(comp_id):
    data = request.json
    if not data:
        return jsonify(ok=False, error='No data'), 400
    allowed = {'name': str, 'description': str, 'sort_order': int}
    sets, vals = [], []
    for field, value in data.items():
        if field not in allowed:
            continue
        if value == '' or value is None:
            sets.append(field + " = NULL")
        elif allowed[field] == int:
            try:
                vals.append(int(value))
                sets.append(field + " = %s")
            except (ValueError, TypeError):
                continue
        else:
            vals.append(str(value))
            sets.append(field + " = %s")
    if not sets:
        return jsonify(ok=False, error='No valid fields'), 400
    vals.append(comp_id)
    execute("UPDATE compartments SET " + ", ".join(sets) + " WHERE id = %s", vals)
    return jsonify(ok=True)

@app.route('/api/compartment/<int:comp_id>', methods=['DELETE'])
@login_required
@limiter.limit("30 per minute")
def delete_compartment(comp_id):
    audit_log.info('DELETE compartment id=%s ip=%s', comp_id, request.remote_addr)
    refs = query("""
        SELECT 
            (SELECT COUNT(*) FROM tasks WHERE compartment_id = %s) as tasks,
            (SELECT COUNT(*) FROM cables WHERE compartment_id = %s) as cables,
            (SELECT COUNT(*) FROM inventory WHERE compartment_id = %s) as gear
    """, [comp_id, comp_id, comp_id], one=True)
    if refs['tasks'] or refs['cables'] or refs['gear']:
        return jsonify(ok=False, error='Space has linked items (tasks/cables/gear). Move them first.'), 400
    execute("DELETE FROM compartments WHERE id = %s", [comp_id])
    return jsonify(ok=True)

# ── Single compartment drill-down ──
# ── Single compartment drill-down ──
@app.route('/compartment/<int:comp_id>')
@login_required
def compartment_detail(comp_id):
    comp = query("SELECT * FROM compartments WHERE id = %s", [comp_id], one=True)
    if not comp:
        return redirect(url_for('compartments_page'))
    
    tasks = query("""
        SELECT t.*, s.name as system, s.color as system_color
        FROM tasks t
        LEFT JOIN systems s ON t.system_id = s.id
        WHERE t.compartment_id = %s
        ORDER BY CASE t.priority WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END
    """, [comp['id']])
    
    gear = query("""
        SELECT i.*, s.name as system
        FROM inventory i
        LEFT JOIN systems s ON i.system_id = s.id
        WHERE i.compartment_id = %s
        ORDER BY i.purchase_status
    """, [comp['id']])
    
    cables = query("""
        SELECT * FROM cables WHERE compartment_id = %s ORDER BY type, circuit
    """, [comp['id']])
    
    content = """
<div style="margin-bottom:12px;">
  <a href="/compartments" style="font-size:13px;">← All spaces</a>
</div>
<div style="text-align:center; padding: 8px 0 16px;">
  <div style="font-size: 22px; font-weight: 700;">""" + comp['name'] + """</div>
  <div style="color: var(--text2); font-size: 12px;">""" + (comp['description'] or '') + """</div>
</div>

<div class="section-title">Tasks (""" + str(len(tasks)) + """)</div>
"""
    for t in tasks:
        phase_badge = ""
        if t['phase']:
            phase_badge = '<span class="badge" style="background:var(--surface2);color:var(--text2);">' + t['phase'] + '</span>'
        content += """
<div class="card tap" onclick="location.href='/task/""" + str(t['id']) + """'">
  <div style="display:flex; justify-content:space-between; align-items:start; gap:8px;">
    <div style="flex:1;">
      <div class="card-title">""" + t['name'] + """</div>
      <div class="card-meta"><span style="color:""" + (t['system_color'] or 'var(--text2)') + """">""" + (t['system'] or '—') + """</span></div>
    </div>
    <span class="badge badge-""" + badge_class(t['status']) + """">""" + t['status'] + """</span>
  </div>
  <div style="margin-top:4px; display:flex; gap:6px; flex-wrap:wrap; align-items:center;">
    """ + ('<span class="badge badge-' + badge_class(t['priority']) + '" style="display:none;">' + t['priority'] + '</span>' if t['status'] == 'Done' else '<span class="badge badge-' + badge_class(t['priority']) + '">' + t['priority'] + '</span>') + """
    """ + phase_badge + """
    """ + ('<span style="font-size:12px; color:var(--text2);">📅 ' + (t['planned_start'] or '?') + ' → ' + (t['planned_end'] or '?') + '</span>' if t['planned_start'] or t['planned_end'] else '') + """
  </div>
</div>
"""
    
    if gear:
        content += '<div class="section-title">Gear (' + str(len(gear)) + ')</div>\n'
        for item in gear:
            cost_line = ""
            if item['total_cost']:
                cost_line = '<div class="cost" style="color:var(--red); margin-top:4px;">€' + str(item['total_cost']) + '</div>'
            content += """
<div class="card">
  <div style="display:flex; justify-content:space-between;">
    <div class="card-title">""" + item['item'] + """</div>
    <span class="badge badge-""" + badge_class(item['purchase_status']) + """ tap" data-id=\"""" + str(item['id']) + """" data-status=\"""" + item['purchase_status'] + """">""" + item['purchase_status'] + """</span>
  </div>
  <div class="card-meta">""" + (item['system'] or '—') + """</div>
  """ + cost_line + """
</div>
"""
    
    if cables:
        content += '<div class="section-title">Cables (' + str(len(cables)) + ')</div>\n<div class="table-wrap"><table><thead><tr><th>Circuit</th><th>Type</th><th>From→To</th><th>mm²</th></tr></thead><tbody>\n'
        for c in cables:
            content += """
<tr>
  <td>""" + c['circuit'] + """</td>
  <td><span class="badge badge-""" + badge_class(c['type']) + """">""" + c['type'] + """</span></td>
  <td>""" + (c['from_location'] or '—') + """ → """ + (c['to_location'] or '—') + """</td>
  <td>""" + (c['cable_mm2'] or '—') + """</td>
</tr>
"""
        content += "</tbody></table></div>"
    
    content += """
<script>
var purchaseOrder=['To buy','Ordered','Bought'];
document.addEventListener('click',function(e){var el=e.target.closest('.tap[data-id]');if(!el)return;e.preventDefault();e.stopPropagation();var id=el.dataset.id;var cur=el.dataset.status;var next=purchaseOrder[(purchaseOrder.indexOf(cur)+1)%purchaseOrder.length];el.style.opacity='0.5';fetch('/api/inventory/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:next})}).then(function(r){if(r.ok){el.textContent=next;el.dataset.status=next;el.className='badge badge-'+next.toLowerCase().replace(' ','')+' tap';el.style.opacity='1';}else{el.style.opacity='1';alert('Error');}}).catch(function(){el.style.opacity='1';alert('Network error');});});
</script>
"""
    return render_template_string(BASE_TEMPLATE, page='compartments', content=content)

# ── Schedule / Timeline ──
@app.route('/schedule')
@login_required
def schedule_page():
    phase_filter = request.args.get('phase', 'all')
    
    # Pull from tasks table instead of schedule table
    sql = """
        SELECT t.*, c.name as compartment, s.name as system
        FROM tasks t
        LEFT JOIN compartments c ON t.compartment_id = c.id
        LEFT JOIN systems s ON t.system_id = s.id
        WHERE t.planned_start IS NOT NULL
    """
    args = []
    if phase_filter != 'all':
        sql += " AND t.phase = %s"
        args.append(phase_filter)
    sql += " ORDER BY t.planned_start, CASE t.priority WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END"
    
    items = query(sql, args)
    
    content = """
<div style="text-align:center; padding: 12px 0;">
  <div style="font-size: 20px; font-weight: 700;">Refit Schedule</div>
  <div style="color: var(--text2); font-size: 12px;">Critical path: woodwork → foam → engine → sail</div>
</div>

<div class="filters">
  <span class="filter-btn """ + ('active' if phase_filter=='all' else '') + """" onclick="setFilter('phase','all')">All</span>
  <span class="filter-btn """ + ('active' if phase_filter=='Before foam' else '') + """" onclick="setFilter('phase','Before foam')">Before Foam</span>
  <span class="filter-btn """ + ('active' if phase_filter=='After foam' else '') + """" onclick="setFilter('phase','After foam')">After Foam</span>
</div>

<div class="timeline">
"""
    for item in items:
        dot_cls = 'done' if item['status'] == 'Done' else ('active' if item['status'] == 'In progress' else '')
        content += """
<div class="tl-item">
  <div class="tl-dot """ + dot_cls + """"></div>
  <div class="tl-content">
    <div style="display:flex; justify-content:space-between; align-items:start;">
      <div style="font-weight:600; font-size:14px;"><a href="/task/""" + str(item['id']) + """" style="color:var(--text); text-decoration:none;">""" + item['name'] + """</a></div>
      <span class="badge" style="background:var(--surface2);color:var(--text2);">""" + (item['phase'] or '—') + """</span>
    </div>
    <div class="tl-date">""" + (item['planned_start'] or '—') + """ → """ + (item['planned_end'] or '—') + """</div>
    <div style="display:flex; gap:6px; margin-top:4px; flex-wrap:wrap; align-items:center;">
      <span class="badge badge-""" + badge_class(item['status']) + """">""" + item['status'] + """</span>
      """ + ('<span class="badge badge-' + badge_class(item['priority']) + '" style="display:none;">' + item['priority'] + '</span>' if item['status'] == 'Done' else '<span class="badge badge-' + badge_class(item['priority']) + '">' + item['priority'] + '</span>') + """
      <span style="font-size:11px; color:var(--text2);">""" + (item['compartment'] or '') + """</span>
    </div>
"""
        if item['notes']:
            content += '<div style="font-size:12px; color:var(--text2); margin-top:4px;">' + item['notes'][:120] + ('...' if len(item['notes']) > 120 else '') + '</div>'
        content += """
  </div>
</div>
"""
    content += """
</div>
<script>
function setFilter(key, val) {
  var url = new URL(location.href);
  url.searchParams.set(key, val);
  location.href = url.toString();
}
</script>
"""
    return render_template_string(BASE_TEMPLATE, page='schedule', content=content)

# ── Inventory ──
@app.route('/inventory')
@login_required
def inventory_page():
    status_filter = request.args.get('status', 'all')
    
    sql = """
        SELECT i.*, c.name as compartment, s.name as system
        FROM inventory i
        LEFT JOIN compartments c ON i.compartment_id = c.id
        LEFT JOIN systems s ON i.system_id = s.id
        WHERE 1=1
    """
    args = []
    if status_filter != 'all':
        sql += " AND i.purchase_status = %s"
        args.append(status_filter)
    sql += " ORDER BY i.purchase_status, i.item"
    
    items = query(sql, args)
    
    counts = query("SELECT purchase_status, COUNT(*) as n, SUM(total_cost) as cost FROM inventory GROUP BY purchase_status")
    total_to_buy = sum(r['cost'] or 0 for r in counts if r['purchase_status'] == 'To buy')
    to_buy = sum(r['n'] for r in counts if r['purchase_status'] == 'To buy')
    bought = sum(r['n'] for r in counts if r['purchase_status'] == 'Bought')
    
    content = """
<div style="margin-bottom:12px;">
  <input type="text" id="inv-search" placeholder="Search gear..." style="margin:0;" oninput="filterInventory()">
</div>

<div class="filters" id="filters">
  <span class="filter-btn """ + ('active' if status_filter=='all' else '') + """" onclick="setFilter('status','all')">All (""" + str(len(items)) + """)</span>
  <span class="filter-btn """ + ('active' if status_filter=='To buy' else '') + """" onclick="setFilter('status','To buy')">To Buy (""" + str(to_buy) + """)</span>
  <span class="filter-btn """ + ('active' if status_filter=='Bought' else '') + """" onclick="setFilter('status','Bought')">Bought (""" + str(bought) + """)</span>
</div>
"""
    for item in items:
        cost_line = ""
        if item['total_cost']:
            cost_line = '<div style="margin-top:6px; font-size:14px;"><span class="cost">€' + str(item['total_cost']) + '</span> <span style="color:var(--text2); margin-left:8px; font-size:12px;">' + (item['reference'] or '') + '</span></div>'
        url_line = ""
        if item['url']:
            url_line = '<div style="margin-top:4px;"><a href="' + item['url'] + '" target="_blank" style="font-size:12px;">🔗 Link</a></div>'
        content += """
<div class="card inv-card">
  <div style="display:flex; justify-content:space-between; align-items:start; gap:8px;">
    <div style="flex:1;">
      <div class="card-title">""" + item['item'] + """</div>
      <div class="card-meta">""" + (item['system'] or '—') + """ · """ + (item['compartment'] or '—') + """</div>
    </div>
    <span class="badge badge-""" + badge_class(item['purchase_status']) + """ tap" data-id=\"""" + str(item['id']) + """" data-status=\"""" + item['purchase_status'] + """">""" + item['purchase_status'] + """</span>
  </div>
  """ + cost_line + url_line + """
  <div style="margin-top:6px;">
    <a href="/item/""" + str(item['id']) + """" style="font-size:12px;">Details →</a>
  </div>
</div>
"""
    
    content += """
<div style="margin-top:16px; padding:12px; background:var(--surface); border-radius:8px; border:1px solid var(--border);">
  <div style="display:flex; justify-content:space-between;">
    <span>Total outstanding</span>
    <span class="cost" style="font-weight:700; color:var(--red);">€""" + ("{:.0f}".format(total_to_buy)) + """</span>
  </div>
</div>

<script>
function setFilter(key, val) {
  var url = new URL(location.href);
  url.searchParams.set(key, val);
  location.href = url.toString();
}
var purchaseOrder = ['To buy', 'Ordered', 'Bought'];
document.addEventListener('click', function(e) {
  var el = e.target.closest('.tap[data-id]');
  if (!el) return;
  e.preventDefault();
  e.stopPropagation();
  var id = el.dataset.id;
  var cur = el.dataset.status;
  var next = purchaseOrder[(purchaseOrder.indexOf(cur) + 1) % purchaseOrder.length];
  el.style.opacity = '0.5';
  fetch('/api/inventory/' + id, {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({status: next})
  }).then(function(r) {
    if (r.ok) {
      el.textContent = next;
      el.dataset.status = next;
      el.className = 'badge badge-' + next.toLowerCase().replace(' ','') + ' tap';
      el.style.opacity = '1';
    } else {
      el.style.opacity = '1';
      alert('Error updating status');
    }
  }).catch(function() { el.style.opacity = '1'; alert('Network error'); });
});
function filterInventory() {
  var q = document.getElementById('inv-search').value.toLowerCase();
  var cards = document.querySelectorAll('.inv-card');
  for (var i = 0; i < cards.length; i++) {
    var text = cards[i].textContent.toLowerCase();
    cards[i].style.display = text.indexOf(q) !== -1 ? '' : 'none';
  }
}
</script>
"""
    return render_template_string(BASE_TEMPLATE, page='inventory', content=content)

# ── Inventory item detail + edit ──
@app.route('/item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def item_detail(item_id):
    item = query("""
        SELECT i.*, c.name as compartment, s.name as system
        FROM inventory i
        LEFT JOIN compartments c ON i.compartment_id = c.id
        LEFT JOIN systems s ON i.system_id = s.id
        WHERE i.id = %s
    """, [item_id], one=True)
    
    if not item:
        return redirect(url_for('inventory_page'))
    
    # Load linked documents (manuals from CSV import)
    docs = query("SELECT filename, file_url, doc_type FROM documents WHERE inventory_id = %s ORDER BY doc_type", [item_id])
    
    compartments = query("SELECT id, name FROM compartments ORDER BY sort_order")
    systems = query("SELECT id, name FROM systems ORDER BY name")
    
    if request.method == 'POST':
        new_item = request.form.get('item', '').strip()
        new_compartment_id = request.form.get('compartment_id', type=int)
        new_system_id = request.form.get('system_id', type=int)
        new_quantity = request.form.get('quantity', type=int) or 1
        new_unit_cost = request.form.get('unit_cost', type=float) or 0
        new_total_cost = request.form.get('total_cost', type=float) or 0
        new_reference = request.form.get('reference', '').strip()
        new_url = request.form.get('url', '').strip()
        new_purchase_status = request.form.get('purchase_status', '')
        new_delivery_date = request.form.get('delivery_date', '').strip()
        new_install_date = request.form.get('install_date', '').strip()
        new_notes = request.form.get('notes', '').strip()
        
        if new_item:
            execute("""
                UPDATE inventory SET
                    item = %s,
                    compartment_id = %s,
                    system_id = %s,
                    quantity = %s,
                    unit_cost = %s,
                    total_cost = %s,
                    reference = %s,
                    url = %s,
                    purchase_status = %s,
                    delivery_date = %s,
                    install_date = %s,
                    notes = %s
                WHERE id = %s
            """, (new_item, new_compartment_id, new_system_id, new_quantity, new_unit_cost,
                  new_total_cost, new_reference, new_url, new_purchase_status,
                  new_delivery_date, new_install_date, new_notes, item_id))
        
        return redirect('/item/' + str(item_id))
    
    comp_options = ""
    for comp in compartments:
        selected = ' selected' if comp['id'] == item['compartment_id'] else ''
        comp_options += f'<option value="{comp["id"]}"{selected}>{comp["name"]}</option>'
    
    sys_options = ""
    for sys in systems:
        selected = ' selected' if sys['id'] == item['system_id'] else ''
        sys_options += f'<option value="{sys["id"]}"{selected}>{sys["name"]}</option>'
    
    status_options = ""
    for st in ['To buy', 'Ordered', 'Bought']:
        selected = ' selected' if st == item['purchase_status'] else ''
        status_options += f'<option value="{st}"{selected}>{st}</option>'
    
    content = f"""
<div style="margin-bottom:12px;">
  <a href="/inventory" style="font-size:13px;">← Back to gear</a>
</div>

<form method="POST" id="item-form">
<div class="card">
  <div style="font-size:18px; font-weight:700; margin-bottom:12px;">Edit Gear</div>
  
  <label style="font-size:12px; color:var(--text2);">Item</label>
  <input type="text" name="item" value="{item['item']}" required>
  
  <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
    <div>
      <label style="font-size:12px; color:var(--text2);">Space</label>
      <select name="compartment_id">{comp_options}</select>
    </div>
    <div>
      <label style="font-size:12px; color:var(--text2);">System</label>
      <select name="system_id">{sys_options}</select>
    </div>
  </div>
  
  <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:8px;">
    <div>
      <label style="font-size:12px; color:var(--text2);">Quantity</label>
      <input type="number" name="quantity" value="{item['quantity'] or 1}" min="1">
    </div>
    <div>
      <label style="font-size:12px; color:var(--text2);">Unit Cost €</label>
      <input type="number" name="unit_cost" value="{item['unit_cost'] or ''}" step="0.01" placeholder="0.00">
    </div>
    <div>
      <label style="font-size:12px; color:var(--text2);">Total Cost €</label>
      <input type="number" name="total_cost" value="{item['total_cost'] or ''}" step="0.01" placeholder="0.00">
    </div>
  </div>
  
  <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
    <div>
      <label style="font-size:12px; color:var(--text2);">Reference / Part #</label>
      <input type="text" name="reference" value="{item['reference'] or ''}" placeholder="SKU, model, part number...">
    </div>
    <div>
      <label style="font-size:12px; color:var(--text2);">Purchase Status</label>
      <select name="purchase_status">{status_options}</select>
    </div>
  </div>
  
  <label style="font-size:12px; color:var(--text2);">URL / Supplier Link</label>
  <input type="url" name="url" value="{item['url'] or ''}" placeholder="https://...">
  
  <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
    <div>
      <label style="font-size:12px; color:var(--text2);">Delivery Date</label>
      <input type="date" name="delivery_date" value="{item['delivery_date'] or ''}">
    </div>
    <div>
      <label style="font-size:12px; color:var(--text2);">Install Date</label>
      <input type="date" name="install_date" value="{item['install_date'] or ''}">
    </div>
  </div>
  
  <label style="font-size:12px; color:var(--text2);">Notes</label>
  <textarea name="notes" rows="3" placeholder="Supplier, specs, install notes...">{item['notes'] or ''}</textarea>
  
  <div style="display:flex; gap:8px;">
    <button type="submit" class="submit" style="flex:1;">Save Changes</button>
    <button type="button" class="submit" style="background:var(--surface2); color:var(--text);" onclick="history.back()">Cancel</button>
  </div>
</div>
</form>
"""
    
    # Add documents section if manuals exist
    if docs:
        content += '<div class="section-title">Manuals & Documents</div>\n'
        for doc in docs:
            link = f'<a href="{doc["file_url"]}" target="_blank" style="font-size:12px;white-space:nowrap;">🔗 View</a>' if doc['file_url'] else ''
            content += f"""
<div class="card">
  <div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">
    <div style="min-width:0; flex:1;">
      <div class="card-title" style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">{doc['filename']}</div>
      <div class="card-meta">{doc['doc_type'] or 'Document'}</div>
    </div>
    <div>{link}</div>
  </div>
</div>
"""
    
    return render_template_string(BASE_TEMPLATE, page='inventory', content=content)

# ── Wiring ──
@app.route('/wiring')
@login_required
def wiring_page():
    type_filter = request.args.get('type', 'all')
    comp_filter = request.args.get('comp', 'all')
    sort_by = request.args.get('sort', 'compartment')
    
    # Build query
    sql = """
        SELECT c.*, comp.name as compartment
        FROM cables c
        LEFT JOIN compartments comp ON c.compartment_id = comp.id
        WHERE 1=1
    """
    args = []
    if type_filter != 'all':
        sql += " AND c.type = %s"
        args.append(type_filter)
    if comp_filter != 'all':
        sql += " AND c.compartment_id = %s"
        args.append(int(comp_filter))
    
    valid_sorts = {'compartment': 'comp.name, c.type, c.from_location', 'type': 'c.type, comp.name, c.from_location', 'from': 'c.from_location, comp.name, c.type', 'to': 'c.to_location, comp.name, c.type'}
    order = valid_sorts.get(sort_by, 'comp.name, c.type, c.from_location')
    sql += " ORDER BY " + order
    
    cables = query(sql, args)
    compartments = query("SELECT id, name FROM compartments ORDER BY sort_order, name")
    inventory = query("SELECT id, item, compartment_id FROM inventory ORDER BY compartment_id, item")
    
    # Filters
    comp_btns = '<span class="filter-btn ' + ('active' if comp_filter=='all' else '') + '" onclick="setFilter(\'comp\',\'all\')">All</span>'
    for comp in compartments:
        active = 'active' if comp_filter==str(comp['id']) else ''
        comp_btns += '<span class="filter-btn ' + active + '" onclick="setFilter(\'comp\',\'' + str(comp['id']) + '\')">' + comp['name'] + '</span>'
    
    sort_labels = {'compartment': 'Compartment', 'type': 'Type', 'from': 'From', 'to': 'To'}
    sort_btns = ''
    for key, label in sort_labels.items():
        if key == 'compartment' and comp_filter != 'all':
            continue
        active = 'active' if sort_by==key else ''
        sort_btns += '<span class="filter-btn ' + active + '" onclick="setSort(\'' + key + '\')">' + label + '</span>'
    if comp_filter != 'all' and sort_by == 'compartment':
        sort_by = 'type'
    
    # JSON data for JS
    cables_json = json.dumps([{k: v for k, v in c.items() if k in ('id','circuit','type','compartment_id','from_location','to_location','cable_mm2','conductors','length_m','notes','compartment','inventory_id')} for c in cables], default=str)
    comps_json = json.dumps([{'id': c['id'], 'name': c['name']} for c in compartments])
    inv_json = json.dumps([{'id': i['id'], 'item': i['item']} for i in inventory])

    content = """
<style>
.wl{font-size:12px;line-height:1.4;border-collapse:collapse;width:100%;}
.wl th{text-align:left;color:var(--text2);font-size:11px;font-weight:500;padding:4px 6px;border-bottom:1px solid var(--border);}
.wl td{padding:3px 6px;border-bottom:1px solid var(--border);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:120px;}
.wl tr.tap{cursor:pointer;}
.wl tr.tap:hover{background:var(--surface2);}
.wl tr.sel{background:var(--surface2);}
.badge{font-size:10px;padding:1px 5px;border-radius:4px;}
#editor{display:none;background:var(--surface2);border-radius:8px;padding:12px;margin:8px 0;}
#editor .row{display:flex;gap:8px;margin-bottom:6px;align-items:center;}
#editor label{font-size:11px;color:var(--text2);width:70px;flex-shrink:0;}
#editor input,#editor select{flex:1;padding:5px 7px;font-size:13px;border:1px solid var(--border);border-radius:4px;background:var(--surface1);color:var(--text1);}
#editor .btns{display:flex;gap:8px;margin-top:8px;}
#editor .btns button{padding:6px 14px;border:none;border-radius:6px;cursor:pointer;font-size:12px;}
</style>
<div class="filters" id="type-filters">
  <span class="filter-btn """ + ('active' if type_filter=='all' else '') + """" onclick="setFilter('type','all')">All</span>
  <span class="filter-btn """ + ('active' if type_filter=='24V' else '') + """" onclick="setFilter('type','24V')">24V</span>
  <span class="filter-btn """ + ('active' if type_filter=='220V' else '') + """" onclick="setFilter('type','220V')">220V</span>
  <span class="filter-btn """ + ('active' if type_filter=='NMEA 2000' else '') + """" onclick="setFilter('type','NMEA 2000')">NMEA</span>
  <span class="filter-btn """ + ('active' if type_filter=='Coax' else '') + """" onclick="setFilter('type','Coax')">Coax</span>
  <span class="filter-btn """ + ('active' if type_filter=='Ethernet' else '') + """" onclick="setFilter('type','Ethernet')">Eth</span>
</div>
<div class="filters" style="flex-wrap:wrap;">""" + comp_btns + """</div>
<div class="filters" style="margin-bottom:2px;">
  <span style="font-size:11px;color:var(--text2);margin-right:4px;">Sort:</span>""" + sort_btns + """
</div>
<table class="wl">
<thead><tr><th>Circuit</th><th>Space</th><th>From → To</th><th>Type</th><th>mm²</th><th>C</th><th>Gear</th><th style="text-align:right;">m</th></tr></thead>
<tbody id="clist">
</tbody>
</table>
<div id="editor">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <span id="ed-title" style="font-size:14px;font-weight:600;"></span>
    <button onclick="closeEdit()" style="background:none;border:none;color:var(--text2);font-size:18px;cursor:pointer;">✕</button>
  </div>
  <div class="row"><label>Circuit</label><input id="ed-circuit"></div>
  <div class="row"><label>Type</label><select id="ed-type"><option value="24V">24V DC</option><option value="220V">220V AC</option><option value="NMEA 2000">NMEA 2000</option><option value="Coax">Coax</option><option value="Ethernet">Ethernet</option><option value="Signal">Signal</option><option value="Other">Other</option></select></div>
  <div class="row"><label>Space</label><select id="ed-comp"><option value="">—</option></select></div>
  <div class="row"><label>Gear</label><select id="ed-gear"><option value="">— none —</option></select></div>
  <div class="row"><label>From</label><input id="ed-from"></div>
  <div class="row"><label>To</label><input id="ed-to"></div>
  <div class="row"><label>mm²</label><input id="ed-mm2" style="width:60px;flex:none;"><label style="width:40px;">Cond</label><input id="ed-cond" type="number" min="0" style="width:50px;flex:none;"><label style="width:40px;">Length</label><input id="ed-len" type="number" step="0.1" style="width:60px;flex:none;"></div>
  <div class="row"><label>Notes</label><input id="ed-notes"></div>
  <div class="btns">
    <button onclick="saveCable()" style="background:var(--green);color:#111;">Save</button>
    <button onclick="deleteCable()" style="background:var(--red);color:#fff;">Delete</button>
    <span id="ed-status" style="font-size:12px;color:var(--green);line-height:30px;"></span>
  </div>
</div>
<div style="margin-top:8px;text-align:center;">
  <a href="/wiring/recap" class="submit" style="padding:6px 12px;font-size:12px;text-decoration:none;margin-right:6px;">📊 Recap</a>
  <button class="submit" onclick="addCable()" style="padding:6px 12px;font-size:12px;">+ Add Cable</button>
  <span style="font-size:11px;color:var(--text2);margin-left:8px;">""" + str(len(cables)) + """ cables</span>
</div>
<script>
var CABLES = """ + cables_json + """;
var COMPS = """ + comps_json + """;\nvar INV = """ + inv_json + """;
var BADGE = {'24V':'blue','220V':'orange','NMEA 2000':'purple','Coax':'teal','Ethernet':'blue','Signal':'teal','Other':'gray'};

var tbody = document.getElementById('clist');
var editId = null;

function badgeClass(t){return 'badge badge-'+(BADGE[t]||'gray');}

function findById(arr, id){for(var i=0;i<arr.length;i++){if(arr[i].id===id)return arr[i];}return null;}

function render(){
  tbody.innerHTML='';
  for(var i=0;i<CABLES.length;i++){
    var c=CABLES[i];
    var tr = document.createElement('tr');
    tr.className = 'tap'+(editId===c.id?' sel':'');
    tr.dataset.id = c.id;
    var comp = findById(COMPS, c.compartment_id);
    var compLabel = comp ? comp.name : '';
    tr.innerHTML = '<td>'+esc(c.circuit)+'</td>'
      +'<td style="font-size:11px;color:var(--text2);">'+esc(compLabel)+'</td>'
      +'<td>'+(c.from_location||c.to_location? esc(c.from_location||'')+' → '+esc(c.to_location||''):'—')+'</td>'
      +'<td><span class="'+badgeClass(c.type)+'">'+esc(c.type)+'</span></td>'
      +'<td>'+(c.cable_mm2||'—')+'</td>'
      +'<td>'+(c.conductors||'—')+'</td>'
      +'<td style="font-size:11px;color:var(--text2);">'+gearLabel(c.inventory_id)+'</td>'
      +'<td style="text-align:right;">'+(c.length_m||'—')+'</td>';
    tr.onclick=function(id){return function(){openEdit(id);};}(c.id);
    tbody.appendChild(tr);
  }
}

function gearLabel(id){if(!id)return '';var g=findById(INV,id);return g?g.item:'';}\nfunction esc(s){if(!s)return '';return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

function openEdit(id){
  var c = findById(CABLES, id);
  if(!c) return;
  editId = id;
  document.getElementById('ed-title').textContent = c.circuit;
  document.getElementById('ed-circuit').value = c.circuit||'';
  document.getElementById('ed-type').value = c.type||'24V';
  document.getElementById('ed-from').value = c.from_location||'';
  document.getElementById('ed-to').value = c.to_location||'';
  document.getElementById('ed-mm2').value = c.cable_mm2||'';
  document.getElementById('ed-cond').value = c.conductors||'';
  document.getElementById('ed-len').value = c.length_m||'';
  document.getElementById('ed-notes').value = c.notes||'';
  var sel = document.getElementById('ed-comp');
  sel.value = c.compartment_id||'';\n  document.getElementById('ed-gear').value = c.inventory_id||'';
  document.getElementById('editor').style.display = 'block';
  document.getElementById('ed-status').textContent = '';
  render();
  document.getElementById('editor').scrollIntoView({behavior:'smooth',block:'nearest'});
}

function closeEdit(){
  editId = null;
  document.getElementById('editor').style.display = 'none';
  render();
}

function saveCable(){
  if(!editId) return;
  var data = {
    circuit: document.getElementById('ed-circuit').value,
    type: document.getElementById('ed-type').value,
    compartment_id: document.getElementById('ed-comp').value||null,
    from_location: document.getElementById('ed-from').value,
    to_location: document.getElementById('ed-to').value,
    cable_mm2: document.getElementById('ed-mm2').value,
    conductors: document.getElementById('ed-cond').value,
    length_m: document.getElementById('ed-len').value,
    notes: document.getElementById('ed-notes').value,\n    inventory_id: document.getElementById('ed-gear').value||null,
  };
  fetch('/api/cable/'+editId,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)}).then(function(res){
    if(res.ok){
      var c = findById(CABLES, editId);
      if(c){for(var k in data){c[k]=data[k];}if(data.compartment_id)c.compartment_id=parseInt(data.compartment_id)||null;if(data.inventory_id)c.inventory_id=parseInt(data.inventory_id)||null;}
      document.getElementById('ed-title').textContent = data.circuit;
      document.getElementById('ed-status').textContent = 'Saved';
      setTimeout(function(){document.getElementById('ed-status').textContent='';},2000);
      render();
    }
  });
}

function addCable(){
  fetch('/api/cable/new',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({circuit:'New cable',type:'24V'})}).then(function(res){
    if(res.ok){
      res.json().then(function(data){
        location.href = location.pathname + '#edit' + data.id;
        location.reload();
      });
    } else {alert('Error adding cable ('+res.status+')');}
  }).catch(function(e){alert('Network error: '+e.message);});
}

function deleteCable(){
  if(!editId||!confirm('Delete this cable?')) return;
  fetch('/api/cable/'+editId,{method:'DELETE'}).then(function(res){if(res.ok) location.reload();});
}

function setFilter(key,val){
  var u=new URL(location.href);
  u.searchParams.set(key,val);
  if(key==='comp'){
    if(val!=='all'){
      if(u.searchParams.get('sort')==='compartment') u.searchParams.set('sort','type');
    } else {
      if(!u.searchParams.get('sort')||u.searchParams.get('sort')==='type') u.searchParams.set('sort','compartment');
    }
  }
  location.href=u.toString();
}
function setSort(val){var u=new URL(location.href);u.searchParams.set('sort',val);location.href=u.toString();}

// Populate compartment dropdown
var selComp = document.getElementById('ed-comp');
for(var i=0;i<COMPS.length;i++){var o=document.createElement('option');o.value=COMPS[i].id;o.textContent=COMPS[i].name;selComp.appendChild(o);}
var selGear = document.getElementById('ed-gear');
for(var i=0;i<INV.length;i++){var o=document.createElement('option');o.value=INV[i].id;o.textContent=INV[i].item;selGear.appendChild(o);}

render();
if(location.hash && location.hash.indexOf('#edit')===0){
  var id = parseInt(location.hash.slice(5));
  if(id) openEdit(id);
}
</script>
"""
    return render_template_string(BASE_TEMPLATE, page='wiring', content=content)

# ── Plumbing ──
@app.route('/plumbing')
@login_required
def plumbing_page():
    type_filter = request.args.get('type', 'all')
    comp_filter = request.args.get('comp', 'all')
    sort_by = request.args.get('sort', 'compartment')
    
    # Build query
    sql = """
        SELECT h.*, comp.name as compartment
        FROM hoses h
        LEFT JOIN compartments comp ON h.compartment_id = comp.id
        WHERE 1=1
    """
    args = []
    if type_filter != 'all':
        sql += " AND h.type = %s"
        args.append(type_filter)
    if comp_filter != 'all':
        sql += " AND h.compartment_id = %s"
        args.append(int(comp_filter))
    
    valid_sorts = {'compartment': 'comp.name, h.type, h.from_location', 'type': 'h.type, comp.name, h.from_location', 'from': 'h.from_location, comp.name, h.type', 'to': 'h.to_location, comp.name, h.type'}
    order = valid_sorts.get(sort_by, 'comp.name, h.type, h.from_location')
    sql += " ORDER BY " + order
    
    hoses = query(sql, args)
    compartments = query("SELECT id, name FROM compartments ORDER BY sort_order, name")
    inventory = query("SELECT id, item, compartment_id FROM inventory ORDER BY compartment_id, item")
    
    # Filters
    comp_btns = '<span class="filter-btn ' + ('active' if comp_filter=='all' else '') + '" onclick="setFilter(\'comp\',\'all\')">All</span>'
    for comp in compartments:
        active = 'active' if comp_filter==str(comp['id']) else ''
        comp_btns += '<span class="filter-btn ' + active + '" onclick="setFilter(\'comp\',\'' + str(comp['id']) + '\')">' + comp['name'] + '</span>'
    
    sort_labels = {'compartment': 'Compartment', 'type': 'Type', 'from': 'From', 'to': 'To'}
    sort_btns = ''
    for key, label in sort_labels.items():
        if key == 'compartment' and comp_filter != 'all':
            continue
        active = 'active' if sort_by==key else ''
        sort_btns += '<span class="filter-btn ' + active + '" onclick="setSort(\'' + key + '\')">' + label + '</span>'
    if comp_filter != 'all' and sort_by == 'compartment':
        sort_by = 'type'
    
    # JSON data for JS
    hoses_json = json.dumps([{k: v for k, v in h.items() if k in ('id','circuit','type','compartment_id','from_location','to_location','hose_size','length_m','notes','compartment','inventory_id')} for h in hoses], default=str)
    comps_json = json.dumps([{'id': c['id'], 'name': c['name']} for c in compartments])
    inv_json = json.dumps([{'id': i['id'], 'item': i['item']} for i in inventory])

    content = """
<style>
.wl{font-size:12px;line-height:1.4;border-collapse:collapse;width:100%;}
.wl th{text-align:left;color:var(--text2);font-size:11px;font-weight:500;padding:4px 6px;border-bottom:1px solid var(--border);}
.wl td{padding:3px 6px;border-bottom:1px solid var(--border);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:120px;}
.wl tr.tap{cursor:pointer;}
.wl tr.tap:hover{background:var(--surface2);}
.wl tr.sel{background:var(--surface2);}
.badge{font-size:10px;padding:1px 5px;border-radius:4px;}
#editor{display:none;background:var(--surface2);border-radius:8px;padding:12px;margin:8px 0;}
#editor .row{display:flex;gap:8px;margin-bottom:6px;align-items:center;}
#editor label{font-size:11px;color:var(--text2);width:70px;flex-shrink:0;}
#editor input,#editor select{flex:1;padding:5px 7px;font-size:13px;border:1px solid var(--border);border-radius:4px;background:var(--surface1);color:var(--text1);}
#editor .btns{display:flex;gap:8px;margin-top:8px;}
#editor .btns button{padding:6px 14px;border:none;border-radius:6px;cursor:pointer;font-size:12px;}
</style>
<div class="filters" id="type-filters">
  <span class="filter-btn """ + ('active' if type_filter=='all' else '') + """" onclick="setFilter('type','all')">All</span>
  <span class="filter-btn """ + ('active' if type_filter=='Fresh water' else '') + """" onclick="setFilter('type','Fresh water')">Fresh</span>
  <span class="filter-btn """ + ('active' if type_filter=='Salt water' else '') + """" onclick="setFilter('type','Salt water')">Salt</span>
  <span class="filter-btn """ + ('active' if type_filter=='Bilge' else '') + """" onclick="setFilter('type','Bilge')">Bilge</span>
  <span class="filter-btn """ + ('active' if type_filter=='Black water' else '') + """" onclick="setFilter('type','Black water')">Black</span>
  <span class="filter-btn """ + ('active' if type_filter=='Diesel' else '') + """" onclick="setFilter('type','Diesel')">Diesel</span>
  <span class="filter-btn """ + ('active' if type_filter=='Hydraulic' else '') + """" onclick="setFilter('type','Hydraulic')">Hydraulic</span>
  <span class="filter-btn """ + ('active' if type_filter=='Vent' else '') + """" onclick="setFilter('type','Vent')">Vent</span>
  <span class="filter-btn """ + ('active' if type_filter=='Propane' else '') + """" onclick="setFilter('type','Propane')">Propane</span>
  <span class="filter-btn """ + ('active' if type_filter=='Other' else '') + """" onclick="setFilter('type','Other')">Other</span>
</div>
<div class="filters" style="flex-wrap:wrap;">""" + comp_btns + """</div>
<div class="filters" style="margin-bottom:2px;">
  <span style="font-size:11px;color:var(--text2);margin-right:4px;">Sort:</span>""" + sort_btns + """
</div>
<table class="wl">
<thead><tr><th>Circuit</th><th>Space</th><th>From → To</th><th>Type</th><th>Size</th><th>Gear</th><th style="text-align:right;">m</th></tr></thead>
<tbody id="hlist">
</tbody>
</table>
<div id="editor">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <span id="ed-title" style="font-size:14px;font-weight:600;"></span>
    <button onclick="closeEdit()" style="background:none;border:none;color:var(--text2);font-size:18px;cursor:pointer;">✕</button>
  </div>
  <div class="row"><label>Circuit</label><input id="ed-circuit"></div>
  <div class="row"><label>Type</label><select id="ed-type"><option value="Fresh water">Fresh water</option><option value="Salt water">Salt water</option><option value="Bilge">Bilge</option><option value="Black water">Black water</option><option value="Diesel">Diesel</option><option value="Hydraulic">Hydraulic</option><option value="Vent">Vent</option><option value="Propane">Propane</option><option value="Other">Other</option></select></div>
  <div class="row"><label>Space</label><select id="ed-comp"><option value="">—</option></select></div>
  <div class="row"><label>Gear</label><select id="ed-gear"><option value="">— none —</option></select></div>
  <div class="row"><label>From</label><input id="ed-from"></div>
  <div class="row"><label>To</label><input id="ed-to"></div>
  <div class="row"><label>Size</label><input id="ed-size" style="width:80px;flex:none;"><label style="width:50px;">Length</label><input id="ed-len" type="number" step="0.1" style="width:70px;flex:none;"></div>
  <div class="row"><label>Notes</label><input id="ed-notes"></div>
  <div class="btns">
    <button onclick="saveHose()" style="background:var(--green);color:#111;">Save</button>
    <button onclick="deleteHose()" style="background:var(--red);color:#fff;">Delete</button>
    <span id="ed-status" style="font-size:12px;color:var(--green);line-height:30px;"></span>
  </div>
</div>
<div style="margin-top:8px;text-align:center;">
  <button class="submit" onclick="addHose()" style="padding:6px 12px;font-size:12px;">+ Add Hose</button>
  <span style="font-size:11px;color:var(--text2);margin-left:8px;">""" + str(len(hoses)) + """ hoses</span>
</div>
<script>
var HOSES = """ + hoses_json + """;
var COMPS = """ + comps_json + """;
var INV = """ + inv_json + """;
var BADGE = {'Fresh water':'blue','Salt water':'teal','Bilge':'orange','Black water':'purple','Diesel':'red','Hydraulic':'orange','Vent':'gray','Propane':'red','Other':'gray'};

var tbody = document.getElementById('hlist');
var editId = null;

function badgeClass(t){return 'badge badge-'+(BADGE[t]||'gray');}

function findById(arr, id){for(var i=0;i<arr.length;i++){if(arr[i].id===id)return arr[i];}return null;}

function render(){
  tbody.innerHTML='';
  for(var i=0;i<HOSES.length;i++){
    var h=HOSES[i];
    var tr = document.createElement('tr');
    tr.className = 'tap'+(editId===h.id?' sel':'');
    tr.dataset.id = h.id;
    var comp = findById(COMPS, h.compartment_id);
    var compLabel = comp ? comp.name : '';
    tr.innerHTML = '<td>'+esc(h.circuit)+'</td>'
      +'<td style="font-size:11px;color:var(--text2);">'+esc(compLabel)+'</td>'
      +'<td>'+(h.from_location||h.to_location? esc(h.from_location||'')+' → '+esc(h.to_location||''):'—')+'</td>'
      +'<td><span class="'+badgeClass(h.type)+'">'+esc(h.type)+'</span></td>'
      +'<td>'+(h.hose_size||'—')+'</td>'
      +'<td style="font-size:11px;color:var(--text2);">'+gearLabel(h.inventory_id)+'</td>'
      +'<td style="text-align:right;">'+(h.length_m||'—')+'</td>';
    tr.onclick=function(id){return function(){openEdit(id);};}(h.id);
    tbody.appendChild(tr);
  }
}

function gearLabel(id){if(!id)return '';var g=findById(INV,id);return g?g.item:'';}
function esc(s){if(!s)return '';return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

function openEdit(id){
  var h = findById(HOSES, id);
  if(!h) return;
  editId = id;
  document.getElementById('ed-title').textContent = h.circuit;
  document.getElementById('ed-circuit').value = h.circuit||'';
  document.getElementById('ed-type').value = h.type||'Fresh water';
  document.getElementById('ed-from').value = h.from_location||'';
  document.getElementById('ed-to').value = h.to_location||'';
  document.getElementById('ed-size').value = h.hose_size||'';
  document.getElementById('ed-len').value = h.length_m||'';
  document.getElementById('ed-notes').value = h.notes||'';
  var sel = document.getElementById('ed-comp');
  sel.value = h.compartment_id||'';
  document.getElementById('ed-gear').value = h.inventory_id||'';
  document.getElementById('editor').style.display = 'block';
  document.getElementById('ed-status').textContent = '';
  render();
  document.getElementById('editor').scrollIntoView({behavior:'smooth',block:'nearest'});
}

function closeEdit(){
  editId = null;
  document.getElementById('editor').style.display = 'none';
  render();
}

function saveHose(){
  if(!editId) return;
  var data = {
    circuit: document.getElementById('ed-circuit').value,
    type: document.getElementById('ed-type').value,
    compartment_id: document.getElementById('ed-comp').value||null,
    from_location: document.getElementById('ed-from').value,
    to_location: document.getElementById('ed-to').value,
    hose_size: document.getElementById('ed-size').value,
    length_m: document.getElementById('ed-len').value,
    notes: document.getElementById('ed-notes').value,
    inventory_id: document.getElementById('ed-gear').value||null,
  };
  fetch('/api/hose/'+editId,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)}).then(function(res){
    if(res.ok){
      var h = findById(HOSES, editId);
      if(h){for(var k in data){h[k]=data[k];}if(data.compartment_id)h.compartment_id=parseInt(data.compartment_id)||null;if(data.inventory_id)h.inventory_id=parseInt(data.inventory_id)||null;}
      document.getElementById('ed-title').textContent = data.circuit;
      document.getElementById('ed-status').textContent = '✓ Saved';
      document.getElementById('ed-status').style.fontWeight = '700';
      setTimeout(function(){document.getElementById('ed-status').textContent='';document.getElementById('ed-status').style.fontWeight='';},2000);
      render();
    }
  });
}

function addHose(){
  fetch('/api/hose/new',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({circuit:'New hose',type:'Fresh water'})}).then(function(res){
    if(res.ok){
      res.json().then(function(data){
        location.href = location.pathname + '#edit' + data.id;
        location.reload();
      });
    } else {alert('Error adding hose ('+res.status+')');}
  }).catch(function(e){alert('Network error: '+e.message);});
}

function deleteHose(){
  if(!editId||!confirm('Delete this hose?')) return;
  fetch('/api/hose/'+editId,{method:'DELETE'}).then(function(res){if(res.ok) location.reload();});
}

function setFilter(key,val){
  var u=new URL(location.href);
  u.searchParams.set(key,val);
  if(key==='comp'){
    if(val!=='all'){
      if(u.searchParams.get('sort')==='compartment') u.searchParams.set('sort','type');
    } else {
      if(!u.searchParams.get('sort')||u.searchParams.get('sort')==='type') u.searchParams.set('sort','compartment');
    }
  }
  location.href=u.toString();
}
function setSort(val){var u=new URL(location.href);u.searchParams.set('sort',val);location.href=u.toString();}

// Populate compartment dropdown
var selComp = document.getElementById('ed-comp');
for(var i=0;i<COMPS.length;i++){var o=document.createElement('option');o.value=COMPS[i].id;o.textContent=COMPS[i].name;selComp.appendChild(o);}
var selGear = document.getElementById('ed-gear');
for(var i=0;i<INV.length;i++){var o=document.createElement('option');o.value=INV[i].id;o.textContent=INV[i].item;selGear.appendChild(o);}

render();
if(location.hash && location.hash.indexOf('#edit')===0){
  var id = parseInt(location.hash.slice(5));
  if(id) openEdit(id);
}
</script>
"""
    return render_template_string(BASE_TEMPLATE, page='plumbing', content=content)


# ── API endpoints ──
@app.route('/api/task/<int:task_id>', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def update_task(task_id):
    data = request.json or {}
    status = data.get('status')
    if status in ('To plan', 'Ready', 'In progress', 'Done'):
        execute("UPDATE tasks SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s", (status, task_id))
        return jsonify(ok=True)
    if 'inventory_id' in data:
        inv_id = data['inventory_id'] or None
        execute("UPDATE tasks SET inventory_id = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s", (inv_id, task_id))
        return jsonify(ok=True)
    return jsonify(ok=False), 400

@app.route('/api/task/<int:task_id>/delete', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def delete_task(task_id):
    audit_log.info('DELETE task id=%s ip=%s', task_id, request.remote_addr)
    execute("DELETE FROM logs WHERE task_id = %s", [task_id])
    execute("DELETE FROM tasks WHERE id = %s", [task_id])
    return jsonify(ok=True)

@app.route('/api/log/<int:log_id>/delete', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def delete_log(log_id):
    audit_log.info('DELETE log id=%s ip=%s', log_id, request.remote_addr)
    execute("DELETE FROM logs WHERE id = %s", [log_id])
    return jsonify(ok=True)

@app.route('/api/log/<int:log_id>/photo', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def upload_log_photo(log_id):
    f = request.files.get('photo')
    if not f:
        return jsonify(ok=False, error='No file'), 400
    import uuid, os
    ext = os.path.splitext(f.filename)[1].lower()
    ALLOWED_EXTS = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
    if ext not in ALLOWED_EXTS:
        return jsonify(ok=False, error='Invalid file type'), 400
    # MIME type validation
    ALLOWED_MIMES = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}
    if f.content_type not in ALLOWED_MIMES:
        return jsonify(ok=False, error='Invalid file content type'), 400
    f.seek(0, 2)
    size = f.tell()
    f.seek(0)
    if size > 10 * 1024 * 1024:  # 10 MB
        return jsonify(ok=False, error='File too large (max 10 MB)'), 400
    fname = f"log_{log_id}_{uuid.uuid4().hex[:6]}{ext}"
    path = os.path.join('/opt/refit/static/uploads', fname)
    f.save(path)
    url = f'/static/uploads/{fname}'
    execute("UPDATE logs SET photo_url = %s WHERE id = %s", (url, log_id))
    # Sanitize filename for audit log — strip newlines to prevent log injection
    safe_fname = fname.replace('\n', ' ').replace('\r', ' ')
    audit_log.info('PHOTO upload log_id=%s file=%s size=%d', log_id, safe_fname, size)
    return jsonify(ok=True, url=url)

@app.route('/api/inventory/<int:inv_id>', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def update_inventory(inv_id):
    status = request.json.get('status')
    if status in ('To buy', 'Ordered', 'Bought'):
        execute("UPDATE inventory SET purchase_status = %s WHERE id = %s", (status, inv_id))
        return jsonify(ok=True)
    return jsonify(ok=False), 400

@app.route('/api/cable/<int:cable_id>/length', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def update_cable_length(cable_id):
    length = request.json.get('length_m')
    if length is not None:
        try:
            length_val = float(length)
            execute("UPDATE cables SET length_m = %s WHERE id = %s", (length_val, cable_id))
            return jsonify(ok=True)
        except ValueError:
            return jsonify(ok=False, error='Invalid length'), 400
    return jsonify(ok=False), 400

@app.route('/api/cable/<int:cable_id>', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def update_cable(cable_id):
    """Generic cable update — any editable field."""
    data = request.json
    if not data:
        return jsonify(ok=False, error='No data'), 400
    
    allowed = {
        'circuit': str,
        'type': str,
        'compartment_id': int,
        'from_location': str,
        'to_location': str,
        'cable_mm2': str,
        'conductors': int,
        'length_m': float,
        'notes': str,
        'inventory_id': int,
    }
    
    valid_types = ('24V', '220V', 'NMEA 2000', 'Coax', 'Ethernet', 'Signal', 'Other')
    sets = []
    vals = []
    for field, value in data.items():
        if field == 'id' or field not in allowed:
            continue
        if value == '' or value is None:
            sets.append(field + " = NULL")
        elif allowed[field] == int:
            try:
                vals.append(int(value))
                sets.append(field + " = %s")
            except (ValueError, TypeError):
                continue
        elif allowed[field] == float:
            try:
                vals.append(float(value))
                sets.append(field + " = %s")
            except (ValueError, TypeError):
                continue
        else:
            # Validate type field
            if field == 'type' and value not in valid_types:
                return jsonify(ok=False, error='Invalid type'), 400
            vals.append(str(value))
            sets.append(field + " = %s")
    
    if not sets:
        return jsonify(ok=False, error='No valid fields'), 400
    
    vals.append(cable_id)
    sql = "UPDATE cables SET " + ", ".join(sets) + " WHERE id = %s"
    execute(sql, vals)
    return jsonify(ok=True)


# ── Cable Create/Delete API ──
@app.route('/api/cable/new', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def new_cable():
    data = request.json or {}
    circuit = sanitize_text(data.get('circuit', 'New cable'), max_len=200)
    ctype = sanitize_text(data.get('type', '24V'), max_len=50)
    comp_id = data.get('compartment_id') or None
    cable_id = execute(
        "INSERT INTO cables (circuit, type, compartment_id) VALUES (%s, %s, %s) RETURNING id",
        (circuit, ctype, comp_id)
    )
    return jsonify(ok=True, id=cable_id)

@app.route('/api/cable/<int:cable_id>', methods=['DELETE'])
@login_required
@limiter.limit("30 per minute")
def delete_cable(cable_id):
    audit_log.info('DELETE cable id=%s ip=%s', cable_id, request.remote_addr)
    execute("DELETE FROM cables WHERE id = %s", [cable_id])
    return jsonify(ok=True)

# ── Hose API ──
@app.route('/api/hose/<int:hose_id>', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def update_hose(hose_id):
    """Generic hose update — any editable field."""
    data = request.json
    if not data:
        return jsonify(ok=False, error='No data'), 400
    
    allowed = {
        'circuit': str,
        'type': str,
        'compartment_id': int,
        'from_location': str,
        'to_location': str,
        'hose_size': str,
        'length_m': float,
        'notes': str,
        'inventory_id': int,
    }
    
    valid_types = ('Fresh water', 'Salt water', 'Bilge', 'Black water', 'Diesel', 'Hydraulic', 'Vent', 'Propane', 'Other')
    sets = []
    vals = []
    for field, value in data.items():
        if field == 'id' or field not in allowed:
            continue
        if value == '' or value is None:
            sets.append(field + " = NULL")
        elif allowed[field] == int:
            try:
                vals.append(int(value))
                sets.append(field + " = %s")
            except (ValueError, TypeError):
                continue
        elif allowed[field] == float:
            try:
                vals.append(float(value))
                sets.append(field + " = %s")
            except (ValueError, TypeError):
                continue
        else:
            # Validate type field
            if field == 'type' and value not in valid_types:
                return jsonify(ok=False, error='Invalid type'), 400
            vals.append(str(value))
            sets.append(field + " = %s")
    
    if not sets:
        return jsonify(ok=False, error='No valid fields'), 400
    
    vals.append(hose_id)
    sql = "UPDATE hoses SET " + ", ".join(sets) + " WHERE id = %s"
    execute(sql, vals)
    return jsonify(ok=True)

@app.route('/api/hose/new', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def new_hose():
    data = request.json or {}
    circuit = sanitize_text(data.get('circuit', 'New hose'), max_len=200)
    htype = sanitize_text(data.get('type', 'Fresh water'), max_len=50)
    comp_id = data.get('compartment_id') or None
    hose_id = execute(
        "INSERT INTO hoses (circuit, type, compartment_id) VALUES (%s, %s, %s) RETURNING id",
        (circuit, htype, comp_id)
    )
    return jsonify(ok=True, id=hose_id)

@app.route('/api/hose/<int:hose_id>', methods=['DELETE'])
@login_required
@limiter.limit("30 per minute")
def delete_hose(hose_id):
    audit_log.info('DELETE hose id=%s ip=%s', hose_id, request.remote_addr)
    execute("DELETE FROM hoses WHERE id = %s", [hose_id])
    return jsonify(ok=True)

# ── Cable Recap ──
@app.route('/wiring/recap')
@login_required
def wiring_recap():
    # Total length per cable type
    type_totals = query("""
        SELECT type, COUNT(*) as circuits, SUM(length_m) as total_m
        FROM cables
        WHERE length_m IS NOT NULL AND length_m > 0
        GROUP BY type
        ORDER BY total_m DESC
    """)
    
    # Overall totals
    overall = query("""
        SELECT COUNT(*) as circuits, SUM(length_m) as total_m
        FROM cables
        WHERE length_m IS NOT NULL AND length_m > 0
    """, one=True)
    
    # Missing lengths count
    missing = query("""
        SELECT COUNT(*) as n FROM cables WHERE length_m IS NULL OR length_m = 0
    """, one=True)
    
    content = """
<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
  <div style="font-size:18px; font-weight:700;">Cable Recap</div>
  <a href="/wiring" style="font-size:13px;">← Back to Wiring</a>
</div>

<div class="stats">
  <div class="stat"><div class="num" style="color:var(--blue)">""" + str(overall['circuits'] or 0) + """</div><div class="label">Circuits</div></div>
  <div class="stat"><div class="num cost" style="color:var(--green)">""" + str(int(overall['total_m'] or 0)) + """m</div><div class="label">Total Length</div></div>
  <div class="stat"><div class="num" style="color:var(--orange)">""" + str(missing['n'] or 0) + """</div><div class="label">Missing</div></div>
</div>

<div class="section-title">By Cable Type</div>
<div class="table-wrap">
<table>
<thead><tr><th>Type</th><th>Circuits</th><th>Total (m)</th><th>Avg (m)</th></tr></thead>
<tbody>
"""
    for t in type_totals:
        avg = round(t['total_m'] / t['circuits'], 1) if t['circuits'] else 0
        content += """
<tr>
  <td><span class="badge badge-""" + badge_class(t['type']) + """">""" + t['type'] + """</span></td>
  <td>""" + str(t['circuits']) + """</td>
  <td class="cost" style="font-weight:600;">""" + str(int(t['total_m'])) + """ m</td>
  <td>""" + str(avg) + """ m</td>
</tr>
"""
    content += """
</tbody></table></div>

<div class="section-title">Per-Circuit Detail</div>
"""
    # Detailed breakdown by type
    for t in type_totals:
        circuits = query("""
            SELECT circuit, compartment, from_location, to_location, length_m
            FROM cables
            WHERE type = %s AND length_m IS NOT NULL AND length_m > 0
            ORDER BY length_m DESC
        """, [t['type']])
        
        content += """
<div class="card" style="margin-bottom:8px;">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
    <span class="badge badge-""" + badge_class(t['type']) + """">""" + t['type'] + """</span>
    <span style="font-size:12px; color:var(--text2);">""" + str(len(circuits)) + """ circuits · """ + str(int(t['total_m'])) + """m total</span>
  </div>
  <div style="font-size:12px; line-height:1.6;">
"""
        for c in circuits:
            content += """    <div style="display:flex; justify-content:space-between; padding:2px 0; border-bottom:1px solid var(--border);">
      <span>""" + c['circuit'] + """ (""" + (c['from_location'] or '?') + """ → """ + (c['to_location'] or '?') + """)</span>
      <span class="cost" style="font-weight:600;">""" + str(c['length_m']) + """m</span>
    </div>
"""
        content += """  </div>
</div>
"""
    
    return render_template_string(BASE_TEMPLATE, page='wiring', content=content)

@app.route('/settings')
@login_required
def settings_page():
    content = """
<div style="margin-bottom:12px;">
  <a href="/" style="font-size:13px;">← Back to dashboard</a>
</div>

<div class="card">
  <div style="font-size:18px; font-weight:700; margin-bottom:16px;">Settings</div>

  <div style="margin-bottom:20px;">
    <div style="font-size:14px; font-weight:600; margin-bottom:8px;">Theme</div>
    <div style="display:flex; gap:8px;">
      <button id="btn-dark" onclick="setTheme('dark')" style="flex:1; padding:10px; border-radius:6px; border:1px solid var(--border); background:var(--surface2); color:var(--text); cursor:pointer;">
        🌙 Dark
      </button>
      <button id="btn-light" onclick="setTheme('light')" style="flex:1; padding:10px; border-radius:6px; border:1px solid var(--border); background:var(--surface2); color:var(--text); cursor:pointer;">
        ☀️ Light
      </button>
    </div>
  </div>

  <form method="POST" action="/logout" style="margin-top:16px;">
    <button type="submit" style="width:100%;padding:10px;border-radius:6px;border:1px solid var(--red);background:transparent;color:var(--red);cursor:pointer;font-weight:600;">Log Out</button>
  </form>
</div>

<script>
function setTheme(t){
  if(t==='light'){
    document.documentElement.setAttribute('data-theme','light');
    localStorage.setItem('theme','light');
  } else {
    document.documentElement.removeAttribute('data-theme');
    localStorage.setItem('theme','dark');
  }
  updateButtons();
}
function updateButtons(){
  var isLight = document.documentElement.getAttribute('data-theme') === 'light';
  document.getElementById('btn-dark').style.borderColor = isLight ? 'var(--border)' : 'var(--blue)';
  document.getElementById('btn-dark').style.background = isLight ? 'var(--surface2)' : 'var(--surface1)';
  document.getElementById('btn-light').style.borderColor = isLight ? 'var(--blue)' : 'var(--border)';
  document.getElementById('btn-light').style.background = isLight ? 'var(--surface1)' : 'var(--surface2)';
}
updateButtons();
</script>
"""
    return render_template_string(BASE_TEMPLATE, page='settings', content=content)

# ── Run ──
# When run directly (development), use Werkzeug. Production uses gunicorn.
if __name__ == '__main__':
    print("⚓ Libertaire Refit Manager (dev server)")
    print(f"   https://0.0.0.0:{PORT}")
    print("   For production, use: gunicorn --bind 0.0.0.0:8080 refit_app:app")
    ssl_context = None
    if USE_HTTPS and os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH):
        ssl_context = (CERT_PATH, KEY_PATH)
        print(f"   SSL: {CERT_PATH}")
    app.run(host='0.0.0.0', port=PORT, debug=False, ssl_context=ssl_context, threaded=True)
