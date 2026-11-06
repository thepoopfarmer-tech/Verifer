import datetime
import json
import sqlite3
import threading
import time

DB_PATH = "verifier.db"
_lock = threading.Lock()


def _conn():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.execute("PRAGMA journal_mode=WAL")
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _lock, _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            domain TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            detail TEXT DEFAULT '',
            confidence TEXT DEFAULT '',
            created_at REAL NOT NULL,
            finished_at REAL,
            batch_id INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
        CREATE INDEX IF NOT EXISTS idx_jobs_domain ON jobs(domain);

        CREATE TABLE IF NOT EXISTS domain_state (
            group_name TEXT PRIMARY KEY,
            interval REAL NOT NULL,
            next_allowed_at REAL NOT NULL DEFAULT 0,
            consecutive_success INTEGER NOT NULL DEFAULT 0,
            consecutive_fail INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS domain_cache (
            domain TEXT PRIMARY KEY,
            mx_json TEXT,
            catchall INTEGER
        );

        CREATE TABLE IF NOT EXISTS batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at REAL NOT NULL,
            copied INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        """)


# ---------- jobs ----------

def add_emails(emails):
    now = time.time()
    added = 0
    with _lock, _conn() as c:
        for e in emails:
            e = e.strip()
            if not e:
                continue
            domain = e.rsplit("@", 1)[-1].lower() if "@" in e else ""
            try:
                c.execute(
                    "INSERT INTO jobs (email, domain, status, created_at) "
                    "VALUES (?, ?, 'PENDING', ?)",
                    (e, domain, now),
                )
                added += 1
            except sqlite3.IntegrityError:
                pass  # already queued or checked before
    return added


def next_pending_for_group(group_name, domains_in_group):
    with _lock, _conn() as c:
        placeholders = ",".join("?" * len(domains_in_group))
        row = c.execute(
            f"SELECT * FROM jobs WHERE status='PENDING' AND domain IN ({placeholders}) "
            f"ORDER BY created_at LIMIT 1",
            domains_in_group,
        ).fetchone()
        return dict(row) if row else None


def all_pending_domains():
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT DISTINCT domain FROM jobs WHERE status='PENDING'"
        ).fetchall()
        return [r["domain"] for r in rows]


def mark_in_progress(job_id):
    with _lock, _conn() as c:
        c.execute("UPDATE jobs SET status='CHECKING' WHERE id=?", (job_id,))


def finish_job(job_id, status, detail, confidence):
    with _lock, _conn() as c:
        c.execute(
            "UPDATE jobs SET status=?, detail=?, confidence=?, finished_at=? WHERE id=?",
            (status, detail, confidence, time.time(), job_id),
        )


def pending_count():
    with _lock, _conn() as c:
        return c.execute("SELECT COUNT(*) n FROM jobs WHERE status IN ('PENDING','CHECKING')").fetchone()["n"]


def total_count():
    with _lock, _conn() as c:
        return c.execute("SELECT COUNT(*) n FROM jobs").fetchone()["n"]


def status_counts():
    with _lock, _conn() as c:
        rows = c.execute("SELECT status, COUNT(*) n FROM jobs GROUP BY status").fetchall()
        return {r["status"]: r["n"] for r in rows}


# ---------- domain pacing ----------

DEFAULT_INTERVAL = {"outlook": 45.0}
MIN_INTERVAL = {"outlook": 20.0}
MAX_INTERVAL = {"outlook": 3600.0}
DEFAULT_FALLBACK_INTERVAL = 5.0
MIN_FALLBACK_INTERVAL = 2.0
MAX_FALLBACK_INTERVAL = 600.0


def _bounds(group_name):
    lo = MIN_INTERVAL.get(group_name, MIN_FALLBACK_INTERVAL)
    hi = MAX_INTERVAL.get(group_name, MAX_FALLBACK_INTERVAL)
    start = DEFAULT_INTERVAL.get(group_name, DEFAULT_FALLBACK_INTERVAL)
    return lo, hi, start


def get_domain_state(group_name):
    lo, hi, start = _bounds(group_name)
    with _lock, _conn() as c:
        row = c.execute("SELECT * FROM domain_state WHERE group_name=?", (group_name,)).fetchone()
        if row:
            return dict(row)
        c.execute(
            "INSERT INTO domain_state (group_name, interval, next_allowed_at) VALUES (?, ?, 0)",
            (group_name, start),
        )
        return {"group_name": group_name, "interval": start, "next_allowed_at": 0,
                "consecutive_success": 0, "consecutive_fail": 0}


def record_outcome(group_name, is_temp_or_blocked):
    """Adaptive pacing: speed up slowly on clean runs, back off hard on trouble."""
    lo, hi, _ = _bounds(group_name)
    state = get_domain_state(group_name)
    interval = state["interval"]
    succ = state["consecutive_success"]
    fail = state["consecutive_fail"]

    if is_temp_or_blocked:
        fail += 1
        succ = 0
        interval = min(interval * 3, hi)
    else:
        succ += 1
        fail = 0
        if succ % 5 == 0:
            interval = max(interval * 0.85, lo)

    next_allowed = time.time() + interval
    with _lock, _conn() as c:
        c.execute(
            "UPDATE domain_state SET interval=?, next_allowed_at=?, "
            "consecutive_success=?, consecutive_fail=? WHERE group_name=?",
            (interval, next_allowed, succ, fail, group_name),
        )


def group_ready(group_name):
    state = get_domain_state(group_name)
    return time.time() >= state["next_allowed_at"]


# ---------- MX / catch-all cache ----------

def mx_cache_get(domain):
    with _lock, _conn() as c:
        row = c.execute("SELECT mx_json FROM domain_cache WHERE domain=?", (domain,)).fetchone()
        if row and row["mx_json"] is not None:
            return json.loads(row["mx_json"])
        return None


def mx_cache_set(domain, hosts):
    with _lock, _conn() as c:
        c.execute(
            "INSERT INTO domain_cache (domain, mx_json) VALUES (?, ?) "
            "ON CONFLICT(domain) DO UPDATE SET mx_json=excluded.mx_json",
            (domain, json.dumps(hosts)),
        )


def catchall_cache_get(domain):
    with _lock, _conn() as c:
        row = c.execute("SELECT catchall FROM domain_cache WHERE domain=?", (domain,)).fetchone()
        if row and row["catchall"] is not None:
            return bool(row["catchall"])
        return None


def catchall_cache_set(domain, value):
    with _lock, _conn() as c:
        c.execute(
            "INSERT INTO domain_cache (domain, catchall) VALUES (?, ?) "
            "ON CONFLICT(domain) DO UPDATE SET catchall=excluded.catchall",
            (domain, int(value)),
        )


# ---------- daily warm-up cap ----------

def _today():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d")


def _meta_get(key, default=None):
    with _lock, _conn() as c:
        row = c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default


def _meta_set(key, value):
    with _lock, _conn() as c:
        c.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )


def daily_status():
    """Returns (count_today, cap_today). Rolls over and raises the cap once
    a day, as long as that's been called (i.e. the app has run)."""
    today = _today()
    stored_day = _meta_get("daily_day")
    if stored_day != today:
        prev_cap = float(_meta_get("daily_cap", 200))
        new_cap = min(prev_cap + 200, 5000)
        _meta_set("daily_day", today)
        _meta_set("daily_count", 0)
        _meta_set("daily_cap", new_cap)
    count = int(float(_meta_get("daily_count", 0)))
    cap = float(_meta_get("daily_cap", 200))
    return count, cap


def daily_increment():
    count, _ = daily_status()
    _meta_set("daily_count", count + 1)


# ---------- batches (the results window) ----------

def sweep_new_batch():
    """Collect any VALID results not yet in a batch into one new batch.
    Returns the new batch id, or None if there was nothing new."""
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT id FROM jobs WHERE status='VALID' AND batch_id IS NULL"
        ).fetchall()
        if not rows:
            return None
        cur = c.execute("INSERT INTO batches (created_at) VALUES (?)", (time.time(),))
        batch_id = cur.lastrowid
        ids = [r["id"] for r in rows]
        c.executemany("UPDATE jobs SET batch_id=? WHERE id=?", [(batch_id, i) for i in ids])
        return batch_id


def list_batches():
    with _lock, _conn() as c:
        batches = c.execute("SELECT * FROM batches ORDER BY id DESC").fetchall()
        result = []
        for b in batches:
            emails = c.execute(
                "SELECT email FROM jobs WHERE batch_id=? ORDER BY email", (b["id"],)
            ).fetchall()
            result.append({
                "id": b["id"],
                "created_at": b["created_at"],
                "copied": bool(b["copied"]),
                "emails": [e["email"] for e in emails],
            })
        return result


def mark_batch_copied(batch_id):
    with _lock, _conn() as c:
        c.execute("UPDATE batches SET copied=1 WHERE id=?", (batch_id,))


def results_by_status(status, limit=500):
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT email, status, detail, confidence FROM jobs WHERE status=? "
            "ORDER BY finished_at DESC LIMIT ?",
            (status, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def all_results_csv_rows():
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT email, status, confidence, detail FROM jobs "
            "WHERE status NOT IN ('PENDING','CHECKING') ORDER BY email"
        ).fetchall()
        return [dict(r) for r in rows]
