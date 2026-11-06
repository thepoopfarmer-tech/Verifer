import csv
import hmac
import io
import os

from flask import Flask, jsonify, request, Response

import db
import worker

SENDER = os.environ.get("SENDER", "verify@example.com")
HELO_DOMAIN = os.environ.get("HELO_DOMAIN", "example.com")
ACCESS_KEY = os.environ.get("ACCESS_KEY", "")
MAX_UPLOAD = int(os.environ.get("MAX_UPLOAD", "10000"))

app = Flask(__name__)
db.init_db()
_worker = worker.Worker(sender=SENDER, helo_domain=HELO_DOMAIN)
_worker.start()


def authorized():
    if not ACCESS_KEY:
        return False
    supplied = request.headers.get("X-Access-Key", "")
    return hmac.compare_digest(supplied.encode(), ACCESS_KEY.encode())


@app.get("/")
def index():
    return INDEX_HTML


@app.post("/api/upload")
def upload():
    if not authorized():
        return jsonify(error="Unauthorized"), 401
    data = request.get_json(silent=True) or {}
    raw = data.get("emails", [])
    if not isinstance(raw, list):
        return jsonify(error="emails must be a list"), 400
    if len(raw) > MAX_UPLOAD:
        return jsonify(error=f"Max {MAX_UPLOAD} per upload"), 400
    added = db.add_emails(raw)
    return jsonify(added=added, total_submitted=len(raw))


@app.get("/api/status")
def status():
    if not authorized():
        return jsonify(error="Unauthorized"), 401
    count_today, cap_today = db.daily_status()
    return jsonify(
        total=db.total_count(),
        pending=db.pending_count(),
        by_status=db.status_counts(),
        daily_count=count_today,
        daily_cap=cap_today,
    )


@app.post("/api/refresh")
def refresh():
    """Call on page load/refresh: sweeps newly confirmed VALID results into
    a fresh batch, then returns every batch so far."""
    if not authorized():
        return jsonify(error="Unauthorized"), 401
    db.sweep_new_batch()
    return jsonify(batches=db.list_batches())


@app.post("/api/batch/<int:batch_id>/copied")
def batch_copied(batch_id):
    if not authorized():
        return jsonify(error="Unauthorized"), 401
    db.mark_batch_copied(batch_id)
    return jsonify(ok=True)


@app.get("/api/other/<status_name>")
def other_status(status_name):
    if not authorized():
        return jsonify(error="Unauthorized"), 401
    allowed = {"CATCH_ALL", "TEMPORARY", "BLOCKED", "UNREACHABLE", "INVALID",
               "NO_MX", "SYNTAX_INVALID"}
    if status_name not in allowed:
        return jsonify(error="unknown status"), 400
    return jsonify(results=db.results_by_status(status_name))


@app.get("/api/download")
def download():
    if not authorized():
        return jsonify(error="Unauthorized"), 401
    rows = db.all_results_csv_rows()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Email", "Status", "Confidence", "Detail"])
    for r in rows:
        w.writerow([r["email"], r["status"], r["confidence"], r["detail"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                     headers={"Content-Disposition": "attachment; filename=results.csv"})


INDEX_HTML = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Email Verifier</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--muted:#6b6b6b;--card:#f4f4f2;--line:#ddd;--accent:#2b5fd9;--ok:#1f8a4c}
@media (prefers-color-scheme:dark){:root{--bg:#161616;--fg:#eee;--muted:#999;--card:#222;--line:#333;--accent:#6c9bff;--ok:#2fae66}}
*{box-sizing:border-box}
body{margin:0;padding:16px;background:var(--bg);color:var(--fg);font:16px/1.4 system-ui,sans-serif;max-width:640px;margin:auto}
h1{font-size:20px;margin:0 0 12px}
textarea,input{width:100%;padding:12px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--fg);font:inherit;margin-bottom:10px}
textarea{min-height:120px}
button{width:100%;padding:14px;border:0;border-radius:10px;background:var(--accent);color:#fff;font:600 16px system-ui;margin-bottom:8px}
button.sec{background:var(--card);color:var(--fg);border:1px solid var(--line)}
button.copy{width:auto;padding:8px 14px;font-size:14px;margin:0}
#msg{color:var(--muted);margin:8px 0;font-size:14px}
.statrow{display:flex;justify-content:space-between;background:var(--card);border-radius:10px;padding:10px 14px;margin-bottom:12px;font-size:14px;color:var(--muted)}
.tabs{display:flex;gap:6px;margin:14px 0 10px;overflow-x:auto}
.tab{padding:8px 12px;border-radius:999px;background:var(--card);border:1px solid var(--line);font-size:14px;white-space:nowrap}
.tab.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.batch{border:1px solid var(--line);border-radius:12px;padding:12px;margin-bottom:12px}
.batch.copied{opacity:.5}
.batch-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.batch-title{font-weight:600;font-size:14px}
.batch-list{font-size:14px;line-height:1.6;word-break:break-all;white-space:pre-wrap;color:var(--fg)}
.badge{font-size:12px;font-weight:700;padding:2px 8px;border-radius:99px;color:#fff;background:var(--muted)}
.row{background:var(--card);border-radius:10px;padding:10px 12px;margin-top:8px;font-size:14px}
.row .em{font-weight:600;word-break:break-all}
.row .det{color:var(--muted);font-size:12px;margin-top:2px}
</style></head><body>
<h1>Email Verifier</h1>
<input id="key" type="password" placeholder="Access key" autocomplete="off">
<textarea id="list" placeholder="One email per line (or comma-separated)"></textarea>
<button id="go">Add to queue</button>
<div id="msg"></div>
<div class="statrow" id="stats"></div>

<div class="tabs">
  <div class="tab active" data-tab="confirmed">Confirmed</div>
  <div class="tab" data-tab="other">Can't tell / Invalid</div>
</div>

<div id="confirmed"></div>
<div id="other" style="display:none"></div>
<button class="sec" id="dl">Download everything as CSV</button>

<script>
const $=id=>document.getElementById(id);
$('key').value=localStorage.getItem('k')||'';
async function call(url,opts={}){
  localStorage.setItem('k',$('key').value);
  const r=await fetch(url,{...opts,headers:{'Content-Type':'application/json','X-Access-Key':$('key').value}});
  const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j;
}
$('go').onclick=async()=>{
  const emails=$('list').value.split(/[\\n,;\\s]+/).filter(Boolean);
  if(!emails.length){$('msg').textContent='Enter at least one email.';return}
  $('go').disabled=true;$('msg').textContent='Adding '+emails.length+' to the queue...';
  try{
    const j=await call('/api/upload',{method:'POST',body:JSON.stringify({emails})});
    $('msg').textContent='Added '+j.added+' new addresses. The checker will work through them in the background — you can close this page.';
    $('list').value='';
  }catch(e){$('msg').textContent='Error: '+e.message}
  $('go').disabled=false;
  refreshAll();
};
document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
  t.classList.add('active');
  $('confirmed').style.display=t.dataset.tab==='confirmed'?'block':'none';
  $('other').style.display=t.dataset.tab==='other'?'block':'none';
  if(t.dataset.tab==='other')loadOther();
});
async function loadStats(){
  try{
    const s=await call('/api/status');
    $('stats').innerHTML='<span>'+s.pending+' left in queue</span><span>'+s.daily_count+' / '+s.daily_cap+' today</span>';
  }catch(e){}
}
async function loadBatches(){
  try{
    const j=await call('/api/refresh',{method:'POST'});
    const c=$('confirmed');c.replaceChildren();
    if(!j.batches.length){c.innerHTML='<div class="row">Nothing confirmed yet.</div>';return}
    for(const b of j.batches){
      const d=document.createElement('div');d.className='batch'+(b.copied?' copied':'');
      const when=new Date(b.created_at*1000).toLocaleString();
      d.innerHTML='<div class="batch-head"><span class="batch-title">'+when+' — '+b.emails.length+' emails</span>'+
        (b.copied?'<span class="badge">Copied</span>':'<button class="copy">Copy</button>')+'</div>'+
        '<div class="batch-list">'+b.emails.join('\\n')+'</div>';
      if(!b.copied){
        d.querySelector('.copy').onclick=async()=>{
          try{await navigator.clipboard.writeText(b.emails.join('\\n'));
            await call('/api/batch/'+b.id+'/copied',{method:'POST'});
            loadBatches();
          }catch(e){$('msg').textContent='Copy failed: '+e.message}
        };
      }
      c.append(d);
    }
  }catch(e){$('confirmed').innerHTML='<div class="row">Error: '+e.message+'</div>'}
}
async function loadOther(){
  const el=$('other');el.innerHTML='Loading...';
  const statuses=['CATCH_ALL','TEMPORARY','BLOCKED','UNREACHABLE','INVALID','NO_MX','SYNTAX_INVALID'];
  let html='';
  for(const s of statuses){
    try{
      const j=await call('/api/other/'+s);
      for(const r of j.results.slice(0,50)){
        html+='<div class="row"><div class="em">'+r.email+'</div><div class="det">'+r.status+' — '+(r.detail||'').slice(0,80)+'</div></div>';
      }
    }catch(e){}
  }
  el.innerHTML=html||'<div class="row">Nothing here yet.</div>';
}
$('dl').onclick=()=>{
  const k=encodeURIComponent($('key').value);
  window.open('/api/download?k='+k,'_blank'); // key also sent via header below for same-tab fetch fallback
  // Most mobile browsers won't attach custom headers to a plain link, so fetch+blob instead:
};
$('dl').onclick=async()=>{
  try{
    const r=await fetch('/api/download',{headers:{'X-Access-Key':$('key').value}});
    const blob=await r.blob();
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');a.href=url;a.download='results.csv';a.click();
  }catch(e){$('msg').textContent='Download failed: '+e.message}
};
function refreshAll(){loadStats();loadBatches();}
refreshAll();
setInterval(refreshAll,15000);
</script></body></html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
