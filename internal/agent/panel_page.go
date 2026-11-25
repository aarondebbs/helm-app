package agent

// panelPage is the small status window that opens when the tray or menu-bar icon is clicked. It uses the same colours,
// corners and type as the Helm console. The agent serves it on the loopback address; it has no external files.
const panelPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Helm</title>
<style>
:root{color-scheme:light;--bg:#f0f4f4;--panel:#fff;--panel2:#e8eeee;--text:#17201e;--text2:#3c4a47;--muted:#66756f;--line:#dae1de;--accent:#0d7a70;--accent-hover:#09605a;--accent-soft:#dcf1ee;--accent-text:#fff;--ok:#1b8348;--ok-soft:#e1f2e7;--warn:#9a5f08;--warn-soft:#fbf0d9;--bad:#b93228;--bad-soft:#fbe6e3;--side:#15211f}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#0a0e13;--panel:#11171e;--panel2:#18202a;--text:#e6eeec;--text2:#b8c6c2;--muted:#8a9c97;--line:#232d38;--accent:#5fd0c4;--accent-hover:#7fe0d5;--accent-soft:#12302d;--accent-text:#06211e;--ok:#5fcf8f;--ok-soft:#12301f;--warn:#e0b050;--warn-soft:#33270c;--bad:#ee7b70;--bad-soft:#3a1a17}}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--text);font:14px/1.45 "Inter","Segoe UI",system-ui,-apple-system,"SF Pro Text",sans-serif;display:flex;flex-direction:column;-webkit-font-smoothing:antialiased;user-select:none;-webkit-user-select:none}
header{background:var(--side);color:#fff;padding:14px 18px;display:flex;align-items:center;gap:11px;min-height:56px}
header svg{width:24px;height:24px;color:var(--ac,#5fd0c4);flex:none}
#logo{height:26px;max-width:110px;object-fit:contain;flex:none}
#org{font-weight:650;font-size:15px;letter-spacing:-.01em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
main{flex:1;padding:16px;display:flex;flex-direction:column;gap:12px;overflow:auto}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:0 1px 2px rgba(15,30,28,.05)}
.status{padding:16px 18px;display:flex;gap:14px;align-items:center}
.dot{width:12px;height:12px;border-radius:50%;background:var(--muted);flex:none}
.ok .dot{background:var(--ok);box-shadow:0 0 0 5px var(--ok-soft)}.warn .dot{background:var(--warn);box-shadow:0 0 0 5px var(--warn-soft)}.bad .dot{background:var(--bad);box-shadow:0 0 0 5px var(--bad-soft)}
.status b{display:block;font-size:16px;font-weight:650;letter-spacing:-.01em}.status span{color:var(--muted);font-size:13px}
dl{margin:0;padding:4px 18px}dl div{display:flex;justify-content:space-between;gap:16px;padding:9px 0;border-bottom:1px solid var(--line)}dl div:last-child{border:0}
dt{color:var(--muted)}dd{margin:0;font-weight:550;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.note{padding:12px 18px;color:var(--text2);background:var(--accent-soft);border-radius:12px;font-size:13px}
.acts{display:flex;flex-direction:column;gap:8px}
button,a.btn{font:600 14px inherit;font-family:inherit;border-radius:8px;padding:10px 14px;border:1px solid var(--line);background:var(--panel);color:var(--text);cursor:pointer;text-align:center;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:8px;transition:background .12s,border-color .12s}
button:hover,a.btn:hover{border-color:var(--accent)}
.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-text)}.primary:hover{background:var(--accent-hover);border-color:var(--accent-hover)}
button:disabled{opacity:.5;cursor:not-allowed}
.count{background:var(--accent);color:var(--accent-text);font-size:11px;font-weight:650;padding:0 7px;border-radius:999px;line-height:18px}.primary .count{background:var(--accent-text);color:var(--accent)}
#msg{min-height:18px;font-size:13px;color:var(--muted);text-align:center}
footer{padding:0 16px 14px;color:var(--muted);font-size:12px;text-align:center}
</style></head><body>
<header><svg id="mark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="2.2" fill="currentColor"/><path d="M12 3v4M12 17v4M3 12h4M17 12h4"/></svg><img id="logo" alt="" hidden><span id="org">Helm</span></header>
<main>
<div class="card status" id="st"><span class="dot"></span><div><b id="head">Checking…</b><span id="sub"></span></div></div>
<div class="note" id="note" hidden></div>
<div class="card"><dl>
<div><dt>This computer</dt><dd id="pc">…</dd></div>
<div><dt>Managed by</dt><dd id="by">…</dd></div>
<div><dt>Agent version</dt><dd id="ver">…</dd></div>
</dl></div>
<div class="acts" id="acts" hidden>
<a class="btn primary" id="chat">Chat with support <span class="count" id="un" hidden></span></a>
<button id="sup" type="button">Request support</button>
</div>
<div id="msg"></div>
</main>
<footer>Helm keeps this computer updated and secure.</footer>
<script>
var base=location.pathname.replace(/\/$/,''),$=function(i){return document.getElementById(i)};
function draw(d){
  var cls=d.state==='connected'?'ok':(d.state==='offline'?'bad':'warn');
  $('st').className='card status '+cls;$('head').textContent=d.headline;$('sub').textContent=d.sub||'';
  $('org').textContent=d.org||'Helm';$('pc').textContent=d.computer||'';$('by').textContent=d.org||d.server||'';$('ver').textContent=d.version||'';
  if(d.logo){var l=$('logo');if(l.hidden){l.src=base+'/logo';l.hidden=false;$('mark').style.display='none'}}
  if(/^#[0-9a-fA-F]{6}$/.test(d.accent||''))document.documentElement.style.setProperty('--ac',d.accent);
  $('note').hidden=!d.supportText;$('note').textContent=d.supportText||'';
  $('acts').hidden=!d.allowSupport;$('chat').href=d.chatUrl||'#';
  $('un').hidden=!d.unread;$('un').textContent=d.unread||'';
  $('sup').disabled=d.state!=='connected';
}
function poll(){fetch(base+'/s',{cache:'no-store'}).then(function(r){return r.json()}).then(draw).catch(function(){draw({state:'offline',headline:'The Helm agent is not running',sub:'It starts by itself with this computer.'})})}
$('sup').onclick=function(){var b=this;b.disabled=true;$('msg').textContent='';
  fetch(base+'/support',{method:'POST',headers:{'X-Helm-Chat':'1','Content-Type':'application/json'},body:'{}'}).then(function(r){
    $('msg').textContent=r.status===204?'Sent. Your administrator will see it in Helm.':r.status===429?'A request was sent a moment ago. Please wait a minute.':'Could not send: this computer is not connected right now.'
  }).catch(function(){$('msg').textContent='Could not reach the Helm agent.'}).then(function(){setTimeout(poll,500)})};
poll();setInterval(poll,3000);
</script></body></html>`
