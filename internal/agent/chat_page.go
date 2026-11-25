package agent

// chatPage is the small chat window the tray opens. It has no external files: the agent serves it on the loopback address.
const chatPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Chat with support</title>
<style>
:root{--bg:#0f1519;--panel:#151d22;--line:#243038;--ink:#e8eef0;--mute:#8da0a8;--accent:#5fd0c4;--accent-ink:#06211e;--me:#1c3b38}
@media (prefers-color-scheme:light){:root{--bg:#f6f8f8;--panel:#fff;--line:#dbe3e5;--ink:#162023;--mute:#5b6e74;--accent:#0f8f84;--accent-ink:#fff;--me:#dff3f0}}
*{box-sizing:border-box}html,body{height:100%;margin:0}
body{display:flex;flex-direction:column;background:var(--bg);color:var(--ink);font:14px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif}
header{padding:12px 16px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px;background:var(--panel)}
header b{font-weight:600;font-size:15px}#logo{height:24px;max-width:96px;object-fit:contain}
#dot{width:8px;height:8px;border-radius:50%;background:var(--mute)}#dot.on{background:var(--accent)}
#state{color:var(--mute);font-size:12px;margin-left:auto}
#log{flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:10px}
.m{max-width:86%;padding:8px 12px;border-radius:12px;white-space:pre-wrap;word-wrap:break-word;overflow-wrap:anywhere}
.m.admin{align-self:flex-start;background:var(--panel);border:1px solid var(--line);border-bottom-left-radius:4px}
.m.user{align-self:flex-end;background:var(--me);border-bottom-right-radius:4px}
.t{display:block;margin-top:2px;font-size:11px;color:var(--mute)}
#empty{margin:auto;text-align:center;color:var(--mute);max-width:24em}
form{display:flex;gap:8px;padding:12px;border-top:1px solid var(--line);background:var(--panel)}
textarea{flex:1;resize:none;height:42px;max-height:110px;padding:9px 11px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--ink);font:inherit}
textarea:focus{outline:2px solid var(--accent);outline-offset:-1px}
button{border:0;border-radius:10px;padding:0 16px;background:var(--accent);color:var(--accent-ink);font:600 14px inherit;cursor:pointer}
button:disabled,textarea:disabled{opacity:.5;cursor:not-allowed}
#err{color:#e5736a;font-size:12px;padding:0 16px 8px;min-height:0}
</style></head><body>
<header><img id="logo" alt="" hidden><span id="dot"></span><b id="title">Chat with support</b><span id="state">Connecting…</span></header>
<div id="log"><div id="empty">Write to the person who looks after this PC. They will see your message in Helm.</div></div>
<div id="err"></div>
<form id="f"><textarea id="t" rows="1" maxlength="2000" placeholder="Write a message" autofocus></textarea><button id="s" type="submit">Send</button></form>
<script>
var base=location.pathname.replace(/\/$/,''),log=document.getElementById('log'),t=document.getElementById('t'),s=document.getElementById('s'),err=document.getElementById('err'),last='';
function esc(x){return String(x).replace(/[&<>]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;'}[c]})}
function hm(iso){var d=new Date(iso);return d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}
function draw(d){
  document.getElementById('dot').className=d.online?'on':'';
  document.getElementById('state').textContent=d.enabled===false?'Chat is turned off':d.online?'Connected':'Not connected';
  if(d.logo){var lg=document.getElementById('logo');if(lg.hidden){lg.src=base+'/logo';lg.hidden=false}}
  if(/^#[0-9a-fA-F]{6}$/.test(d.accent||'')){var c=d.accent,r=parseInt(c.substr(1,2),16),g=parseInt(c.substr(3,2),16),b=parseInt(c.substr(5,2),16),st=document.documentElement.style;st.setProperty('--accent',c);st.setProperty('--accent-ink',(0.299*r+0.587*g+0.114*b)>150?'#10181a':'#ffffff')}
  if(d.org)document.getElementById('title').textContent=d.org+' support';
  t.disabled=s.disabled=!d.online||d.enabled===false;
  var sig=JSON.stringify(d.messages);if(sig===last)return;last=sig;
  var near=log.scrollHeight-log.scrollTop-log.clientHeight<80;
  if(!d.messages.length){log.innerHTML='<div id="empty">Write to the person who looks after this PC. They will see your message in Helm.</div>';return}
  log.innerHTML=d.messages.map(function(m){return '<div class="m '+m.from+'">'+esc(m.text)+'<span class="t">'+(m.from==='admin'?'Support · ':'')+hm(m.at)+'</span></div>'}).join('');
  if(near||!log.dataset.seen){log.scrollTop=log.scrollHeight;log.dataset.seen=1}
}
function poll(){fetch(base+'/m',{cache:'no-store'}).then(function(r){return r.json()}).then(draw).catch(function(){document.getElementById('state').textContent='Not connected'})}
document.getElementById('f').onsubmit=function(e){e.preventDefault();var v=t.value.trim();if(!v)return;s.disabled=true;err.textContent='';
  fetch(base+'/send',{method:'POST',headers:{'X-Helm-Chat':'1','Content-Type':'application/json'},body:JSON.stringify({text:v})}).then(function(r){
    if(r.status===204){t.value='';t.style.height='';poll()}else return r.text().then(function(x){err.textContent=x.trim()||'Could not send'})
  }).catch(function(){err.textContent='Could not reach the Helm agent'}).then(function(){s.disabled=false;t.focus()})};
t.onkeydown=function(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();document.getElementById('f').requestSubmit()}};
t.oninput=function(){t.style.height='42px';t.style.height=Math.min(110,t.scrollHeight)+'px'};
poll();setInterval(poll,2000);
</script></body></html>`
