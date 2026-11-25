'use strict';
/* Helm console: chat with the person at a PC. The thread is shared by the Inbox page and each PC's Chat tab. */

const chatDay = t => { const d = new Date(t), n = new Date(); return d.toDateString() === n.toDateString() ? 'Today' : new Date(n - 864e5).toDateString() === d.toDateString() ? 'Yesterday' : d.toLocaleDateString([], { day: 'numeric', month: 'long' }); };
const chatClock = t => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

// One conversation: messages on top, a composer underneath. It polls while it is on screen.
function chatThread(id, name, opt) {
  opt = opt || {};
  const log = h('div', { class: 'bubbles', role: 'log', 'aria-live': 'polite' });
  const box = h('textarea', { rows: 1, maxLength: 2000, placeholder: 'Write to ' + name, 'aria-label': 'Message' });
  const state = h('span', { class: 'muted small-text' });
  let sig = '', alive = true, online = false;
  const send = async () => {
    const text = box.value.trim(); if (!text) return;
    box.value = ''; box.style.height = '';
    try { await api('POST', `/api/devices/${id}/chat`, { text }); await load(true); } catch (e) { box.value = text; throw e; }
  };
  const sendBtn = actionButton('Send', send, 'primary');
  const load = async force => {
    let r; try { r = await api('GET', `/api/devices/${id}/chat`); } catch (e) { return; }
    if (!alive) return;
    online = r.online;
    state.textContent = online ? 'Online. Messages arrive at once.' : 'Offline. Your message is delivered when the PC reconnects.';
    const s = JSON.stringify(r.messages);
    if (!force && s === sig) return; sig = s;
    const near = log.scrollHeight - log.scrollTop - log.clientHeight < 90;
    clear(log);
    if (!r.messages.length) log.append(h('div', { class: 'bubbles-empty' }, 'No messages yet. What you write appears in a small window on the PC, and replies come back here.'));
    let day = '';
    for (const m of r.messages) {
      const dl = chatDay(m.at); if (dl !== day) { day = dl; log.append(h('div', { class: 'bday' }, dl)); }
      log.append(h('div', { class: 'bubble ' + m.from }, h('div', { class: 'btext' }, m.text),
        h('div', { class: 'bmeta' }, chatClock(m.at) + (m.from === 'admin' ? (m.read ? ' · seen' : m.sent ? ' · delivered' : ' · waiting for the PC') : ''))));
    }
    if (near || force || !log.dataset.seen) { log.scrollTop = log.scrollHeight; log.dataset.seen = '1'; }
    if (opt.onRead) opt.onRead();
  };
  box.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendBtn.click(); } });
  box.addEventListener('input', () => { box.style.height = 'auto'; box.style.height = Math.min(140, box.scrollHeight) + 'px'; });
  const node = h('div', { class: 'thread' }, log, h('div', { class: 'composer' }, box, sendBtn), h('div', { class: 'composer-note' }, state));
  load(true);
  const t = setInterval(() => load(false), 3000);
  onLeave(() => { alive = false; clearInterval(t); });
  return { node, focus: () => box.focus(), stop: () => { alive = false; clearInterval(t); } };
}

route(/^\/inbox(?:\/([^/]+))?$/, viewInbox);
async function viewInbox(openId) {
  const my = routeToken;
  const list = h('div', { class: 'convs' }), pane = h('div', { class: 'convpane' });
  const wrap = h('div', { class: 'inbox' + (openId ? ' open' : '') }, h('aside', null, list), pane);
  shell('inbox', [pageHead('Inbox', 'Messages from the people at your PCs'), wrap]);
  let devs = []; try { devs = await getDevices(true); } catch (e) { /* api() reported it */ }
  let convs = [], thread = null;
  const nameOf = id => (devs.find(d => d.id === id) || {}).name || 'this PC';
  const drawList = () => {
    clear(list);
    const online = devs.filter(d => d.approved && d.online && !convs.some(c => c.deviceId === d.id));
    const pick = h('select', { 'aria-label': 'Start a chat', onchange: e => { if (e.target.value) location.hash = '#/inbox/' + e.target.value; } },
      h('option', { value: '' }, 'Start a chat with…'), online.map(d => h('option', { value: d.id }, d.name)));
    list.append(h('div', { class: 'convhead' }, pick));
    if (!convs.length) list.append(h('p', { class: 'muted small-text', style: { padding: '14px 4px' } }, 'No conversations yet. They start when you write to a PC, or when someone uses Chat with support in the Helm tray.'));
    for (const c of convs) {
      list.append(h('a', { class: 'conv' + (c.deviceId === openId ? ' on' : '') + (c.unread ? ' unread' : ''), href: '#/inbox/' + c.deviceId },
        h('span', { class: 'statusdot' + (c.online ? ' on' : '') }),
        h('span', { class: 'cmain' }, h('b', null, c.name), h('span', { class: 'cprev' }, (c.last.from === 'admin' ? 'You: ' : '') + c.last.text)),
        h('span', { class: 'cside' }, h('span', { class: 'muted small-text' }, fmtAgo(c.last.at)), c.unread ? h('span', { class: 'count' }, String(c.unread)) : null)));
    }
  };
  const loadList = async () => {
    try { const r = await api('GET', '/api/chat'); if (my !== routeToken) return; convs = r.conversations || []; setChatCount(r.unread); drawList(); } catch (e) { /* ignore */ }
  };
  if (openId) {
    clear(pane).append(h('div', { class: 'convtop' }, h('a', { class: 'back', href: '#/inbox' }, '← All chats'), h('h2', null, nameOf(openId)), h('a', { class: 'btn small', href: '#/d/' + openId }, 'Open PC')));
    thread = chatThread(openId, nameOf(openId), { onRead: loadList }); pane.append(thread.node); thread.focus();
  } else pane.append(emptyState('💬', 'Pick a conversation', 'Messages from your PCs show up on the left. Chats are kept for 30 days.'));
  await loadList(); every(5000, loadList);
}

// Chat tab on a PC's page.
function tabChat(body, dev, id) {
  if (!dev.online && !dev.approved) { body.append(h('div', { class: 'notice' }, 'Approve this PC first.')); return; }
  const t = chatThread(id, dev.name);
  body.append(h('div', { class: 'chatpage' }, t.node));
}
