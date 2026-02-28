let token = localStorage.getItem("token") || "";
let deviceId = localStorage.getItem("deviceId") || "";
let room = "global", ws = null, since = 0;

const $ = id => document.getElementById(id);
const msgs = $("msgs"), txt = $("txt");

function esc(s){ return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }

function renderContent(raw){
  let s = esc(raw);
  s = s.replace(/\|\|([\s\S]+?)\|\|/g, (_,t)=>`<span class="spoiler" data-spoiler="1">${t}</span>`);
  let cls="msg";
  if(/^##\s+/.test(s)){ cls="msg h2"; s=s.replace(/^##\s+/,""); }
  else if(/^#\s+/.test(s)){ cls="msg h1"; s=s.replace(/^#\s+/,""); }
  return { cls, html: s.replace(/\n/g,"<br>") };
}

function setMe(name){ $("me").textContent = name || "..."; }

function showPin(pin){
  const box = $("pinBox");
  if(!pin){ box.style.display="none"; box.textContent=""; return; }
  box.style.display="block";
  box.textContent = ` ${pin.username}: ${pin.content}  (id:${pin.message_id})`;
}

async function api(path, method="GET", body=null){
  const headers = {};
  if(token) headers.authorization = "Bearer " + token;
  if(body){ headers["content-type"]="application/json"; body=JSON.stringify(body); }
  const r = await fetch(path, { method, headers, body });
  const j = await r.json().catch(()=>({}));
  if(!r.ok) throw j;
  return j;
}

function addMsg(m){
  const d=document.createElement("div");
  d.className="m";
  const r=renderContent(m.content);
  const id = m.id != null ? m.id : "";
  const meta = id ? `<span class="meta">#${id}</span>` : "";
  d.innerHTML = `<div class="u"></div><div class="t ${r.cls}">${r.html}</div>`;
  d.querySelector(".u").innerHTML = `${esc(m.username)}${meta}`;
  msgs.appendChild(d);
  msgs.scrollTop = msgs.scrollHeight;
}

function clearMsgs(){ msgs.innerHTML=""; }

function connectWS(){
  if(ws) try{ws.close()}catch{}
  const proto = location.protocol==="https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws?room=${encodeURIComponent(room)}&token=${encodeURIComponent(token)}`);
  ws.onmessage = e=>{
    try{
      const m = JSON.parse(e.data);
      if(m.type==="pin"){ showPin(m.pin); return; }
      if(m.type==="msg"){ addMsg({ id:m.id, username:m.username, content:m.content }); return; }
    }catch{}
  };
}

async function loadHistory(){
  const r = await api(`/api/room/${encodeURIComponent(room)}/poll?since=0`);
  clearMsgs();
  since = r.last || 0;
  for(const m of (r.messages||[])) addMsg(m);
}

async function loadPin(){
  const r = await api(`/api/room/${encodeURIComponent(room)}/pinned`);
  showPin(r.pin);
}

async function boot(){
  if(!token) return false;
  try{
    const me = await api("/api/me");
    setMe(me.me.username);
    await loadPin();
    await loadHistory();
    connectWS();
    return true;
  }catch{
    token=""; localStorage.removeItem("token");
    setMe("...");
    return false;
  }
}

function genDeviceId(){
  const s = (crypto?.randomUUID ? crypto.randomUUID() : (Math.random().toString(16).slice(2)+Date.now())).replace(/-/g,"");
  return s.slice(0, 24);
}

async function autoGuest(){
  if(!deviceId){ deviceId = genDeviceId(); localStorage.setItem("deviceId", deviceId); }
  const username = "Guest" + Math.floor(Math.random()*9000+1000);
  const r = await api("/api/auth/guest","POST",{ username, deviceId });
  token = r.token;
  localStorage.setItem("token", token);
  localStorage.setItem("deviceId", r.deviceId || deviceId);
  setMe(r.user.username);
  await loadPin();
  await loadHistory();
  connectWS();
}

async function reg(){
  const username = prompt("New username?");
  const password = prompt("New password (>=6)?");
  const r = await api("/api/auth/register","POST",{ username, password });
  token = r.token;
  localStorage.setItem("token", token);
  setMe(r.user.username);
  await loadPin(); await loadHistory(); connectWS();
}

async function login(){
  const username = prompt("Username?");
  const password = prompt("Password?");
  const r = await api("/api/auth/login","POST",{ username, password });
  token = r.token;
  localStorage.setItem("token", token);
  setMe(r.user.username);
  await loadPin(); await loadHistory(); connectWS();
}

function logout(){
  token=""; localStorage.removeItem("token");
  showPin(null); clearMsgs(); setMe("...");
  if(ws) try{ws.close()}catch{}
  ws=null;
  autoGuest().catch(()=>{});
}

msgs.addEventListener("click", e=>{
  const sp = e.target.closest?.(".spoiler[data-spoiler='1']");
  if(!sp) return;
  sp.classList.toggle("reveal");
});

$("register").onclick = ()=>reg().catch(e=>alert(JSON.stringify(e)));
$("login").onclick = ()=>login().catch(e=>alert(JSON.stringify(e)));
$("logout").onclick = ()=>logout();

$("send").onclick = async ()=>{
  const c = txt.value.trim();
  if(!c) return;
  txt.value="";
  try{
    await api(`/api/room/${encodeURIComponent(room)}/send`,"POST",{ content:c });
  }catch(e){
    alert(e.msg || JSON.stringify(e));
  }
};
txt.addEventListener("keydown", e=>{ if(e.key==="Enter") $("send").click(); });

$("room").textContent = room;

(async ()=>{
  const ok = await boot();
  if(!ok) await autoGuest();
})();
