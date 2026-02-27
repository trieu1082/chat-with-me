let token="", room="global", ws=null;
const $=id=>document.getElementById(id);
const msgs=$("msgs"), txt=$("txt");

function addMsg(u,c){
  const d=document.createElement("div");
  d.className="m";
  d.innerHTML='<div class="u"></div><div class="t"></div>';
  d.querySelector(".u").textContent=u;
  d.querySelector(".t").textContent=c;
  msgs.appendChild(d);
  msgs.scrollTop=msgs.scrollHeight;
}

async function api(path, method="GET", body=null){
  const headers={};
  if(token) headers.authorization="Bearer "+token;
  if(body){ headers["content-type"]="application/json"; body=JSON.stringify(body); }
  const r=await fetch(path,{method,headers,body});
  const j=await r.json().catch(()=>({}));
  if(!r.ok) throw j;
  return j;
}

function connectWS(){
  if(ws) try{ws.close()}catch{}
  const proto = location.protocol==="https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws?room=${encodeURIComponent(room)}&token=${encodeURIComponent(token)}`);
  ws.onmessage=e=>{ try{ const m=JSON.parse(e.data); addMsg(m.username,m.content);}catch{} };
}

async function guest(){
  const username = prompt("Guest name?") || ("Guest"+Math.floor(Math.random()*9000+1000));
  const r=await api("/api/auth/guest","POST",{username});
  token=r.token; $("me").textContent=r.user.username;
  connectWS();
}

async function reg(){
  const username = prompt("New username?");
  const password = prompt("New password (>=6)?");
  const r=await api("/api/auth/register","POST",{username,password});
  token=r.token; $("me").textContent=r.user.username;
  connectWS();
}

async function login(){
  const username = prompt("Username?");
  const password = prompt("Password?");
  const r=await api("/api/auth/login","POST",{username,password});
  token=r.token; $("me").textContent=r.user.username;
  connectWS();
}

$("guest").onclick=()=>guest().catch(e=>alert(JSON.stringify(e)));
$("register").onclick=()=>reg().catch(e=>alert(JSON.stringify(e)));
$("login").onclick=()=>login().catch(e=>alert(JSON.stringify(e)));

$("send").onclick=async()=>{
  const c=txt.value.trim(); if(!c) return;
  txt.value="";
  try{ await api(`/api/room/${encodeURIComponent(room)}/send`,"POST",{content:c}); }
  catch(e){ alert(JSON.stringify(e)); }
};
txt.addEventListener("keydown",e=>{ if(e.key==="Enter") $("send").click(); });

$("room").textContent=room;
addMsg("SYSTEM","Bấm Guest/Register/Login để chat.");
