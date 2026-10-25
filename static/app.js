const $=s=>document.querySelector(s);let T=sessionStorage.getItem("t"),ALL=[],AU={files:[]};
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
async function api(p,o={}){const r=await fetch("/api/"+p,{...o,headers:{"x-token":T||""}});if(!r.ok){let m=r.status;try{m=(await r.json()).detail||m}catch{}throw new Error(m)}return r}
async function sha(f){const b=await crypto.subtle.digest("SHA-256",await f.arrayBuffer());return[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("")}
function lock(){T=null;sessionStorage.clear();start()}
async function start(){if(T)return vault();const st=await(await fetch("/api/status")).json(),n=!st.setup;
$("#app").innerHTML=`<header><h1>Notes</h1></header><form class=card id=af><h2>${n?"Set your PINs":"Unlock"}</h2>${n?`<p class=meta>Choose a PIN, and a different duress PIN that opens an empty vault if you are ever forced to unlock. There is no PIN recovery, so write them down somewhere safe.</p><label for=d>Duress PIN</label><input id=d type=password autocomplete=off>`:""}<label for=p>PIN</label><input id=p type=password autocomplete=off autofocus><p class=err id=e role=alert></p><button>${n?"Create":"Unlock"}</button></form>`;
$("#af").onsubmit=async ev=>{ev.preventDefault();const f=new FormData();f.append("pin",$("#p").value);if(n)f.append("duress",$("#d").value);
try{T=(await(await api(n?"setup":"login",{method:"POST",body:f})).json()).token;sessionStorage.setItem("t",T);vault()}catch(x){$("#e").textContent=x.message}}}
async function vault(){try{ALL=await(await api("incidents")).json();AU=await(await api("audit")).json()}catch{return lock()}
const names=[...new Set(ALL.map(i=>i.who).filter(Boolean))];
$("#app").innerHTML=`<header><h1>Notes</h1><div class=row style="flex:none"><button class="ghost sm" id=pdf>Export PDF</button><button class="ghost sm" id=lk>Lock</button></div></header>
<div class="banner ${AU.chain_ok?"ok":"bad"}"><strong>${AU.chain_ok?"Record chain intact":"Record chain broken"}</strong><span>${ALL.length} ${ALL.length==1?"entry":"entries"}</span></div>
<form class=card id=nf><h2>Add an entry</h2><label class=drop id=dz for=f><span id=fn>Drop a file here or click to choose</span><input type=file id=f></label>
<div class=row><div><label for=k>Type</label><select id=k><option>Threat<option>Stalking<option>Coercion<option>Harassment<option>Other</select></div><div><label for=w>Person</label><input id=w list=pl placeholder="e.g. Rahul"><datalist id=pl>${names.map(n=>`<option value="${esc(n)}">`).join("")}</datalist></div></div>
<label for=n>Note</label><textarea id=n placeholder="What happened?"></textarea><p class=err id=ne role=alert></p><button id=sv>Save and fingerprint</button></form>
<div class=row style="margin-bottom:16px"><select id=fp aria-label="Filter by person"><option value="">All people${names.map(n=>`<option>${esc(n)}`).join("")}</select><select id=ft aria-label="Filter by type"><option value="">All types<option>Threat<option>Stalking<option>Coercion<option>Harassment<option>Other</select></div>
<div class=tl id=tl></div><p class=meta><a href=/verify.html>Public verify page</a> · The record shows whether files changed after saving. It does not prove the original was genuine.</p>`;
$("#lk").onclick=lock;$("#pdf").onclick=async()=>{try{open(URL.createObjectURL(await(await api("report")).blob()))}catch(x){alert(x.message)}};
const f=$("#f"),dz=$("#dz");f.onchange=()=>$("#fn").textContent=f.files[0]?f.files[0].name:"Drop a file here or click to choose";
["dragover","dragenter"].forEach(e=>dz.addEventListener(e,x=>{x.preventDefault();dz.classList.add("on")}));["dragleave","drop"].forEach(e=>dz.addEventListener(e,x=>{x.preventDefault();dz.classList.remove("on")}));
dz.addEventListener("drop",x=>{if(x.dataTransfer.files.length){f.files=x.dataTransfer.files;f.onchange()}});
$("#nf").onsubmit=async ev=>{ev.preventDefault();const file=f.files[0],e=$("#ne");e.textContent="";if(!file)return e.textContent="Choose a file first.";
const b=$("#sv");b.disabled=true;b.textContent="Fingerprinting…";const d=new FormData();d.append("file",file);d.append("kind",$("#k").value);d.append("who",$("#w").value);d.append("note",$("#n").value);
try{d.append("client_hash",await sha(file));await api("incidents",{method:"POST",body:d});vault()}catch(x){e.textContent=x.message;b.disabled=false;b.textContent="Save and fingerprint"}};
$("#fp").onchange=$("#ft").onchange=draw;draw()}
function draw(){const p=$("#fp").value,t=$("#ft").value,st={};AU.files.forEach(x=>st[x.id]=x);
const L=ALL.filter(i=>(!p||i.who==p)&&(!t||i.kind==t)).reverse();
$("#tl").innerHTML=L.length?L.map(i=>{const s=st[i.id]||{},ok=s.file_ok&&s.link_ok;return `<article class="card ent"><div class=meta>#${i.id} · ${esc(i.ts)}</div><h3 style="margin:4px 0 8px"><span class=chip>${esc(i.kind)}</span>${esc(i.who||"Unknown person")}</h3><div>${esc(i.note)}</div><div class=meta style="margin-top:6px">${esc(i.fname)}</div><div class=fp>${i.file_hash}</div><button class="ghost sm" style="margin-top:8px" onclick="navigator.clipboard.writeText('${i.file_hash}');this.textContent='Copied'">Copy fingerprint</button><div class="st ${ok?"ok":"bad"}">${ok?"Integrity verified":"Change detected"}</div></article>`}).join(""):`<div class=empty>No entries yet.</div>`}
start();
