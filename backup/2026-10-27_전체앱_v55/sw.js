/* 우리 다이어리: 암호를 푼 화면·사진을 폰 안에서만 만들어 보여 주는 서비스 워커 (v2) */
'use strict';
const SHELL='hj-shell-v1', ENC='hj-enc-v1';
const SHELL_FILES=['./','index.html','manifest.webmanifest','k.json','icons/icon-192.png','icons/icon-512.png','icons/apple-touch-icon.png'];
const BASE=new URL('./',self.location).pathname;           // 예: /diary/
const PROT=/^(app|season1|movies|tarot|lover)\.html$|^(data|cfg|news|fresh)\.json$|^p\/[^/]+\.webp$/;   // v2: cfg.json(바로 공유 설정), news.json(아침 소식)
const TYPES={html:'text/html; charset=utf-8',json:'application/json; charset=utf-8',webp:'image/webp'};

self.addEventListener('install',e=>{self.skipWaiting();e.waitUntil(caches.open(SHELL).then(c=>c.addAll(SHELL_FILES)).catch(()=>{}));});
self.addEventListener('activate',e=>{e.waitUntil((async()=>{for(const k of await caches.keys())if(k!==SHELL&&k!==ENC)await caches.delete(k);await self.clients.claim();})());});

let KEY=null;
function readKey(){return new Promise(res=>{let r;try{r=indexedDB.open('hj-diary',1);}catch(e){res(null);return;}
 r.onupgradeneeded=()=>r.result.createObjectStore('k');
 r.onsuccess=()=>{const db=r.result;try{const g=db.transaction('k').objectStore('k').get('aes');g.onsuccess=()=>{db.close();res(g.result||null);};g.onerror=()=>{db.close();res(null);};}catch(e){db.close();res(null);}};
 r.onerror=()=>res(null);});}
async function key(){if(!KEY)KEY=await readKey();return KEY;}

async function encBytes(url,fresh){
 const c=await caches.open(ENC);
 if(!fresh){const hit=await c.match(url);if(hit)return hit.arrayBuffer();}
 try{const r=await fetch(url,{cache:'no-cache'});if(r.ok){await c.put(url,r.clone());return r.arrayBuffer();}if(r.status===404){return null;}}catch(e){}
 const hit=await c.match(url);return hit?hit.arrayBuffer():null;}
async function open(buf,k){return crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(buf.slice(0,12))},k,buf.slice(12));}

async function protectedResponse(rel){
 const k=await key();if(!k)return new Response('locked',{status:401});
 const fresh=!/^p\//.test(rel);                       // 사진은 한 번 받으면 그대로, 기록·화면은 새것 먼저
 const buf=await encBytes(self.location.origin+BASE+rel+'.enc',fresh);
 if(!buf)return new Response('missing',{status:404});
 try{const pt=await open(buf,k);const ext=rel.split('.').pop();return new Response(pt,{headers:{'Content-Type':TYPES[ext]||'application/octet-stream','Cache-Control':'no-store'}});}
 catch(e){KEY=null;return new Response('locked',{status:403});}}

async function appOrLock(req){
 const k=await key();
 if(k){const r=await protectedResponse('app.html');if(r.ok)return r;}
 try{const net=await fetch(BASE+'index.html',{cache:'no-cache'});if(net.ok){const c=await caches.open(SHELL);c.put(BASE+'index.html',net.clone());}return net;}
 catch(e){const hit=await caches.match(BASE+'index.html');return hit||new Response('인터넷 연결을 확인해 주세요.',{status:503,headers:{'Content-Type':'text/plain; charset=utf-8'}});}}

self.addEventListener('fetch',e=>{
 const req=e.request;if(req.method!=='GET')return;
 const u=new URL(req.url);if(u.origin!==self.location.origin||!u.pathname.startsWith(BASE))return;
 const rel=u.pathname.slice(BASE.length);
 if(req.mode==='navigate'&&(rel===''||rel==='index.html')){e.respondWith(appOrLock(req));return;}
 if(PROT.test(rel)){e.respondWith(protectedResponse(rel));return;}
 if(/\.enc$/.test(rel))return;                         // 암호 파일은 그대로
 e.respondWith((async()=>{try{const net=await fetch(req);if(net.ok&&SHELL_FILES.includes(rel||'./')){const c=await caches.open(SHELL);c.put(req,net.clone());}return net;}
  catch(err){const hit=await caches.match(req);return hit||Response.error();}})());
});
self.addEventListener('message',e=>{if(e.data==='rekey')KEY=null;});
