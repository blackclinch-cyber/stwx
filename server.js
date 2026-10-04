// Node 18+, без зависимостей. Запуск: node server.js
const http=require('http'),fs=require('fs'),crypto=require('crypto');
const {GOOGLE_CLIENT_ID,SESSION_SECRET,YK_SHOP_ID,YK_SECRET,BASE_URL,PORT=3000}=process.env;
const DB='db.json',db=fs.existsSync(DB)?JSON.parse(fs.readFileSync(DB)):{users:{},done:{}};
const save=()=>fs.writeFileSync(DB,JSON.stringify(db));
const sign=v=>crypto.createHmac('sha256',SESSION_SECRET).update(v).digest('hex');
const cookie=e=>{const p=e+'|'+(Date.now()+30*864e5);return `sid=${Buffer.from(p).toString('base64url')}.${sign(p)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`};
function who(req){const m=(req.headers.cookie||'').match(/sid=([^;]+)/);if(!m)return;const[b,s]=m[1].split('.');
  const p=Buffer.from(b||'','base64url').toString(),ok=sign(p);if(!s||s.length!==ok.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(ok)))return;
  const[e,exp]=p.split('|');return Date.now()<+exp?e:undefined}
const body=req=>new Promise(r=>{let d='';req.on('data',c=>d+=c);req.on('end',()=>{try{r(JSON.parse(d||'{}'))}catch{r({})}})});
const yk=(path,opt={})=>fetch('https://api.yookassa.ru/v3/'+path,{...opt,headers:{'Content-Type':'application/json',Authorization:'Basic '+Buffer.from(YK_SHOP_ID+':'+YK_SECRET).toString('base64'),...opt.headers}}).then(r=>r.json());
const view=u=>({free:u.free,paid:u.paid});
http.createServer(async(req,res)=>{
  const send=(c,o,h={})=>{res.writeHead(c,{'Content-Type':'application/json',...h});res.end(JSON.stringify(o))};
  const url=req.url.split('?')[0];
  try{
    if(req.method==='GET'&&url==='/'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(fs.readFileSync('index.html'))}
    if(url==='/api/auth'){const{access_token}=await body(req);
      const t=await fetch('https://oauth2.googleapis.com/tokeninfo?access_token='+encodeURIComponent(access_token||'')).then(r=>r.json());
      if(t.aud!==GOOGLE_CLIENT_ID||t.email_verified!=='true')return send(401,{});
      const u=db.users[t.email]??={free:1,paid:0};save();return send(200,view(u),{'Set-Cookie':cookie(t.email)})}
    if(url==='/api/logout')return send(200,{},{'Set-Cookie':'sid=; Path=/; Max-Age=0'});
    if(url==='/api/yk-webhook'){const{object}=await body(req);if(!object?.id)return send(400,{});
      const p=await yk('payments/'+object.id);  // не верим телу запроса — перепроверяем у ЮKassa
      if(p.status==='succeeded'&&p.amount?.value==='50.00'&&!db.done[p.id]&&db.users[p.metadata?.email]){db.done[p.id]=1;db.users[p.metadata.email].paid+=5;save()}
      return send(200,{})}
    const email=who(req),u=email&&db.users[email];if(!u)return send(401,{});
    if(url==='/api/me')return send(200,view(u));
    if(url==='/api/consume'){if(u.free>0)u.free--;else if(u.paid>0)u.paid--;else return send(402,{});save();return send(200,view(u))}
    if(url==='/api/checkout'){if(!YK_SHOP_ID||!YK_SECRET)return send(503,{});const p=await yk('payments',{method:'POST',headers:{'Idempotence-Key':crypto.randomUUID()},body:JSON.stringify({
      amount:{value:'50.00',currency:'RUB'},capture:true,description:'5 прогнозов роста',metadata:{email},
      confirmation:{type:'redirect',return_url:BASE_URL+'/?paid=1'}})});
      return p.confirmation?send(200,{url:p.confirmation.confirmation_url}):send(500,{})}
    send(404,{});
  }catch(e){console.error(e);send(500,{})}
}).listen(PORT,()=>console.log('http://localhost:'+PORT));
