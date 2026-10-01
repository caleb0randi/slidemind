
/*
  SlideMind — single-server full-stack MVP
  Node 20+

  Install:
    npm install
    cp .env.example .env
    npm start

  Required for AI:
    OPENAI_API_KEY

  Optional email:
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM

  The app works without SMTP in development: verification/reset codes are
  written to the server console. Configure SMTP before production.

  Security model:
  - Passwords are bcrypt-hashed; admins never receive plaintext passwords.
  - Admin support can initiate a password-help request, but the user's
    registered email must receive and confirm the reset code.
  - Users only access their own presentations.
  - Screen capture requires browser permission and is user-initiated.
*/

const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const multer = require("multer");
const OpenAI = require("openai");
const pptxgen = require("pptxgenjs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString("hex");
const COOKIE_NAME = "slidemind_session";
const db = new Database(process.env.DB_FILE || "slidemind.db");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

app.use(express.json({ limit: "12mb" }));
app.use(express.urlencoded({ extended: true, limit: "12mb" }));
app.use(cookieParser());
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 12 * 1024 * 1024 } });

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
  plan TEXT NOT NULL DEFAULT 'free' CHECK(plan IN ('free','pro')),
  verified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS verification_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  purpose TEXT NOT NULL CHECK(purpose IN ('verify','reset','support_reset')),
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS presentations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  theme TEXT NOT NULL,
  slide_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS support_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  admin_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','declined','completed','expired')),
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(admin_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_id INTEGER,
  action TEXT NOT NULL,
  target_user_id INTEGER,
  metadata TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(actor_id) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY(target_user_id) REFERENCES users(id) ON DELETE SET NULL
);
`);

function envBool(v) { return String(v || "").toLowerCase() === "true"; }
function now() { return Date.now(); }
function normalizeEmail(e) { return String(e || "").trim().toLowerCase(); }
function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role, plan: u.plan, verified: !!u.verified, created_at: u.created_at };
}
function signSession(user) {
  return jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
}
function setSession(res, user) {
  res.cookie(COOKIE_NAME, signSession(user), {
    httpOnly: true, sameSite: "lax", secure: envBool(process.env.COOKIE_SECURE),
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}
function clearSession(res) { res.clearCookie(COOKIE_NAME); }

function auth(req, res, next) {
  try {
    const token = req.cookies[COOKIE_NAME];
    if (!token) return res.status(401).json({ error: "Authentication required." });
    const p = jwt.verify(token, JWT_SECRET);
    const u = db.prepare("SELECT * FROM users WHERE id=?").get(p.sub);
    if (!u) return res.status(401).json({ error: "Session is invalid." });
    req.user = u; next();
  } catch { return res.status(401).json({ error: "Session expired." }); }
}
function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Administrator access required." });
  next();
}
function audit(actor, action, target, metadata={}) {
  db.prepare("INSERT INTO audit_logs(actor_id,action,target_user_id,metadata) VALUES(?,?,?,?)")
    .run(actor?.id || null, action, target || null, JSON.stringify(metadata));
}

let mailer = null;
if (process.env.SMTP_HOST) {
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: envBool(process.env.SMTP_SECURE),
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
  });
}
async function sendCodeEmail(to, name, purpose, code) {
  const subject = purpose === "verify" ? "Verify your SlideMind account" : "Your SlideMind security code";
  const text = `Hi ${name},\n\nYour SlideMind security code is ${code}. It expires in 10 minutes.\n\nIf you did not request this, you can ignore this email.`;
  if (!mailer) {
    console.log(`[DEV EMAIL] ${to} | ${subject} | CODE: ${code}`);
    return;
  }
  await mailer.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to, subject, text,
    html: `<div style="font-family:Arial,sans-serif"><h2>SlideMind</h2><p>Hi ${escapeHtml(name)},</p><p>Your security code is:</p><div style="font-size:28px;font-weight:700;letter-spacing:8px">${code}</div><p>It expires in 10 minutes.</p></div>` });
}
function codeHash(code) { return crypto.createHash("sha256").update(String(code)).digest("hex"); }
function createCode(userId, purpose) {
  const code = String(crypto.randomInt(100000, 1000000));
  db.prepare("UPDATE verification_codes SET used=1 WHERE user_id=? AND purpose=? AND used=0").run(userId, purpose);
  db.prepare("INSERT INTO verification_codes(user_id,purpose,code_hash,expires_at) VALUES(?,?,?,?,?)")
    .run(userId, purpose, codeHash(code), now()+10*60*1000);
  return code;
}
function consumeCode(userId, purpose, code) {
  const row = db.prepare(`SELECT * FROM verification_codes
    WHERE user_id=? AND purpose=? AND used=0 AND expires_at>? ORDER BY id DESC LIMIT 1`).get(userId,purpose,now());
  if (!row || row.code_hash !== codeHash(code)) return false;
  db.prepare("UPDATE verification_codes SET used=1 WHERE id=?").run(row.id);
  return true;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
}

app.get("/api/health", (_,res)=>res.json({ok:true,app:"SlideMind",time:new Date().toISOString()}));

app.post("/api/auth/register", async (req,res)=>{
  try {
    const name = String(req.body.name||"").trim();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password||"");
    if (name.length < 2) return res.status(400).json({error:"Enter your name."});
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({error:"Enter a valid email."});
    if (password.length < 8) return res.status(400).json({error:"Password must be at least 8 characters."});
    if (db.prepare("SELECT id FROM users WHERE email=?").get(email)) return res.status(409).json({error:"An account with that email already exists."});
    const hash = await bcrypt.hash(password, 12);
    const info = db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name,email,hash);
    const user = db.prepare("SELECT * FROM users WHERE id=?").get(info.lastInsertRowid);
    const code = createCode(user.id,"verify");
    await sendCodeEmail(user.email,user.name,"verify",code);
    setSession(res,user);
    res.json({user:publicUser(user),verificationRequired:true});
  } catch(e) { console.error(e); res.status(500).json({error:"Could not create account."}); }
});

app.post("/api/auth/verify", auth, async (req,res)=>{
  const code=String(req.body.code||"").trim();
  if(!consumeCode(req.user.id,"verify",code)) return res.status(400).json({error:"Invalid or expired code."});
  db.prepare("UPDATE users SET verified=1,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(req.user.id);
  audit(req.user,"verify_email",req.user.id);
  res.json({ok:true,user:publicUser(db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id))});
});

app.post("/api/auth/resend-verification", auth, async (req,res)=>{
  if(req.user.verified) return res.json({ok:true});
  const code=createCode(req.user.id,"verify");
  await sendCodeEmail(req.user.email,req.user.name,"verify",code);
  res.json({ok:true});
});

app.post("/api/auth/login", async (req,res)=>{
  const email=normalizeEmail(req.body.email), password=String(req.body.password||"");
  const user=db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if(!user || !(await bcrypt.compare(password,user.password_hash))) return res.status(401).json({error:"Incorrect email or password."});
  setSession(res,user);
  res.json({user:publicUser(user),verificationRequired:!user.verified});
});

app.post("/api/auth/logout", (req,res)=>{clearSession(res);res.json({ok:true});});

app.get("/api/me", auth, (req,res)=>res.json({user:publicUser(req.user)}));

app.post("/api/auth/forgot", async (req,res)=>{
  const email=normalizeEmail(req.body.email);
  const user=db.prepare("SELECT * FROM users WHERE email=?").get(email);
  // Do not reveal whether an email exists.
  if(user) {
    const code=createCode(user.id,"reset");
    await sendCodeEmail(user.email,user.name,"reset",code);
  }
  res.json({ok:true,message:"If that account exists, a security code has been sent."});
});

app.post("/api/auth/reset", async (req,res)=>{
  const email=normalizeEmail(req.body.email), code=String(req.body.code||""), password=String(req.body.password||"");
  if(password.length<8) return res.status(400).json({error:"New password must be at least 8 characters."});
  const user=db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if(!user || !consumeCode(user.id,"reset",code)) return res.status(400).json({error:"Invalid or expired code."});
  db.prepare("UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(await bcrypt.hash(password,12),user.id);
  audit(null,"password_reset",user.id);
  res.json({ok:true});
});

/* Admin support: user must approve first; the actual reset still requires the
   code delivered to the user's registered email. */
app.post("/api/admin/support-requests", auth, adminOnly, (req,res)=>{
  const userId=Number(req.body.userId);
  const user=db.prepare("SELECT * FROM users WHERE id=?").get(userId);
  if(!user || user.role==="admin") return res.status(404).json({error:"User not found."});
  const info=db.prepare("INSERT INTO support_requests(user_id,admin_id,expires_at) VALUES(?,?,?)")
    .run(userId,req.user.id,now()+15*60*1000);
  audit(req.user,"support_request_created",userId,{requestId:info.lastInsertRowid});
  res.json({ok:true,requestId:info.lastInsertRowid});
});
app.post("/api/support/approve", auth, async (req,res)=>{
  const id=Number(req.body.requestId);
  const row=db.prepare("SELECT * FROM support_requests WHERE id=? AND user_id=? AND status='pending' AND expires_at>?").get(id,req.user.id,now());
  if(!row) return res.status(404).json({error:"Support request not found or expired."});
  db.prepare("UPDATE support_requests SET status='approved' WHERE id=?").run(id);
  const code=createCode(req.user.id,"support_reset");
  await sendCodeEmail(req.user.email,req.user.name,"support_reset",code);
  audit(req.user,"support_approved",req.user.id,{requestId:id});
  res.json({ok:true,message:"A security code was sent to your registered email."});
});
app.post("/api/admin/support-reset", auth, adminOnly, async (req,res)=>{
  const id=Number(req.body.requestId), code=String(req.body.code||""), newPassword=String(req.body.newPassword||"");
  if(newPassword.length<8) return res.status(400).json({error:"Password must be at least 8 characters."});
  const row=db.prepare("SELECT * FROM support_requests WHERE id=? AND admin_id=? AND status='approved' AND expires_at>?").get(id,req.user.id,now());
  if(!row) return res.status(403).json({error:"Support authorization is missing or expired."});
  if(!consumeCode(row.user_id,"support_reset",code)) return res.status(400).json({error:"Invalid or expired user code."});
  db.prepare("UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(await bcrypt.hash(newPassword,12),row.user_id);
  db.prepare("UPDATE support_requests SET status='completed' WHERE id=?").run(id);
  audit(req.user,"assisted_password_reset",row.user_id,{requestId:id});
  res.json({ok:true});
});

app.get("/api/presentations",auth,(req,res)=>{
  const rows=db.prepare("SELECT id,title,theme,created_at,updated_at FROM presentations WHERE user_id=? ORDER BY updated_at DESC").all(req.user.id);
  res.json({presentations:rows});
});
app.get("/api/presentations/:id",auth,(req,res)=>{
  const row=db.prepare("SELECT * FROM presentations WHERE id=? AND user_id=?").get(req.params.id,req.user.id);
  if(!row)return res.status(404).json({error:"Presentation not found."});
  res.json({presentation:{...row,slides:JSON.parse(row.slide_json)}});
});
app.post("/api/presentations",auth,(req,res)=>{
  const title=String(req.body.title||"Untitled presentation").slice(0,160);
  const theme=String(req.body.theme||"modern").slice(0,40);
  const slides=Array.isArray(req.body.slides)?req.body.slides:[];
  if(!slides.length)return res.status(400).json({error:"At least one slide is required."});
  const info=db.prepare("INSERT INTO presentations(user_id,title,theme,slide_json) VALUES(?,?,?,?)")
    .run(req.user.id,title,theme,JSON.stringify(slides));
  res.json({id:info.lastInsertRowid});
});
app.put("/api/presentations/:id",auth,(req,res)=>{
  const slides=Array.isArray(req.body.slides)?req.body.slides:[];
  const title=String(req.body.title||"Untitled presentation").slice(0,160);
  const theme=String(req.body.theme||"modern").slice(0,40);
  const info=db.prepare("UPDATE presentations SET title=?,theme=?,slide_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?")
    .run(title,theme,JSON.stringify(slides),req.params.id,req.user.id);
  if(!info.changes)return res.status(404).json({error:"Presentation not found."});
  res.json({ok:true});
});
app.delete("/api/presentations/:id",auth,(req,res)=>{
  db.prepare("DELETE FROM presentations WHERE id=? AND user_id=?").run(req.params.id,req.user.id);
  res.json({ok:true});
});

/* Admin intentionally gets aggregate analytics, not private user content. */
app.get("/api/admin/overview",auth,adminOnly,(req,res)=>{
  const users=db.prepare("SELECT COUNT(*) c FROM users").get().c;
  const verified=db.prepare("SELECT COUNT(*) c FROM users WHERE verified=1").get().c;
  const presentations=db.prepare("SELECT COUNT(*) c FROM presentations").get().c;
  const free=db.prepare("SELECT COUNT(*) c FROM users WHERE plan='free'").get().c;
  const pro=db.prepare("SELECT COUNT(*) c FROM users WHERE plan='pro'").get().c;
  res.json({users,verified,presentations,free,pro});
});
app.get("/api/admin/users",auth,adminOnly,(req,res)=>{
  const rows=db.prepare("SELECT id,name,email,role,plan,verified,created_at FROM users ORDER BY created_at DESC").all();
  res.json({users:rows});
});
app.get("/api/admin/support-requests",auth,adminOnly,(req,res)=>{
  const rows=db.prepare(`SELECT s.id,s.status,s.expires_at,u.name user_name,u.email user_email
    FROM support_requests s JOIN users u ON u.id=s.user_id
    WHERE s.admin_id=? ORDER BY s.id DESC LIMIT 50`).all(req.user.id);
  res.json({requests:rows});
});
app.get("/api/admin/audit",auth,adminOnly,(req,res)=>{
  const rows=db.prepare(`SELECT a.id,a.action,a.target_user_id,a.created_at,u.email actor_email
    FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 100`).all();
  res.json({logs:rows});
});
app.post("/api/admin/users/:id/plan",auth,adminOnly,(req,res)=>{
  const plan=req.body.plan==="pro"?"pro":"free";
  const target=Number(req.params.id);
  if(target===req.user.id)return res.status(400).json({error:"Do not change your own plan through this endpoint."});
  db.prepare("UPDATE users SET plan=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(plan,target);
  audit(req.user,"plan_changed",target,{plan});
  res.json({ok:true});
});


app.get("/api/support/pending",auth,(req,res)=>{
  const rows=db.prepare(`SELECT s.id,s.status,s.expires_at,u.name admin_name,u.email admin_email
    FROM support_requests s JOIN users u ON u.id=s.admin_id
    WHERE s.user_id=? AND s.status='pending' AND s.expires_at>? ORDER BY s.id DESC`).all(req.user.id,now());
  res.json({requests:rows});
});
app.post("/api/support/decline",auth,(req,res)=>{
  const id=Number(req.body.requestId);
  const row=db.prepare("SELECT * FROM support_requests WHERE id=? AND user_id=? AND status='pending'").get(id,req.user.id);
  if(!row)return res.status(404).json({error:"Support request not found."});
  db.prepare("UPDATE support_requests SET status='declined' WHERE id=?").run(id);
  audit(req.user,"support_declined",req.user.id,{requestId:id});
  res.json({ok:true});
});

/* AI generation. Images are sent as data URLs to the Responses API. */
function cleanJson(text) {
  const s=String(text||"").trim().replace(/^```json\s*/i,"").replace(/```$/,"").trim();
  const start=s.indexOf("{"), end=s.lastIndexOf("}");
  if(start<0||end<0)throw new Error("AI returned invalid JSON.");
  return JSON.parse(s.slice(start,end+1));
}
async function generateSlidesFromImages(images, options={}) {
  if(!process.env.OPENAI_API_KEY) {
    throw new Error("OPENAI_API_KEY is not configured. Add it to .env.");
  }
  const client=new OpenAI({apiKey:process.env.OPENAI_API_KEY});
  const theme=options.theme||"modern";
  const count=Math.min(Math.max(Number(options.slideCount||8),3),20);
  const input = [
    {role:"system",content:`You are SlideMind, an expert presentation information architect.
Analyze user-provided screen captures and reconstruct the INFORMATION into an original,
editable presentation. Do not merely paste screenshots. Preserve important facts, numbers,
definitions, examples, stories and explanatory relationships. Do not invent facts that are
not supported by the input. If the input is ambiguous, mark uncertainty in notes.
Create concise, human-readable slides. Stories should remain narrative when appropriate.
Return JSON only with this exact shape:
{"title":"...","slides":[{"type":"title|content|story|comparison|data|summary","title":"...",
"subtitle":"...","body":["..."],"highlight":"...","speakerNotes":"...",
"imageHint":"...","layout":"hero|two-column|quote|timeline|data|closing"}]}
Use at most 6 bullets per slide and prefer 3-5. Target ${count} slides.
Theme requested: ${theme}.`},
    {role:"user",content:[
      {type:"input_text",text:"Create the presentation from these authorized screen captures. Make it polished and faithful to the source."},
      ...images.map(data=>({type:"input_image",image_url:data}))
    ]}
  ];
  const response=await client.responses.create({model:process.env.OPENAI_MODEL||"gpt-5.6-luna",input});
  return cleanJson(response.output_text);
}

app.post("/api/ai/generate",auth,upload.array("screens",12),async(req,res)=>{
  try {
    if(!req.files?.length)return res.status(400).json({error:"Add at least one screen capture."});
    const images=req.files.map(f=>`data:${f.mimetype};base64,${f.buffer.toString("base64")}`);
    const result=await generateSlidesFromImages(images,{theme:req.body.theme,slideCount:req.body.slideCount});
    res.json({presentation:result});
  } catch(e) {
    console.error(e);
    res.status(500).json({error:e.message||"AI generation failed."});
  }
});

/* PPTX export. The slide content is editable text/shapes, not screenshots. */
const THEMES = {
  modern:{bg:"F6F8FC",ink:"14213D",muted:"5D6678",accent:"6C5CE7",soft:"E9E7FF"},
  dark:{bg:"111827",ink:"F9FAFB",muted:"CBD5E1",accent:"8B5CF6",soft:"27223F"},
  academic:{bg:"F8FAFC",ink:"172033",muted:"526071",accent:"2563EB",soft:"DBEAFE"},
  nature:{bg:"F5FAF6",ink:"153A2A",muted:"557166",accent:"16845B",soft:"DDF4E9"},
  business:{bg:"F7F8FA",ink:"172033",muted:"5B6472",accent:"0F766E",soft:"DDF4F0"}
};
function hex(x){return String(x).replace("#","").toUpperCase();}
async function buildPptx(title,slides,themeName,res) {
  const t=THEMES[themeName]||THEMES.modern;
  const pptx=new pptxgen();
  pptx.layout="LAYOUT_WIDE";
  pptx.author="SlideMind";
  pptx.subject="AI-generated editable presentation";
  pptx.title=title;
  pptx.company="SlideMind";
  pptx.lang="en-US";
  pptx.theme={headFontFace:"Aptos Display",bodyFontFace:"Aptos",lang:"en-US"};
  const W=13.333,H=7.5;
  for(let i=0;i<slides.length;i++){
    const s=slides[i]||{};
    const slide=pptx.addSlide();
    slide.background={color:hex(t.bg)};
    slide.addShape(pptx.ShapeType.rect,{x:0,y:0,w:0.16,h:H,fill:{color:hex(t.accent)},line:{color:hex(t.accent)}});
    if(i===0 || s.type==="title"){
      slide.addText(s.title||title,{x:0.8,y:1.35,w:11.7,h:1.0,fontFace:"Aptos Display",fontSize:34,bold:true,color:hex(t.ink),margin:0});
      slide.addText(s.subtitle||"Created with SlideMind",{x:0.82,y:2.55,w:10.8,h:0.55,fontSize:17,color:hex(t.muted),margin:0});
      if(s.highlight)slide.addText(s.highlight,{x:0.82,y:4.1,w:10.5,h:1.0,fontSize:24,bold:true,color:hex(t.accent),margin:0});
    } else {
      slide.addText(s.title||`Slide ${i+1}`,{x:0.72,y:0.55,w:11.6,h:0.65,fontFace:"Aptos Display",fontSize:25,bold:true,color:hex(t.ink),margin:0});
      if(s.subtitle)slide.addText(s.subtitle,{x:0.74,y:1.25,w:11.2,h:0.4,fontSize:13,color:hex(t.muted),margin:0});
      if(s.type==="story" || s.layout==="quote"){
        slide.addShape(pptx.ShapeType.roundRect,{x:0.9,y:2.0,w:11.2,h:3.55,rectRadius:0.08,fill:{color:hex(t.soft)},line:{color:hex(t.soft)}});
        slide.addText((s.body||[]).join("\n\n"),{x:1.3,y:2.55,w:10.3,h:2.35,fontSize:20,color:hex(t.ink),breakLine:false,margin:0.02,fit:"shrink"});
      } else if(s.layout==="two-column"){
        const mid=Math.ceil((s.body||[]).length/2);
        [s.body?.slice(0,mid)||[],s.body?.slice(mid)||[]].forEach((arr,j)=>{
          slide.addShape(pptx.ShapeType.roundRect,{x:j?6.85:0.8,y:1.9,w:5.65,h:3.9,fill:{color:hex(j?t.soft:"FFFFFF")},line:{color:"E5E7EB",pt:1}});
          slide.addText(arr.map(x=>({text:String(x),options:{bullet:{indent:16},breakLine:true}})),{x:j?7.2:1.15,y:2.25,w:5.0,h:3.0,fontSize:16,color:hex(t.ink),margin:0.02,breakLine:false,fit:"shrink"});
        });
      } else {
        const body=s.body||[];
        const runs=[];
        body.forEach((x,idx)=>{runs.push({text:String(x),options:{bullet:{indent:16},breakLine:true,paraSpaceAfterPt:12}})});
        slide.addText(runs,{x:1.0,y:1.85,w:11.0,h:3.95,fontSize:18,color:hex(t.ink),margin:0.02,fit:"shrink",breakLine:false});
      }
      if(s.highlight)slide.addText(s.highlight,{x:0.9,y:6.25,w:10.8,h:0.45,fontSize:13,bold:true,color:hex(t.accent),margin:0});
    }
    slide.addText(`${i+1} / ${slides.length}`,{x:11.75,y:6.9,w:0.7,h:0.25,fontSize:9,color:hex(t.muted),align:"right",margin:0});
    if(s.speakerNotes) slide.addNotes(s.speakerNotes);
  }
  const buf=await pptx.write({outputType:"nodebuffer"});
  res.setHeader("Content-Type","application/vnd.openxmlformats-officedocument.presentationml.presentation");
  res.setHeader("Content-Disposition",`attachment; filename="${safeFile(title)}.pptx"`);
  res.send(buf);
}
function safeFile(s){return String(s||"slidemind-presentation").replace(/[^a-z0-9-_]+/gi,"-").replace(/^-|-$/g,"").slice(0,80)||"presentation";}
app.post("/api/export/pptx",auth,async(req,res)=>{
  try {
    const slides=Array.isArray(req.body.slides)?req.body.slides:[];
    if(!slides.length)return res.status(400).json({error:"No slides to export."});
    await buildPptx(String(req.body.title||"SlideMind Presentation"),slides,String(req.body.theme||"modern"),res);
  } catch(e){console.error(e);res.status(500).json({error:"PPTX export failed."});}
});

const HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SlideMind — Screen to beautiful slides</title>
<style>
:root{--bg:#f5f7fb;--card:#fff;--ink:#172033;--muted:#657084;--accent:#6c5ce7;--line:#e5e8ef;--soft:#eeecff;--danger:#c0392b}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(145deg,#f7f8fc,#eef1fa);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;color:var(--ink)}
button,input,select,textarea{font:inherit}button{cursor:pointer}.hidden{display:none!important}
.top{height:70px;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 28px;position:sticky;top:0;z-index:5}
.brand{font-weight:900;letter-spacing:-.8px;font-size:21px}.brand span{color:var(--accent)}
.btn{border:0;border-radius:12px;padding:11px 16px;background:var(--accent);color:white;font-weight:750}.btn.secondary{background:#f0efff;color:#5648d7}.btn.ghost{background:#fff;color:var(--ink);border:1px solid var(--line)}.btn.danger{background:#fff0ee;color:#b33829}
.shell{max-width:1250px;margin:auto;padding:32px 22px}.hero{padding:40px 0 26px}.hero h1{font-size:clamp(38px,6vw,72px);line-height:.98;letter-spacing:-4px;max-width:800px;margin:0 0 18px}.hero p{font-size:18px;color:var(--muted);max-width:690px;line-height:1.6}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.card{background:rgba(255,255,255,.92);border:1px solid var(--line);border-radius:20px;padding:22px;box-shadow:0 12px 40px rgba(20,30,60,.05)}.card h3{margin:0 0 7px}.muted{color:var(--muted)}.small{font-size:13px}
.auth{max-width:460px;margin:60px auto}.auth h1{font-size:36px;letter-spacing:-1.5px}.field{margin:14px 0}.field label{display:block;font-size:13px;font-weight:750;margin-bottom:7px}.field input,.field select,.field textarea{width:100%;border:1px solid var(--line);background:#fff;border-radius:12px;padding:12px;outline:none}.field input:focus{border-color:var(--accent);box-shadow:0 0 0 3px #eceaff}
.tabs{display:flex;gap:8px;margin-bottom:22px;flex-wrap:wrap}.tab{border:1px solid var(--line);background:#fff;border-radius:10px;padding:10px 14px}.tab.active{background:var(--soft);color:#5548d3;border-color:#d8d4ff}
.workspace{display:grid;grid-template-columns:270px 1fr;min-height:calc(100vh - 70px)}.side{background:#fff;border-right:1px solid var(--line);padding:18px}.side button{width:100%;text-align:left;border:0;background:transparent;padding:12px;border-radius:10px}.side button:hover,.side button.active{background:#f0efff;color:#5749d4}.main{padding:28px;overflow:auto}
.capture{border:2px dashed #cfd4e2;border-radius:20px;padding:35px;text-align:center;background:#fbfcff}.capture.live{border-color:var(--accent);background:#f4f2ff}.preview{max-width:100%;border-radius:14px;border:1px solid var(--line);margin-top:15px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:12px 0}.toolbar select,.toolbar input{border:1px solid var(--line);border-radius:10px;padding:10px;background:#fff}
.slides{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:15px}.thumb{border:1px solid var(--line);border-radius:14px;background:#fff;overflow:hidden;cursor:pointer}.thumb.active{outline:3px solid #cfcaff}.mini{aspect-ratio:16/9;padding:14px;background:#f7f8fc}.mini h4{margin:0 0 8px;font-size:14px}.mini p{font-size:10px;color:#667085}.editor{background:#fff;border:1px solid var(--line);border-radius:18px;padding:20px}.slide-canvas{aspect-ratio:16/9;border-radius:16px;padding:35px;background:#f6f8fc;display:flex;flex-direction:column;justify-content:center;max-width:900px}.slide-canvas h2{font-size:32px;margin:0 0 15px}.slide-canvas li{margin:9px 0}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.stat b{display:block;font-size:28px;margin-top:4px}
.modal{position:fixed;inset:0;background:rgba(10,16,30,.45);display:flex;align-items:center;justify-content:center;padding:20px;z-index:20}.modal>div{background:#fff;border-radius:20px;padding:24px;max-width:520px;width:100%;max-height:90vh;overflow:auto}
.notice{padding:12px;border-radius:12px;background:#fff8df;color:#725900;margin:12px 0}.error{background:#fff0ee;color:#a93226}.ok{background:#ebfff4;color:#187443}
table{width:100%;border-collapse:collapse}th,td{padding:11px;border-bottom:1px solid var(--line);text-align:left;font-size:13px}
@media(max-width:850px){.grid,.stats{grid-template-columns:1fr}.workspace{grid-template-columns:1fr}.side{display:flex;gap:6px;overflow:auto;border-right:0;border-bottom:1px solid var(--line)}.side button{width:auto;white-space:nowrap}.hero h1{letter-spacing:-2px}.main{padding:18px}}
</style>
</head>
<body>
<header class="top"><div class="brand">Slide<span>Mind</span></div><div id="topActions"></div></header>
<div id="app"></div>
<script>
const $=s=>document.querySelector(s), app=$("#app"), actions=$("#topActions");
let state={user:null,view:"home",slides:[],title:"Untitled presentation",theme:"modern",selected:0,capture:null,history:[]};
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function api(url,opt={}){const r=await fetch(url,{...opt,headers:{"Content-Type":"application/json",...(opt.headers||{})}});let d={};try{d=await r.json()}catch{}if(!r.ok)throw Error(d.error||"Request failed");return d}
function setNotice(msg,type="notice"){const n=$("#notice");if(n){n.className="notice "+type;n.textContent=msg;n.classList.remove("hidden")}}
function render(){state.user?renderApp():renderLanding()}
function renderLanding(){
 actions.innerHTML='<button class="btn ghost" onclick="showAuth(\\'login\\')">Sign in</button> <button class="btn" onclick="showAuth(\\'register\\')">Create account</button>';
 app.innerHTML=\`
 <div class="shell"><section class="hero"><div class="small">AI PRESENTATION STUDIO</div><h1>Turn what you see into beautiful slides.</h1><p>Capture information you are allowed to capture, let AI understand the important ideas, and create an editable presentation in seconds.</p><div class="toolbar"><button class="btn" onclick="showAuth('register')">Start for free</button><button class="btn secondary" onclick="showAuth('login')">I already have an account</button></div></section>
 <div class="grid"><div class="card"><h3>🖥 Screen to slides</h3><p class="muted">Use browser-approved screen capture or upload captures and let AI reconstruct the information as editable slides.</p></div><div class="card"><h3>✨ Smart storytelling</h3><p class="muted">Preserve explanations, stories, examples, definitions and key points instead of dumping screenshots into PowerPoint.</p></div><div class="card"><h3>🔐 Private by design</h3><p class="muted">Passwords are never visible to admins. Account recovery uses codes sent to the registered email.</p></div></div></div>\`;
}
function showAuth(mode){
 actions.innerHTML='<button class="btn ghost" onclick="render()">Home</button>';
 app.innerHTML=\`<div class="shell"><div class="auth card"><div class="tabs"><button class="tab \${mode==='login'?'active':''}" onclick="showAuth('login')">Sign in</button><button class="tab \${mode==='register'?'active':''}" onclick="showAuth('register')">Create account</button><button class="tab" onclick="forgot()">Forgot password</button></div>
 <h1>\${mode==='login'?'Welcome back':'Create your account'}</h1><div id="notice" class="notice hidden"></div>
 \${mode==='register'?'<div class="field"><label>Name</label><input id="name" placeholder="Your name"></div>':''}
 <div class="field"><label>Email</label><input id="email" type="email" placeholder="you@example.com"></div>
 <div class="field"><label>Password</label><input id="password" type="password" placeholder="At least 8 characters"></div>
 <button class="btn" style="width:100%" onclick="\${mode==='login'?'login()':'register()'}">\${mode==='login'?'Sign in':'Create account'}</button>
 </div></div>\`;
}
async function register(){try{const d=await api("/api/auth/register",{method:"POST",body:JSON.stringify({name:$("#name").value,email:$("#email").value,password:$("#password").value})});state.user=d.user;render();if(d.verificationRequired)verifyModal()}catch(e){setNotice(e.message,"error")}}
async function login(){try{const d=await api("/api/auth/login",{method:"POST",body:JSON.stringify({email:$("#email").value,password:$("#password").value})});state.user=d.user;render();if(d.verificationRequired)verifyModal()}catch(e){setNotice(e.message,"error")}}
function verifyModal(){document.body.insertAdjacentHTML("beforeend",\`<div class="modal" id="verifyModal"><div><h2>Verify your email</h2><p class="muted">Enter the 6-digit code sent to your registered email.</p><div class="field"><input id="vcode" inputmode="numeric" maxlength="6" placeholder="123456"></div><button class="btn" onclick="verify()">Verify</button> <button class="btn ghost" onclick="resend()">Resend code</button></div></div>\`)}
async function verify(){try{await api("/api/auth/verify",{method:"POST",body:JSON.stringify({code:$("#vcode").value})});$("#verifyModal").remove();state.user=(await api("/api/me")).user;render()}catch(e){alert(e.message)}}
async function resend(){try{await api("/api/auth/resend-verification",{method:"POST"});alert("A new code was sent.")}catch(e){alert(e.message)}}
function forgot(){app.innerHTML=\`<div class="shell"><div class="auth card"><h1>Reset password</h1><p class="muted">A code will be sent to the registered email if the account exists.</p><div id="notice" class="notice hidden"></div><div class="field"><label>Email</label><input id="email" type="email"></div><button class="btn" onclick="sendForgot()">Send code</button></div></div>\`}
async function sendForgot(){try{await api("/api/auth/forgot",{method:"POST",body:JSON.stringify({email:$("#email").value})});app.querySelector(".auth").innerHTML=\`<h1>Enter your code</h1><p class="muted">Check your registered email.</p><div class="field"><label>Email</label><input id="email" value="\${esc($("#email").value)}"></div><div class="field"><label>Code</label><input id="code" maxlength="6"></div><div class="field"><label>New password</label><input id="newpass" type="password"></div><button class="btn" onclick="resetPassword()">Change password</button>\`}catch(e){setNotice(e.message,"error")}}
async function resetPassword(){try{await api("/api/auth/reset",{method:"POST",body:JSON.stringify({email:$("#email").value,code:$("#code").value,password:$("#newpass").value})});alert("Password changed. You can sign in now.");showAuth("login")}catch(e){setNotice(e.message,"error")}}
async function logout(){await api("/api/auth/logout",{method:"POST"});state.user=null;state.slides=[];render()}
function renderApp(){
 actions.innerHTML=\`<span class="small muted">\${esc(state.user.name)} · \${state.user.plan.toUpperCase()}</span> <button class="btn ghost" onclick="logout()">Sign out</button>\`;
 app.innerHTML=\`<div class="workspace"><aside class="side">
 <button class="\${state.view==='home'?'active':''}" onclick="state.view='home';renderApp()">⌂ Dashboard</button>
 <button class="\${state.view==='create'?'active':''}" onclick="newPresentation()">＋ Create slides</button>
 <button class="\${state.view==='library'?'active':''}" onclick="state.view='library';renderApp()">▣ My presentations</button>
 \${state.user.role==='admin'?'<button class="'+(state.view==='admin'?'active':'')+'" onclick="state.view=\\'admin\\';renderApp()">⚙ Admin</button>':''}
 </aside><main class="main"><div id="notice" class="notice hidden"></div>\${state.view==='home'?homeView():state.view==='create'?createView():state.view==='library'?libraryView():adminView()}</main></div>\`;
}
function homeView(){return \`<h1>Good to see you, \${esc(state.user.name.split(' ')[0])}.</h1><p class="muted">Build a presentation from a screen capture or start with your own content.</p><div class="grid" style="margin-top:22px"><div class="card"><h3>⚡ Create from screen</h3><p class="muted">Capture a screen you are authorized to capture, then let SlideMind turn it into editable slides.</p><button class="btn" onclick="newPresentation()">Create presentation</button></div><div class="card"><h3>🎨 Design-first</h3><p class="muted">Choose a visual style and regenerate the layout without losing your content.</p></div><div class="card"><h3>📦 Export</h3><p class="muted">Save editable PowerPoint files when your presentation is ready.</p></div></div>\`}
function newPresentation(){state.view="create";state.slides=[];state.title="Untitled presentation";state.selected=0;state.capture=null;renderApp()}
function createView(){return \`
<div class="toolbar"><button class="btn ghost" onclick="state.view='home';renderApp()">← Back</button><input id="pptTitle" value="\${esc(state.title)}" style="min-width:260px" placeholder="Presentation title"><select id="theme"><option value="modern">Modern</option><option value="academic">Academic</option><option value="business">Business</option><option value="nature">Nature</option><option value="dark">Dark</option></select><button class="btn" onclick="savePresentation()">Save</button><button class="btn secondary" onclick="exportPptx()">Download PPTX</button></div>
<div class="capture \${state.capture?'live':''}"><h2>Capture your source</h2><p class="muted">Browser permission is required. Capture only content you are allowed to capture.</p><button class="btn" onclick="captureScreen()">Select screen/window</button><input id="fileInput" type="file" accept="image/*" multiple hidden onchange="handleFiles(event)"><button class="btn ghost" onclick="$('#fileInput').click()">Upload captures</button><div id="capturePreview"></div></div>
\${state.slides.length?editorView():'<div class="card" style="margin-top:18px"><h3>Nothing generated yet</h3><p class="muted">Capture or upload one or more images, then generate your presentation.</p></div>'}\`}
function editorView(){const s=state.slides[state.selected]||state.slides[0];return \`<div class="toolbar"><button class="btn" onclick="generate()">✨ Generate with AI</button><button class="btn ghost" onclick="addSlide()">＋ Add slide</button><button class="btn ghost" onclick="changeDesign()">Change design</button></div><div class="editor"><div class="slide-canvas" id="canvas"><h2>\${esc(s.title)}</h2>\${s.subtitle?'<p class="muted">'+esc(s.subtitle)+'</p>':''}<ul>\${(s.body||[]).map(x=>'<li>'+esc(x)+'</li>').join('')}</ul>\${s.highlight?'<strong>'+esc(s.highlight)+'</strong>':''}</div><div class="field"><label>Slide title</label><input value="\${esc(s.title||'')}" oninput="editSlide('title',this.value)"></div><div class="field"><label>Subtitle</label><input value="\${esc(s.subtitle||'')}" oninput="editSlide('subtitle',this.value)"></div><div class="field"><label>Body (one point per line)</label><textarea rows="7" oninput="editSlide('body',this.value.split('\\n'))">\${esc((s.body||[]).join('\\n'))}</textarea></div><div class="field"><label>Highlight</label><input value="\${esc(s.highlight||'')}" oninput="editSlide('highlight',this.value)"></div></div><h3>Slides</h3><div class="slides">\${state.slides.map((x,i)=>\`<div class="thumb \${i===state.selected?'active':''}" onclick="state.selected=\${i};renderApp()"><div class="mini"><h4>\${esc(x.title||'Slide')}</h4><p>\${esc((x.body||[]).slice(0,2).join(' · '))}</p></div></div>\`).join('')}</div>\`}
function editSlide(k,v){state.slides[state.selected][k]=v;const c=$("#canvas");if(c){const s=state.slides[state.selected];c.querySelector("h2").textContent=s.title||"";renderAppDebounced()}}
let rt;function renderAppDebounced(){clearTimeout(rt);rt=setTimeout(()=>{const active=state.selected;renderApp();state.selected=active},500)}
function addSlide(){state.slides.push({type:"content",title:"New slide",subtitle:"",body:["Add your first point"],highlight:"",speakerNotes:"",layout:"two-column"});state.selected=state.slides.length-1;renderApp()}
async function captureScreen(){
 try{
  const stream=await navigator.mediaDevices.getDisplayMedia({video:{displaySurface:"browser"},audio:false});
  const video=document.createElement("video");video.srcObject=stream;await video.play();await new Promise(r=>setTimeout(r,350));
  const c=document.createElement("canvas");c.width=video.videoWidth;c.height=video.videoHeight;c.getContext("2d").drawImage(video,0,0);
  stream.getTracks().forEach(t=>t.stop());state.capture=c.toDataURL("image/png");$("#capturePreview").innerHTML='<img class="preview" src="'+state.capture+'">';
 }catch(e){alert("Screen capture was cancelled or unavailable.")}
}
function handleFiles(e){const files=[...e.target.files];if(!files.length)return;let done=0;state.capture=[];files.forEach(f=>{const r=new FileReader();r.onload=()=>{state.capture.push(r.result);done++;if(done===files.length)$("#capturePreview").innerHTML=state.capture.map(x=>'<img class="preview" style="max-height:170px;margin-right:8px" src="'+x+'">').join('')};r.readAsDataURL(f)})}
async function generate(){
 if(!state.capture || (Array.isArray(state.capture)&&!state.capture.length))return alert("Capture or upload at least one image.");
 const fd=new FormData();const arr=Array.isArray(state.capture)?state.capture:[state.capture];arr.forEach((x,i)=>{const b64=x.split(",")[1],mime=x.match(/^data:([^;]+)/)?.[1]||"image/png";const bin=atob(b64);const u=new Uint8Array(bin.length);for(let j=0;j<bin.length;j++)u[j]=bin.charCodeAt(j);fd.append("screens",new Blob([u],{type:mime}),"screen-"+i+".png")});fd.append("theme",$("#theme").value);fd.append("slideCount","8");
 const btn=event?.target;try{if(btn)btn.disabled=true;const r=await fetch("/api/ai/generate",{method:"POST",body:fd});const d=await r.json();if(!r.ok)throw Error(d.error);state.title=d.presentation.title||"Untitled presentation";state.slides=d.presentation.slides||[];renderApp();setNotice("Presentation generated. Review and edit it before exporting.","ok")}catch(e){alert(e.message)}finally{if(btn)btn.disabled=false}
}
async function savePresentation(){try{state.title=$("#pptTitle").value||"Untitled presentation";state.theme=$("#theme").value;const d=await api("/api/presentations",{method:"POST",body:JSON.stringify({title:state.title,theme:state.theme,slides:state.slides})});setNotice("Saved to your private library.","ok")}catch(e){setNotice(e.message,"error")}}
async function exportPptx(){try{const title=$("#pptTitle").value||state.title||"Presentation";const theme=$("#theme").value;const r=await fetch("/api/export/pptx",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({title,theme,slides:state.slides})});if(!r.ok){const d=await r.json();throw Error(d.error)}const blob=await r.blob();const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=title.replace(/[^a-z0-9]+/gi,"-")+".pptx";a.click();URL.revokeObjectURL(a.href)}catch(e){alert(e.message)}}
async function changeDesign(){const options=["modern","academic","business","nature","dark"];const current=$("#theme").value;const next=options[(options.indexOf(current)+1)%options.length];$("#theme").value=next;setNotice("Design changed to "+next+". Export when ready.","ok")}
function libraryView(){setTimeout(loadLibrary,0);return \`<h1>My presentations</h1><p class="muted">Only your own saved presentations appear here.</p><div id="library" class="grid"><div class="card">Loading…</div></div>\`}
async function loadLibrary(){try{const d=await api("/api/presentations");$("#library").innerHTML=d.presentations.length?d.presentations.map(x=>\`<div class="card"><h3>\${esc(x.title)}</h3><p class="small muted">\${esc(x.theme)} · \${esc(x.updated_at)}</p><button class="btn secondary" onclick="openPresentation(\${x.id})">Open</button> <button class="btn danger" onclick="deletePresentation(\${x.id})">Delete</button></div>\`).join(''):'<div class="card"><h3>No presentations yet</h3><p class="muted">Create your first one from the dashboard.</p></div>'}catch(e){$("#library").innerHTML='<div class="notice error">'+esc(e.message)+'</div>'}}
async function openPresentation(id){try{const d=await api("/api/presentations/"+id);state.title=d.presentation.title;state.theme=d.presentation.theme;state.slides=d.presentation.slides;state.selected=0;state.view="create";renderApp()}catch(e){alert(e.message)}}
async function deletePresentation(id){if(!confirm("Delete this presentation?"))return;try{await api("/api/presentations/"+id,{method:"DELETE"});loadLibrary()}catch(e){alert(e.message)}}
function adminView(){setTimeout(loadAdmin,0);return \`<h1>Admin console</h1><p class="muted">Aggregate supervision and support tools. Private passwords and private presentation content are not exposed here.</p><div id="adminContent">Loading…</div>\`}
async function loadAdmin(){try{const d=await api("/api/admin/overview"),u=await api("/api/admin/users");$("#adminContent").innerHTML=\`<div class="stats"><div class="card stat">Users<b>\${d.users}</b></div><div class="card stat">Verified<b>\${d.verified}</b></div><div class="card stat">Presentations<b>\${d.presentations}</b></div></div><div class="card" style="margin-top:18px"><h3>User supervision</h3><p class="small muted">Account metadata only. Passwords and private presentation contents are never shown.</p><table><thead><tr><th>Name</th><th>Email</th><th>Plan</th><th>Verified</th><th>Support</th></tr></thead><tbody>\${u.users.map(x=>\`<tr><td>\${esc(x.name)}</td><td>\${esc(x.email)}</td><td>\${x.plan}</td><td>\${x.verified?'Yes':'No'}</td><td>\${x.role==='admin'?'—':'<button class="btn secondary" onclick="supportUser('+x.id+')">Request help</button>'}</td></tr>\`).join('')}</tbody></table></div><div class="card" style="margin-top:18px"><h3>Support requests</h3><div id="supportQueue">Loading…</div></div>\`;const q=await api("/api/admin/support-requests");$("#supportQueue").innerHTML=q.requests.length?q.requests.map(r=>\`<p><b>\${esc(r.user_name)}</b> · \${esc(r.user_email)} · \${r.status} \${r.status==='approved'?'<button class="btn secondary" onclick="supportReset('+r.id+')">Complete authorized reset</button>':''}</p>\`).join(''):'<p class="muted">No support requests.</p>'}catch(e){$("#adminContent").innerHTML='<div class="notice error">'+esc(e.message)+'</div>'}}
async function supportUser(id){try{await api("/api/admin/support-requests",{method:"POST",body:JSON.stringify({userId:id})});alert("Support request created. The user must approve it first.");}catch(e){alert(e.message)}}
async function supportReset(requestId){const code=prompt("Enter the security code sent to the user's registered email:");if(!code)return;const newPassword=prompt("Enter a temporary password to set for the user (minimum 8 characters):");if(!newPassword)return;try{await api("/api/admin/support-reset",{method:"POST",body:JSON.stringify({requestId,code,newPassword})});alert("Password reset completed after user authorization.");loadAdmin()}catch(e){alert(e.message)}}
(async()=>{try{state.user=(await api("/api/me")).user}catch{}render()})();
</script>
</body></html>`;

app.get("/", (_,res)=>res.type("html").send(HTML));

/* Admin bootstrap: set ADMIN_EMAIL and ADMIN_PASSWORD once on first start. */
if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
  const email=normalizeEmail(process.env.ADMIN_EMAIL);
  const existing=db.prepare("SELECT id FROM users WHERE email=?").get(email);
  if(!existing) {
    const hash=bcrypt.hashSync(process.env.ADMIN_PASSWORD,12);
    db.prepare("INSERT INTO users(name,email,password_hash,role,verified) VALUES(?,?,?,?,1)")
      .run(process.env.ADMIN_NAME||"Administrator",email,hash,"admin");
    console.log(`Created admin account: ${email}`);
  }
}

app.listen(PORT, '0.0.0.0', () => console.log('SlideMind running on http://0.0.0.0:${PORT}'));
