const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DB_DIR = process.env.DB_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(DB_DIR, { recursive: true });
const db = new Database(path.join(DB_DIR, 'moneytalk.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
 email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'member', bio TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS posts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
 category TEXT NOT NULL CHECK(category IN ('News','Fiat money','Cryptocurrency')),
 title TEXT NOT NULL, body TEXT NOT NULL, link TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS comments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS likes (
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
 PRIMARY KEY(user_id, post_id)
);
CREATE INDEX IF NOT EXISTS posts_created_idx ON posts(created_at DESC);
CREATE INDEX IF NOT EXISTS comments_post_idx ON comments(post_id, created_at);
`);

// Optional first administrator. Set ADMIN_EMAIL and ADMIN_PASSWORD in the hosting environment.
if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
  const email = process.env.ADMIN_EMAIL.trim().toLowerCase();
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!existing) {
    const username = (process.env.ADMIN_USERNAME || 'Admin').trim().slice(0, 24) || 'Admin';
    const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
    try { db.prepare("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,'admin')").run(username,email,hash); }
    catch (e) { console.error('Could not create initial admin:', e.message); }
  } else {
    db.prepare("UPDATE users SET role='admin' WHERE email=?").run(email);
  }
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "https://fonts.googleapis.com"],
  fontSrc: ["'self'", "https://fonts.gstatic.com"], imgSrc: ["'self'", 'data:', 'https:'],
  connectSrc: ["'self'"], objectSrc: ["'none'"], upgradeInsecureRequests: []
}}}));
app.use(express.json({ limit: '30kb' }));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: DB_DIR }),
  secret: process.env.SESSION_SECRET || 'change-this-secret-before-deploying-moneytalk',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7*24*60*60*1000 }
}));
const authLimiter = rateLimit({ windowMs: 15*60*1000, limit: 12, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many attempts. Please try again in 15 minutes.' } });
const writeLimiter = rateLimit({ windowMs: 60*1000, limit: 25, standardHeaders: 'draft-7', legacyHeaders: false });
const publicUser = u => ({ id:u.id, username:u.username, role:u.role, bio:u.bio, createdAt:u.created_at });
const currentUser = req => req.session.userId ? db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId) : null;
function requireAuth(req,res,next){ const u=currentUser(req); if(!u) return res.status(401).json({error:'Please sign in first.'}); req.user=u; next(); }
function requireAdmin(req,res,next){ if(req.user.role!=='admin') return res.status(403).json({error:'Administrator access required.'}); next(); }
function cleanText(v,max){ return typeof v==='string' ? v.trim().slice(0,max) : ''; }
function validLink(v){ if(!v) return true; try { const u=new URL(v); return ['http:','https:'].includes(u.protocol); } catch { return false; } }

app.get('/api/health', (req,res)=>res.json({ok:true, name:'MoneyTalk API', version:'2.0.0'}));
app.get('/api/auth/me',(req,res)=>{ const u=currentUser(req); res.json({user:u?publicUser(u):null}); });
app.post('/api/auth/register',authLimiter,async(req,res)=>{
 const username=cleanText(req.body.username,24), email=cleanText(req.body.email,120).toLowerCase(), password=typeof req.body.password==='string'?req.body.password:'';
 if(!/^[\p{L}\p{N}_ -]{3,24}$/u.test(username)) return res.status(400).json({error:'Username must be 3–24 characters and use letters, numbers, spaces, _ or -.'});
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:'Enter a valid email address.'});
 if(password.length<10 || password.length>128) return res.status(400).json({error:'Password must be at least 10 characters.'});
 if(db.prepare('SELECT id FROM users WHERE email=? OR username=? COLLATE NOCASE').get(email,username)) return res.status(409).json({error:'That email or username is already registered.'});
 const hash=await bcrypt.hash(password,12);
 try { const r=db.prepare('INSERT INTO users(username,email,password_hash) VALUES(?,?,?)').run(username,email,hash); req.session.userId=Number(r.lastInsertRowid); res.status(201).json({user:publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId))}); }
 catch(e){res.status(400).json({error:'Could not create account. Please try another username or email.'});}
});
app.post('/api/auth/login',authLimiter,async(req,res)=>{
 const email=cleanText(req.body.email,120).toLowerCase(), password=typeof req.body.password==='string'?req.body.password:'';
 const u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
 if(!u || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:'Email or password is incorrect.'});
 req.session.regenerate(err=>{ if(err)return res.status(500).json({error:'Could not start your session.'}); req.session.userId=u.id; res.json({user:publicUser(u)}); });
});
app.post('/api/auth/logout',requireAuth,(req,res)=>req.session.destroy(()=>{res.clearCookie('connect.sid');res.json({ok:true});}));
app.patch('/api/profile',requireAuth,writeLimiter,(req,res)=>{
 const bio=cleanText(req.body.bio,240); db.prepare('UPDATE users SET bio=? WHERE id=?').run(bio,req.user.id);
 res.json({user:publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id))});
});

const postSelect=`SELECT p.id,p.category,p.title,p.body,p.link,p.created_at,
 u.id AS author_id,u.username AS author,
 (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) AS likes,
 (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) AS comment_count
 FROM posts p JOIN users u ON u.id=p.user_id`;
app.get('/api/posts',(req,res)=>{
 const category=['News','Fiat money','Cryptocurrency'].includes(req.query.category)?req.query.category:null;
 const q=cleanText(req.query.q,100);
 let sql=postSelect, params=[]; const clauses=[];
 if(category){clauses.push('p.category=?');params.push(category)}
 if(q){clauses.push('(p.title LIKE ? OR p.body LIKE ? OR u.username LIKE ?)');params.push(`%${q}%`,`%${q}%`,`%${q}%`)}
 if(clauses.length)sql+=' WHERE '+clauses.join(' AND ');
 sql+=' ORDER BY p.created_at DESC,p.id DESC LIMIT 100';
 const rows=db.prepare(sql).all(...params).map(p=>({...p,liked:!!(req.session.userId&&db.prepare('SELECT 1 FROM likes WHERE user_id=? AND post_id=?').get(req.session.userId,p.id))}));
 res.json({posts:rows});
});
app.post('/api/posts',requireAuth,writeLimiter,(req,res)=>{
 const category=cleanText(req.body.category,30),title=cleanText(req.body.title,120),body=cleanText(req.body.body,4000),link=cleanText(req.body.link,500);
 if(!['News','Fiat money','Cryptocurrency'].includes(category))return res.status(400).json({error:'Choose a valid category.'});
 if(category==='News'&&req.user.role!=='admin')return res.status(403).json({error:'Only administrators can publish home-page news.'});
 if(title.length<4||body.length<10)return res.status(400).json({error:'Title must be at least 4 characters and message at least 10 characters.'});
 if(!validLink(link))return res.status(400).json({error:'Links must begin with http:// or https://.'});
 const r=db.prepare('INSERT INTO posts(user_id,category,title,body,link) VALUES(?,?,?,?,?)').run(req.user.id,category,title,body,link);
 res.status(201).json({post:db.prepare(postSelect+' WHERE p.id=?').get(r.lastInsertRowid)});
});
app.delete('/api/posts/:id',requireAuth,writeLimiter,(req,res)=>{
 const p=db.prepare('SELECT * FROM posts WHERE id=?').get(Number(req.params.id)); if(!p)return res.status(404).json({error:'Post not found.'});
 if(req.user.role!=='admin'&&p.user_id!==req.user.id)return res.status(403).json({error:'You can only delete your own posts.'});
 db.prepare('DELETE FROM posts WHERE id=?').run(p.id);res.json({ok:true});
});
app.post('/api/posts/:id/like',requireAuth,writeLimiter,(req,res)=>{
 const id=Number(req.params.id);if(!db.prepare('SELECT id FROM posts WHERE id=?').get(id))return res.status(404).json({error:'Post not found.'});
 const exists=db.prepare('SELECT 1 FROM likes WHERE user_id=? AND post_id=?').get(req.user.id,id);
 if(exists)db.prepare('DELETE FROM likes WHERE user_id=? AND post_id=?').run(req.user.id,id);else db.prepare('INSERT INTO likes(user_id,post_id) VALUES(?,?)').run(req.user.id,id);
 res.json({liked:!exists,likes:db.prepare('SELECT COUNT(*) AS n FROM likes WHERE post_id=?').get(id).n});
});
app.get('/api/posts/:id/comments',(req,res)=>{
 const id=Number(req.params.id);const comments=db.prepare(`SELECT c.id,c.body,c.created_at,u.username AS author FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.created_at,c.id`).all(id);res.json({comments});
});
app.post('/api/posts/:id/comments',requireAuth,writeLimiter,(req,res)=>{
 const id=Number(req.params.id),body=cleanText(req.body.body,1200);if(!db.prepare('SELECT id FROM posts WHERE id=?').get(id))return res.status(404).json({error:'Post not found.'});if(body.length<2)return res.status(400).json({error:'Comment is too short.'});
 const r=db.prepare('INSERT INTO comments(post_id,user_id,body) VALUES(?,?,?)').run(id,req.user.id,body);res.status(201).json({comment:db.prepare('SELECT c.id,c.body,c.created_at,u.username AS author FROM comments c JOIN users u ON u.id=c.user_id WHERE c.id=?').get(r.lastInsertRowid)});
});
app.delete('/api/comments/:id',requireAuth,(req,res)=>{
 const c=db.prepare('SELECT * FROM comments WHERE id=?').get(Number(req.params.id));if(!c)return res.status(404).json({error:'Comment not found.'});if(req.user.role!=='admin'&&c.user_id!==req.user.id)return res.status(403).json({error:'You can only delete your own comments.'});db.prepare('DELETE FROM comments WHERE id=?').run(c.id);res.json({ok:true});
});
app.get('/api/admin/stats',requireAuth,requireAdmin,(req,res)=>res.json({users:db.prepare('SELECT COUNT(*) n FROM users').get().n,posts:db.prepare('SELECT COUNT(*) n FROM posts').get().n,comments:db.prepare('SELECT COUNT(*) n FROM comments').get().n}));
app.get('/api/admin/users',requireAuth,requireAdmin,(req,res)=>res.json({users:db.prepare('SELECT id,username,email,role,created_at FROM users ORDER BY created_at DESC LIMIT 200').all()}));
app.patch('/api/admin/users/:id',requireAuth,requireAdmin,(req,res)=>{
 const id=Number(req.params.id),role=req.body.role;if(!['member','admin'].includes(role))return res.status(400).json({error:'Invalid role.'});if(id===req.user.id&&role!=='admin')return res.status(400).json({error:'You cannot remove your own administrator role.'});const r=db.prepare('UPDATE users SET role=? WHERE id=?').run(role,id);if(!r.changes)return res.status(404).json({error:'User not found.'});res.json({ok:true});
});
app.use(express.static(path.join(__dirname,'..','public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'..','public','index.html')));
app.listen(PORT,()=>console.log(`MoneyTalk V2 running on port ${PORT}`));
