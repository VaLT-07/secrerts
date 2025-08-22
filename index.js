// Minimal Secrets App (file-based persistence)
// Run: npm install && npm start
require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SECRETS_FILE = path.join(DATA_DIR, 'secrets.json');

const app = express();
app.use(helmet());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/public', express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const NODE_ENV = process.env.NODE_ENV || 'development';
const COOKIE_OPTS = { httpOnly: true, sameSite: 'lax', secure: NODE_ENV === 'production' };

async function ensureFiles() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  if (!fsSync.existsSync(USERS_FILE)) await fs.writeFile(USERS_FILE, '[]', 'utf8');
  if (!fsSync.existsSync(SECRETS_FILE)) await fs.writeFile(SECRETS_FILE, '[]', 'utf8');
}

async function readJSON(file){ const raw = await fs.readFile(file,'utf8'); return JSON.parse(raw||'[]'); }
async function writeJSON(file, obj){ await fs.writeFile(file, JSON.stringify(obj, null, 2), 'utf8'); }

// middleware attach user if token present
function attachUser(secret){
  return (req, res, next) => {
    const token = req.cookies?.token;
    if (token) {
      try { const p = jwt.verify(token, secret); req.user = { id: p.sub, name: p.name, email: p.email }; }
      catch(e) { /* ignore */ }
    }
    next();
  };
}

function authRequired(secret){
  return (req, res, next) => {
    const token = req.cookies?.token;
    if (!token) return res.redirect('/login');
    try { const p = jwt.verify(token, secret); req.user = { id: p.sub, name: p.name, email: p.email }; next(); }
    catch(e){ return res.redirect('/login'); }
  };
}

app.use(attachUser(JWT_SECRET));

// Pages use layout.ejs and include content by name
app.get('/', (req, res) => { if(req.user) return res.redirect('/dashboard'); res.redirect('/login'); });

app.get('/register', (req, res) => res.render('layout', { title: 'Register', user: req.user, content: 'register', errors: [], form: {} }));

const registerValidators = [
  body('name').trim().notEmpty().withMessage('Name required').isLength({ max:60 }).withMessage('Name too long'),
  body('email').trim().toLowerCase().isEmail().withMessage('Valid email required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 chars')
    .matches(/[a-z]/).withMessage('Password must have a lowercase letter')
    .matches(/[A-Z]/).withMessage('Password must have an uppercase letter')
    .matches(/[0-9]/).withMessage('Password must have a number'),
  body('confirmPassword').custom((v,{req})=> v===req.body.password).withMessage('Passwords must match')
];

app.post('/register', registerValidators, async (req, res) => {
  const errors = validationResult(req);
  const { name, email, password } = req.body;
  if (!errors.isEmpty()) return res.status(400).render('layout', { title:'Register', user:req.user, content:'register', errors: errors.array(), form: { name, email } });
  try {
    const users = await readJSON(USERS_FILE);
    if (users.find(u=>u.email===email)) return res.status(400).render('layout',{title:'Register',user:req.user,content:'register',errors:[{msg:'Email already registered'}],form:{name,email}});
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const id = Date.now().toString(36)+Math.random().toString(36).slice(2,8);
    users.push({ id, name, email, passwordHash: hash, createdAt: new Date().toISOString() });
    await writeJSON(USERS_FILE, users);
    return res.redirect('/login');
  } catch(e){ console.error(e); return res.status(500).render('layout',{title:'Register',user:req.user,content:'register',errors:[{msg:'Server error'}],form:{name,email}}); }
});

app.get('/login', (req, res) => res.render('layout', { title:'Login', user:req.user, content:'login', errors: [], form: {} }));

const loginValidators = [
  body('email').trim().toLowerCase().isEmail().withMessage('Valid email required'),
  body('password').isLength({ min: 6 }).withMessage('Invalid password')
];

app.post('/login', loginValidators, async (req, res) => {
  const errors = validationResult(req);
  const { email, password } = req.body;
  if (!errors.isEmpty()) return res.status(400).render('layout',{title:'Login',user:req.user,content:'login',errors:errors.array(),form:{email}});
  try {
    const users = await readJSON(USERS_FILE);
    const user = users.find(u=>u.email===email);
    if (!user) return res.status(401).render('layout',{title:'Login',user:req.user,content:'login',errors:[{msg:'Invalid credentials'}],form:{email}});
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).render('layout',{title:'Login',user:req.user,content:'login',errors:[{msg:'Invalid credentials'}],form:{email}});
    const token = jwt.sign({ sub: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '2h' });
    res.cookie('token', token, { ...COOKIE_OPTS, maxAge: 1000*60*60*2 });
    return res.redirect('/dashboard');
  } catch(e){ console.error(e); return res.status(500).render('layout',{title:'Login',user:req.user,content:'login',errors:[{msg:'Server error'}],form:{email}}); }
});

app.get('/dashboard', authRequired(JWT_SECRET), async (req, res) => {
  const secrets = await readJSON(SECRETS_FILE);
  const userSecrets = secrets.filter(s => s.userId === req.user.id).slice().reverse();
  res.render('layout', { title:'Dashboard', user: req.user, content: 'dashboard', errors: [], secrets: userSecrets });
});

app.post('/secrets', authRequired(JWT_SECRET), [ body('text').trim().isLength({ min:1, max:1000 }).withMessage('Secret must not be empty') ], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const secrets = await readJSON(SECRETS_FILE);
    const userSecrets = secrets.filter(s => s.userId === req.user.id).slice().reverse();
    return res.status(400).render('layout', { title:'Dashboard', user:req.user, content:'dashboard', errors: errors.array(), secrets: userSecrets });
  }
  try {
    const secrets = await readJSON(SECRETS_FILE);
    const id = Date.now().toString(36)+Math.random().toString(36).slice(2,6);
    secrets.push({ id, userId: req.user.id, text: req.body.text, createdAt: new Date().toISOString() });
    await writeJSON(SECRETS_FILE, secrets);
    return res.redirect('/dashboard');
  } catch(e){ console.error(e); return res.status(500).render('layout',{title:'Dashboard',user:req.user,content:'dashboard',errors:[{msg:'Server error'}]}); }
});

app.post('/logout', (req, res) => { res.clearCookie('token', COOKIE_OPTS); res.redirect('/login'); });

// 404
app.use((req, res) => res.status(404).render('layout', { title:'Not Found', user:req.user, content:'404', errors: [], }));

(async function(){ await ensureFiles(); // create demo user if none
  const users = await readJSON(USERS_FILE);
  if (users.length===0) {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash('DemoPass1', salt);
    users.push({ id: 'demo', name: 'Demo User', email: 'demo@example.com', passwordHash: hash, createdAt: new Date().toISOString() });
    await writeJSON(USERS_FILE, users);
    console.log('Created demo user: demo@example.com / DemoPass1');
  }
  if (!fsSync.existsSync(SECRETS_FILE)) await writeJSON(SECRETS_FILE, []);
  app.listen(PORT, ()=> console.log('Server listening on', PORT));
})();