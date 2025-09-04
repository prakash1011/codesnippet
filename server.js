const express = require('express');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

// snippets storage
const DATA_FILE = path.join(__dirname, 'snippets.json');
let snippets = [];
if (fs.existsSync(DATA_FILE)) {
  try { snippets = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch(e) { snippets = []; }
}
function saveSnip() {fs.writeFileSync(DATA_FILE, JSON.stringify(snippets, null, 2));}

// users storage (email + passwordHash)
const USER_FILE = path.join(__dirname, 'users.json');
let users = [];
if (fs.existsSync(DATA_FILE)) {
  try { 
    snippets = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    // If any snippets don't have an email, add a default one (for existing data)
    snippets = snippets.map(snippet => {
      if (!snippet.email) {
        snippet.email = 'default@example.com'; // Or any default email
      }
      return snippet;
    });
    saveSnip(); // Save the updated snippets
  } catch(e) { 
    snippets = []; 
  }
}

function saveUsers() {fs.writeFileSync(USER_FILE, JSON.stringify(users, null, 2));}

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';

// Postgres (optional if DATABASE_URL is set)
const { Pool } = require('pg');
const useDb = !!process.env.DATABASE_URL;
let pool;
if(useDb){
  const isLocal = process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost');
  pool = new Pool({connectionString: process.env.DATABASE_URL, ssl: isLocal?false:{rejectUnauthorized:false}});
  pool.query('CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, password_hash TEXT NOT NULL);');
  pool.query('CREATE TABLE IF NOT EXISTS snippets (id SERIAL PRIMARY KEY, email TEXT NOT NULL, title TEXT NOT NULL, language TEXT NOT NULL, code TEXT NOT NULL, created_at TIMESTAMP DEFAULT NOW());');
}


function authMiddleware(req,res,next){
  const hdr = req.headers['authorization']||'';
  const token = hdr.startsWith('Bearer ')?hdr.slice(7):null;
  if(!token) return res.status(401).json({error:'Missing token'});
  try{req.user = jwt.verify(token, JWT_SECRET);}catch(e){return res.status(401).json({error:'Invalid token'});}
  next();
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// APIs
// ---------- Auth Routes ----------
app.post('/api/register', async (req,res)=>{
  const {email,password}=req.body;
  if(!email||!password) return res.status(400).json({error:'Email and password required'});
  try {
    const hash = await bcrypt.hash(password,10);
    if(useDb){
      const {rows} = await pool.query('SELECT 1 FROM users WHERE email=$1',[email]);
      if(rows.length) return res.status(400).json({error:'User exists'});
      await pool.query('INSERT INTO users(email,password_hash) VALUES($1,$2)',[email,hash]);
    } else {
      if(users.find(u=>u.email===email)) return res.status(400).json({error:'User exists'});
      users.push({email,passwordHash:hash});
      saveUsers();
    }
    res.json({message:'Registered'});
  } catch(err){
    console.error(err);
    res.status(500).json({error:'Server error'});
  }
});

app.post('/api/login', async (req,res)=>{
  const {email,password}=req.body;
  let passwordHash;
  if(useDb){
    const {rows}=await pool.query('SELECT password_hash FROM users WHERE email=$1',[email]);
    if(!rows.length) return res.status(400).json({error:'Invalid credentials'});
    passwordHash = rows[0].password_hash;
  } else {
    const user = users.find(u=>u.email===email);
    if(!user) return res.status(400).json({error:'Invalid credentials'});
    passwordHash = user.passwordHash;
  }
  const ok = await bcrypt.compare(password,passwordHash);
  if(!ok) return res.status(400).json({error:'Invalid credentials'});
  const token = jwt.sign({email}, JWT_SECRET, {expiresIn:'7d'});
  res.json({token});
});

// ---------- Snippet Routes (protected) ----------
app.get('/api/snippets', authMiddleware, async (req, res) => {
  try {
    if(useDb){
      const {rows} = await pool.query(
        'SELECT id, title, language, created_at FROM snippets WHERE email = $1 ORDER BY created_at DESC',
        [req.user.email]
      );
      res.json(rows);
    } else {
      const userSnippets = snippets
        .filter(snip => snip.email === req.user.email)
        .map(({id, title, language, created_at}) => ({id, title, language, created_at}));
      res.json(userSnippets);
    }
  } catch (error) {
    console.error('Error fetching snippets:', error);
    res.status(500).json({ error: 'Server error while fetching snippets' });
  }
});

app.get('/api/snippets/:id', authMiddleware, async (req, res) => {
  try {
    if(useDb){
      const {rows} = await pool.query(
        'SELECT * FROM snippets WHERE id = $1 AND email = $2',
        [req.params.id, req.user.email]
      );
      if(!rows.length) return res.status(404).json({error:'Not found or unauthorized'});
      res.json(rows[0]);
    } else {
      const snip = snippets.find(s => s.id == req.params.id && s.email === req.user.email);
      if (!snip) return res.status(404).json({ error: 'Not found or unauthorized' });
      res.json(snip);
    }
  } catch (error) {
    console.error('Error fetching snippet:', error);
    res.status(500).json({ error: 'Server error while fetching snippet' });
  }
});

app.post('/api/snippets', authMiddleware, async (req, res) => {
  const { title, language, code } = req.body;
  if (!title || !language || !code) return res.status(400).json({ error: 'Missing fields' });
  
  try {
    if(useDb){
      const {rows} = await pool.query(
        'INSERT INTO snippets(email, title, language, code) VALUES($1, $2, $3, $4) RETURNING id',
        [req.user.email, title, language, code]
      );
      res.json({id: rows[0].id});
    } else {
      const id = snippets.length ? Math.max(...snippets.map(s => s.id)) + 1 : 1;
      const snip = {
        id,
        email: req.user.email,  // Add user's email to the snippet
        title,
        language,
        code,
        created_at: new Date().toISOString()
      };
      snippets.push(snip);
      saveSnip();
      res.json({ id });
    }
  } catch (error) {
    console.error('Error saving snippet:', error);
    res.status(500).json({ error: 'Server error while saving snippet' });
  }
});

app.delete('/api/snippets/:id', authMiddleware, async (req, res) => {
  try {
    if(useDb) {
      const { rowCount } = await pool.query(
        'DELETE FROM snippets WHERE id = $1 AND email = $2',
        [req.params.id, req.user.email]
      );
      if (rowCount === 0) return res.status(404).json({ error: 'Snippet not found or unauthorized' });
    } else {
      const index = snippets.findIndex(s => s.id == req.params.id && s.email === req.user.email);
      if (index === -1) return res.status(404).json({ error: 'Snippet not found or unauthorized' });
      snippets.splice(index, 1);
      saveSnip();
    }
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting snippet:', error);
    res.status(500).json({ error: 'Server error while deleting snippet' });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server listening on port ${PORT}`));
