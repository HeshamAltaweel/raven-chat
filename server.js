const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const Datastore  = require('nedb-promises');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs   = require('fs');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: '*' },
  maxHttpBufferSize: 10 * 1024 * 1024  // 10MB
});

const JWT_SECRET    = process.env.JWT_SECRET || 'raven_v5_secret';
const PORT          = process.env.PORT || 3000;
const MAX_MSGS_CONV = 200;   // storage saver: keep only last N messages per conv
const COLORS = ['#00d4aa','#7c3aed','#f59e0b','#ef4444','#3b82f6','#ec4899','#10b981','#f97316','#06b6d4'];

// ── Directories ───────────────────────────────────────────────────────────────
const dataDir   = process.env.DATA_DIR || path.join(__dirname, 'data');
const publicDir = path.join(__dirname, 'public');
[dataDir, publicDir].forEach(d => !fs.existsSync(d) && fs.mkdirSync(d, { recursive: true }));

// ── Database ──────────────────────────────────────────────────────────────────
const db = {
  users:   Datastore.create({ filename: path.join(dataDir,'users.db'),   autoload:true }),
  convs:   Datastore.create({ filename: path.join(dataDir,'convs.db'),   autoload:true }),
  members: Datastore.create({ filename: path.join(dataDir,'members.db'), autoload:true }),
  msgs:    Datastore.create({ filename: path.join(dataDir,'msgs.db'),    autoload:true }),
};
db.users.ensureIndex({ fieldName:'username', unique:true });
db.users.ensureIndex({ fieldName:'id' });
db.msgs.ensureIndex({ fieldName:'conversation_id' });
db.members.ensureIndex({ fieldName:'user_id' });
db.members.ensureIndex({ fieldName:'conversation_id' });

// ── FIX #4: Reset ALL users to offline on startup ──────────────────────────────
(async () => {
  try {
    await db.users.update({}, { $set:{ is_online:false } }, { multi:true });
    console.log('✅ All users set offline on startup');
  } catch(e) { console.error('startup reset:', e.message); }
})();

// ── Helper: strip password ────────────────────────────────────────────────────
function safe(u) {
  if (!u) return null;
  const { password_hash, _id, ...r } = u;
  return r;
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json({ limit:'12mb' }));
app.use(express.static(publicDir));
app.get('/.well-known/appspecific/com.chrome.devtools.json', (_,r)=>r.json({}));
app.get('/favicon.ico', (_,r)=>r.status(204).end());

function auth(req, res, next) {
  const t = req.headers.authorization?.split(' ')[1];
  if (!t) return res.status(401).json({ error:'No token' });
  try { req.user = jwt.verify(t, JWT_SECRET); next(); }
  catch { res.status(401).json({ error:'Invalid token' }); }
}

// ═══════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════
app.post('/api/register', async (req,res) => {
  try {
    const { username, password, display_name } = req.body;
    if (!username||!password)             return res.status(400).json({ error:'Username and password required' });
    if (username.length < 3)             return res.status(400).json({ error:'Username must be 3+ chars' });
    if (password.length < 6)             return res.status(400).json({ error:'Password must be 6+ chars' });
    if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error:'Only letters, numbers, underscores' });
    const uname = username.toLowerCase();
    if (await db.users.findOne({ username:uname })) return res.status(400).json({ error:'Username already taken' });
    const id = uuidv4();
    const user = await db.users.insert({
      _id:id, id, username:uname,
      password_hash: await bcrypt.hash(password,10),
      display_name: (display_name||username).trim(),
      bio:'👋 Hey! I\'m using Raven.',
      avatar_color: COLORS[Math.floor(Math.random()*COLORS.length)],
      created_at: new Date().toISOString(),
      last_seen:  new Date().toISOString(),
      is_online: false,
      role: 'user'
    });
    const token = jwt.sign({ id, username:uname }, JWT_SECRET, { expiresIn:'30d' });
    res.json({ token, user:safe(user) });
  } catch(e) {
    if (e.errorType==='uniqueViolated') return res.status(400).json({ error:'Username already taken' });
    console.error('[register]',e.message);
    res.status(500).json({ error:'Server error' });
  }
});

app.post('/api/login', async (req,res) => {
  try {
    const { username, password } = req.body;
    if (!username||!password) return res.status(400).json({ error:'Required' });
    const user = await db.users.findOne({ username:username.toLowerCase() });
    if (!user || !(await bcrypt.compare(password, user.password_hash)))
      return res.status(401).json({ error:'Invalid username or password' });
    const token = jwt.sign({ id:user.id, username:user.username }, JWT_SECRET, { expiresIn:'30d' });
    res.json({ token, user:safe(user) });
  } catch(e) { console.error('[login]',e.message); res.status(500).json({ error:'Server error' }); }
});

// ═══════════════════════════════════════════════════
// USERS
// ═══════════════════════════════════════════════════
app.get('/api/users/me', auth, async (req,res) => {
  const u = await db.users.findOne({ id:req.user.id });
  u ? res.json(safe(u)) : res.status(404).json({ error:'Not found' });
});

app.patch('/api/users/me', auth, async (req,res) => {
  const { display_name, bio } = req.body;
  await db.users.update({ id:req.user.id }, { $set:{ display_name, bio } }, {});
  res.json(safe(await db.users.findOne({ id:req.user.id })));
});

app.get('/api/users/:id', auth, async (req,res) => {
  const u = await db.users.findOne({ id:req.params.id });
  u ? res.json(safe(u)) : res.status(404).json({ error:'Not found' });
});

app.get('/api/users/search/:q', auth, async (req,res) => {
  try {
    const q = req.params.q.toLowerCase();
    const all = await db.users.find({ id:{ $ne:req.user.id } });
    res.json(all.filter(u=>u.username.includes(q)||(u.display_name||'').toLowerCase().includes(q)).slice(0,20).map(safe));
  } catch { res.json([]); }
});

// ═══════════════════════════════════════════════════
// CONVERSATIONS
// ═══════════════════════════════════════════════════
async function buildConv(convId, myId) {
  const conv = await db.convs.findOne({ id:convId });
  if (!conv) return null;
  const memRows = await db.members.find({ conversation_id:convId });
  const members = (await Promise.all(memRows.map(m=>db.users.findOne({ id:m.user_id })))).filter(Boolean).map(safe);
  const allMsgs = await db.msgs.find({ conversation_id:convId });
  allMsgs.sort((a,b)=>new Date(a.created_at)-new Date(b.created_at));
  const last = allMsgs[allMsgs.length-1];
  const unread = allMsgs.filter(m=>m.sender_id!==myId && !(m.read_by||[]).includes(myId)).length;
  let preview = last?.content||null;
  if (last?.type==='image') preview='📷 Photo';
  if (last?.type==='audio') preview='🎤 Voice';
  if (last?.type==='file')  preview='📎 '+(last.file_name||'File');
  return { ...conv, members, last_message:preview, last_message_time:last?.created_at||conv.created_at, unread_count:unread };
}

app.get('/api/conversations', auth, async (req,res) => {
  try {
    const mine = await db.members.find({ user_id:req.user.id });
    if (!mine.length) return res.json([]);
    const list = (await Promise.all(mine.map(m=>buildConv(m.conversation_id, req.user.id)))).filter(Boolean);
    res.json(list.sort((a,b)=>new Date(b.last_message_time)-new Date(a.last_message_time)));
  } catch(e) { console.error('[convs GET]',e.message); res.status(500).json({ error:e.message }); }
});

// Create DM or Group
app.post('/api/conversations', auth, async (req,res) => {
  try {
    const { user_id, is_group, group_name, member_ids } = req.body;

    if (!is_group) {
      // Find existing DM
      const myM  = await db.members.find({ user_id:req.user.id });
      const thM  = await db.members.find({ user_id });
      const mySet = new Set(myM.map(m=>m.conversation_id));
      const shared = thM.find(m=>mySet.has(m.conversation_id));
      if (shared) {
        const ex = await db.convs.findOne({ id:shared.conversation_id, is_group:false });
        if (ex) return res.json({ id:ex.id, existing:true });
      }
      const id = uuidv4();
      await db.convs.insert({ _id:id, id, is_group:false, created_by:req.user.id, created_at:new Date().toISOString() });
      await db.members.insert({ conversation_id:id, user_id:req.user.id });
      await db.members.insert({ conversation_id:id, user_id });

      // FIX #2: Notify recipient to join room
      const convData = await buildConv(id, user_id);
      io.emit(`user_new_conv_${user_id}`, convData);
      return res.json({ id, existing:false });

    } else {
      // Group
      const id = uuidv4();
      await db.convs.insert({ _id:id, id, is_group:true, group_name, created_by:req.user.id, admin:req.user.id, created_at:new Date().toISOString() });
      const allMembers = [...new Set([req.user.id,...(member_ids||[])])];
      await Promise.all(allMembers.map(uid=>db.members.insert({ conversation_id:id, user_id:uid })));

      // Notify all members
      const convData = await buildConv(id, req.user.id);
      allMembers.forEach(uid => { if (uid!==req.user.id) io.emit(`user_new_conv_${uid}`, convData); });
      return res.json({ id, existing:false });
    }
  } catch(e) { console.error('[convs POST]',e.message); res.status(500).json({ error:e.message }); }
});

// ── FIX #8: Group management ──────────────────────────────────────────────────
// Add member to group
app.post('/api/conversations/:id/members', auth, async (req,res) => {
  try {
    const conv = await db.convs.findOne({ id:req.params.id, is_group:true });
    if (!conv) return res.status(404).json({ error:'Group not found' });
    if (conv.admin !== req.user.id) return res.status(403).json({ error:'Only admin can add members' });

    const { user_id } = req.body;
    const exists = await db.members.findOne({ conversation_id:req.params.id, user_id });
    if (exists) return res.status(400).json({ error:'Already a member' });

    await db.members.insert({ conversation_id:req.params.id, user_id });

    const convData = await buildConv(req.params.id, user_id);
    io.emit(`user_new_conv_${user_id}`, convData);

    // Notify group
    const newUser = safe(await db.users.findOne({ id:user_id }));
    io.to(req.params.id).emit('group_updated', { type:'member_added', user:newUser, conversation_id:req.params.id });
    res.json({ success:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// Remove/kick member from group
app.delete('/api/conversations/:id/members/:uid', auth, async (req,res) => {
  try {
    const conv = await db.convs.findOne({ id:req.params.id, is_group:true });
    if (!conv) return res.status(404).json({ error:'Group not found' });
    if (conv.admin !== req.user.id && req.params.uid !== req.user.id)
      return res.status(403).json({ error:'Only admin can remove members' });
    if (req.params.uid === conv.admin) return res.status(400).json({ error:'Cannot remove admin' });

    await db.members.remove({ conversation_id:req.params.id, user_id:req.params.uid }, {});

    io.to(req.params.id).emit('group_updated', { type:'member_removed', userId:req.params.uid, conversation_id:req.params.id });
    res.json({ success:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// Update group info
app.patch('/api/conversations/:id', auth, async (req,res) => {
  try {
    const conv = await db.convs.findOne({ id:req.params.id, is_group:true });
    if (!conv) return res.status(404).json({ error:'Not found' });
    if (conv.admin !== req.user.id) return res.status(403).json({ error:'Admin only' });
    const { group_name } = req.body;
    await db.convs.update({ id:req.params.id }, { $set:{ group_name } }, {});
    io.to(req.params.id).emit('group_updated', { type:'renamed', group_name, conversation_id:req.params.id });
    res.json({ success:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ═══════════════════════════════════════════════════
// MESSAGES
// ═══════════════════════════════════════════════════
app.get('/api/conversations/:id/messages', auth, async (req,res) => {
  try {
    const isMember = await db.members.findOne({ conversation_id:req.params.id, user_id:req.user.id });
    if (!isMember) return res.status(403).json({ error:'Not a member' });

    const msgs = await db.msgs.find({ conversation_id:req.params.id });
    msgs.sort((a,b)=>new Date(a.created_at)-new Date(b.created_at));

    // Mark read
    const toMark = msgs.filter(m=>m.sender_id!==req.user.id && !(m.read_by||[]).includes(req.user.id));
    await Promise.all(toMark.map(m=>db.msgs.update({id:m.id},{$set:{read_by:[...(m.read_by||[]),req.user.id]}},{})));

    // Attach sender info
    const cache = {};
    const result = await Promise.all(msgs.slice(-MAX_MSGS_CONV).map(async msg=>{
      if (!cache[msg.sender_id]) cache[msg.sender_id] = safe(await db.users.findOne({id:msg.sender_id}));
      const u = cache[msg.sender_id];
      return { ...msg, username:u?.username, display_name:u?.display_name, avatar_color:u?.avatar_color };
    }));
    res.json(result);
  } catch(e) { console.error('[msgs GET]',e.message); res.status(500).json({ error:e.message }); }
});

// ── Storage saver: trim old messages ─────────────────────────────────────────
async function trimMessages(convId) {
  try {
    const all = await db.msgs.find({ conversation_id:convId });
    if (all.length <= MAX_MSGS_CONV) return;
    all.sort((a,b)=>new Date(a.created_at)-new Date(b.created_at));
    const toDelete = all.slice(0, all.length - MAX_MSGS_CONV);
    await Promise.all(toDelete.map(m=>db.msgs.remove({id:m.id},{})));
  } catch {}
}

// ── Fallback ──────────────────────────────────────────────────────────────────
app.get('*', (req,res) => {
  const p = path.join(publicDir,'index.html');
  fs.existsSync(p) ? res.sendFile(p) : res.status(404).send('Missing public/index.html');
});

// ═══════════════════════════════════════════════════
// SOCKET.IO
// ═══════════════════════════════════════════════════
const online = new Map(); // userId → Set<socketId>

io.use((socket,next) => {
  try { socket.user = jwt.verify(socket.handshake.auth.token, JWT_SECRET); next(); }
  catch { next(new Error('Invalid token')); }
});

io.on('connection', async socket => {
  const uid = socket.user.id;

  if (!online.has(uid)) online.set(uid, new Set());
  online.get(uid).add(socket.id);

  // FIX #4: Only mark online when socket connects
  await db.users.update({id:uid},{$set:{last_seen:new Date().toISOString()}},{});
  // online status not broadcast to preserve user privacy

  // Join all conversation rooms
  const memberships = await db.members.find({ user_id:uid });
  memberships.forEach(m=>socket.join(m.conversation_id));

  // Listen for user-specific new_conv event (used to notify recipient of DM)
  socket.join(`user_${uid}`);

  console.log(`✅ ${socket.user.username} connected (${online.get(uid).size} tabs)`);

  // ── Send message ────────────────────────────────────────────────────────────
  socket.on('send_message', async ({ conversation_id, content, type='text', file_name, file_size, duration, voice_mime }) => {
    try {
      const isMember = await db.members.findOne({ conversation_id, user_id:uid });
      if (!isMember) return;

      const id = uuidv4();
      const now = new Date().toISOString();
      await db.msgs.insert({ _id:id, id, conversation_id, sender_id:uid, content, type, file_name:file_name||null, file_size:file_size||null, duration:duration||null, voice_mime:voice_mime||null, read_by:[uid], created_at:now });

      trimMessages(conversation_id);

      const user = await db.users.findOne({ id:uid });
      const msg  = { id, conversation_id, sender_id:uid, content, type, file_name:file_name||null, file_size:file_size||null, duration:duration||null, voice_mime:voice_mime||null, read_by:[uid], created_at:now, username:user.username, display_name:user.display_name, avatar_color:user.avatar_color };

      io.to(conversation_id).emit('new_message', msg);
    } catch(e) { console.error('[send_message]',e.message); }
  });

  // Join specific conversation room (called after creating new conv)
  socket.on('join_conv', async ({ conversation_id }) => {
    const m = await db.members.findOne({ conversation_id, user_id:uid });
    if (m) socket.join(conversation_id);
  });

  // Typing
  socket.on('typing', ({ conversation_id, isTyping }) => {
    socket.to(conversation_id).emit('user_typing', { userId:uid, isTyping, conversation_id });
  });

  // Group events
  socket.on('group_updated', data => {
    io.to(data.conversation_id).emit('group_updated', data);
  });

  // Disconnect
  socket.on('disconnect', async () => {
    online.get(uid)?.delete(socket.id);
    if (!online.get(uid)?.size) {
      online.delete(uid);
      await db.users.update({id:uid},{$set:{last_seen:new Date().toISOString()}},{});
      // online status not broadcast to preserve user privacy
    }
    console.log(`❌ ${socket.user.username} disconnected`);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log('\n╔══════════════════════════════════════╗');
  console.log('║   🐦 Raven Chat v5  —  Ready!        ║');
  console.log(`║   ➜  http://localhost:${PORT}           ║`);
  console.log('╚══════════════════════════════════════╝\n');
});
