const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json({ limit: '50mb' }));

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET || 'alfasecurity_secret';
const PORT = process.env.PORT || 3003;

// ── ADD ONESIGNAL COLUMN IF MISSING ──────────────────────────────────────────
pool.query(`DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='onesignal_player_id')
  THEN ALTER TABLE users ADD COLUMN onesignal_player_id TEXT; END IF;
END $$;`).catch(e => console.error('OneSignal column error:', e.message));

// ── AUTO-CREATE VESTIARIO TABLES ──────────────────────────────────────────────
pool.query(`
  CREATE TABLE IF NOT EXISTS security_vestiario (
    id TEXT PRIMARY KEY,
    operatore_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    nome_operatore TEXT, cognome_operatore TEXT,
    giacca_taglia TEXT, giacca_possesso TEXT, giacca_radio TEXT,
    maglietta_taglia TEXT, maglietta_possesso TEXT, maglietta_radio TEXT,
    pantaloni_taglia TEXT, pantaloni_possesso TEXT, pantaloni_radio TEXT,
    felpa_taglia TEXT, felpa_possesso TEXT, felpa_radio TEXT,
    richiesta_capo TEXT, richiesta_motivo TEXT, richiesta_altro TEXT,
    foto1 TEXT, foto2 TEXT, foto3 TEXT,
    stato_richiesta TEXT, motivazione_admin TEXT,
    data_creazione TIMESTAMPTZ DEFAULT NOW(), data_richiesta TIMESTAMPTZ
  );
  CREATE TABLE IF NOT EXISTS magazzino_vestiario (
    id TEXT PRIMARY KEY, tipo_capo TEXT NOT NULL, taglia TEXT NOT NULL,
    quantita_stock INTEGER DEFAULT 0, quantita_disponibile INTEGER DEFAULT 0,
    quantita_assegnata INTEGER DEFAULT 0,
    data_aggiornamento TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tipo_capo, taglia)
  );
  CREATE TABLE IF NOT EXISTS assegnazioni_vestiario (
    id TEXT PRIMARY KEY, operatore_id TEXT REFERENCES users(id),
    nome_operatore TEXT, tipo_capo TEXT, taglia TEXT,
    data_consegna TIMESTAMPTZ DEFAULT NOW(), quantita INTEGER DEFAULT 1, note TEXT
  );
  CREATE TABLE IF NOT EXISTS storico_sostituzioni_vestiario (
    id TEXT PRIMARY KEY, operatore_id TEXT REFERENCES users(id),
    nome_operatore TEXT, tipo_capo TEXT, motivo_sostituzione TEXT,
    data_sostituzione TIMESTAMPTZ DEFAULT NOW(), richiesta_id TEXT, note_admin TEXT
  );
`).catch(e => console.error('Vestiario tables init error:', e.message));

// ── PRIMA FORNITURE TABLE ──────────────────────────────────────────────────────
pool.query(`CREATE TABLE IF NOT EXISTS prime_forniture (
  id TEXT PRIMARY KEY,
  operatore_id TEXT REFERENCES users(id),
  nome_operatore TEXT, cognome_operatore TEXT,
  admin_id TEXT, admin_nome TEXT,
  giacca INTEGER DEFAULT 0, maglietta INTEGER DEFAULT 0,
  pantaloni INTEGER DEFAULT 0, felpa INTEGER DEFAULT 0, radio INTEGER DEFAULT 0,
  note TEXT,
  data_fornitura TIMESTAMPTZ DEFAULT NOW(),
  messaggio_inviato BOOLEAN DEFAULT FALSE,
  messaggio_inviato_at TIMESTAMPTZ
);`).catch(e => console.error('prime_forniture table error:', e.message));

// ── ADD RADIO_STATO COLUMN IF MISSING ─────────────────────────────────────────
pool.query(`DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='security_vestiario' AND column_name='radio_stato')
  THEN ALTER TABLE security_vestiario ADD COLUMN radio_stato TEXT; END IF;
END $$;`).catch(e => console.error('radio_stato migration error:', e.message));

// ── ADD AMMINISTRAZIONE DETTAGLIO COLUMNS IF MISSING ──────────────────────────
pool.query(`DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='amministrazione_mensile' AND column_name='societa_varie_dettaglio')
  THEN ALTER TABLE amministrazione_mensile ADD COLUMN societa_varie_dettaglio TEXT DEFAULT '[]'; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='amministrazione_mensile' AND column_name='costi_vari_dettaglio')
  THEN ALTER TABLE amministrazione_mensile ADD COLUMN costi_vari_dettaglio TEXT DEFAULT '[]'; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='is_supervisore')
  THEN ALTER TABLE users ADD COLUMN is_supervisore BOOLEAN DEFAULT FALSE; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='rinnovo_matricola')
  THEN ALTER TABLE users ADD COLUMN rinnovo_matricola TEXT; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='istanza_data')
  THEN ALTER TABLE users ADD COLUMN istanza_data DATE; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='istanza_supporto_data')
  THEN ALTER TABLE users ADD COLUMN istanza_supporto_data DATE; END IF;
END $$;`).catch(e => console.error('Migrations error:', e.message));

// ── Auth middleware ──────────────────────────────────────────────────────────
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'Token mancante' });
  try {
    req.user = jwt.verify(h.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token non valido' });
  }
}
function adminOnly(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Solo admin' });
  next();
}
function supervisorOrAdmin(req, res, next) {
  if (!req.user?.is_admin && !req.user?.is_supervisore) return res.status(403).json({ error: 'Accesso negato' });
  next();
}

// ── AUTH ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const r = await pool.query('SELECT * FROM users WHERE LOWER(email)=LOWER($1)', [email]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ error: 'Email o password non corretti' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Email o password non corretti' });
    if (user.blocked && !user.is_admin) return res.status(403).json({ error: 'Account sospeso. Contatta l\'amministratore.' });
    const token = jwt.sign(
      { id: user.id, email: user.email, is_admin: user.is_admin, is_supervisore: !!user.is_supervisore, nome: user.nome, cognome: user.cognome },
      JWT_SECRET, { expiresIn: '24h' }
    );
    res.json({ token, user: { id: user.id, email: user.email, is_admin: user.is_admin, is_supervisore: !!user.is_supervisore, nome: user.nome, cognome: user.cognome, has_push: !!user.onesignal_player_id } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Campi mancanti' });
    const exists = await pool.query('SELECT id FROM users WHERE LOWER(email)=LOWER($1)', [email]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email già registrata' });
    const hash = await bcrypt.hash(password, 10);
    const id = uuidv4();
    await pool.query(
      'INSERT INTO users (id,email,password_hash,is_admin,created_at) VALUES ($1,$2,$3,FALSE,NOW())',
      [id, email, hash]
    );
    const token = jwt.sign({ id, email, is_admin: false, nome: '', cognome: '' }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id, email, is_admin: false, nome: '', cognome: '' } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── USERS ─────────────────────────────────────────────────────────────────────
const USER_COLS = 'id,email,is_admin,is_supervisore,nome,cognome,telefono,indirizzo,data_nascita,codice_fiscale,nr_matricola,matricola_rilasciata,matricola_scadenza,iban,blocked,disclaimer_accepted,disclaimer_accepted_at,created_at,rinnovo_matricola,istanza_data,istanza_supporto_data';

app.get('/api/users', auth, supervisorOrAdmin, async (req, res) => {
  try {
    const r = await pool.query(`SELECT ${USER_COLS} FROM users WHERE is_admin=FALSE ORDER BY created_at`);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users/:id', auth, async (req, res) => {
  try {
    if (!req.user.is_admin && !req.user.is_supervisore && req.user.id !== req.params.id)
      return res.status(403).json({ error: 'Accesso negato' });
    const r = await pool.query(`SELECT ${USER_COLS} FROM users WHERE id=$1`, [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Utente non trovato' });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/users/:id', auth, async (req, res) => {
  try {
    if (!req.user.is_admin && req.user.id !== req.params.id)
      return res.status(403).json({ error: 'Accesso negato' });
    const { nome, cognome, email, telefono, indirizzo, data_nascita, codice_fiscale, iban, nr_matricola, matricola_rilasciata, matricola_scadenza, password, rinnovo_matricola, istanza_data, istanza_supporto_data } = req.body;
    let q, params;
    if (req.user.is_admin) {
      if (password) {
        const hash = await bcrypt.hash(password, 10);
        q = `UPDATE users SET nome=$1,cognome=$2,email=$3,telefono=$4,indirizzo=$5,data_nascita=$6,codice_fiscale=$7,iban=$8,nr_matricola=$9,matricola_rilasciata=$10,matricola_scadenza=$11,password_hash=$12,rinnovo_matricola=$13,istanza_data=$14,istanza_supporto_data=$15 WHERE id=$16 RETURNING ${USER_COLS}`;
        params = [nome, cognome, email, telefono, indirizzo, data_nascita||null, codice_fiscale, iban||null, nr_matricola||null, matricola_rilasciata||null, matricola_scadenza||null, hash, rinnovo_matricola||null, istanza_data||null, istanza_supporto_data||null, req.params.id];
      } else {
        q = `UPDATE users SET nome=$1,cognome=$2,email=$3,telefono=$4,indirizzo=$5,data_nascita=$6,codice_fiscale=$7,iban=$8,nr_matricola=$9,matricola_rilasciata=$10,matricola_scadenza=$11,rinnovo_matricola=$12,istanza_data=$13,istanza_supporto_data=$14 WHERE id=$15 RETURNING ${USER_COLS}`;
        params = [nome, cognome, email, telefono, indirizzo, data_nascita||null, codice_fiscale, iban||null, nr_matricola||null, matricola_rilasciata||null, matricola_scadenza||null, rinnovo_matricola||null, istanza_data||null, istanza_supporto_data||null, req.params.id];
      }
    } else {
      if (password) {
        const hash = await bcrypt.hash(password, 10);
        q = `UPDATE users SET nome=$1,cognome=$2,email=$3,telefono=$4,indirizzo=$5,data_nascita=$6,codice_fiscale=$7,iban=$8,nr_matricola=$9,matricola_rilasciata=$10,matricola_scadenza=$11,password_hash=$12 WHERE id=$13 RETURNING ${USER_COLS}`;
        params = [nome, cognome, email, telefono, indirizzo, data_nascita||null, codice_fiscale, iban||null, nr_matricola||null, matricola_rilasciata||null, matricola_scadenza||null, hash, req.params.id];
      } else {
        q = `UPDATE users SET nome=$1,cognome=$2,email=$3,telefono=$4,indirizzo=$5,data_nascita=$6,codice_fiscale=$7,iban=$8,nr_matricola=$9,matricola_rilasciata=$10,matricola_scadenza=$11 WHERE id=$12 RETURNING ${USER_COLS}`;
        params = [nome, cognome, email, telefono, indirizzo, data_nascita||null, codice_fiscale, iban||null, nr_matricola||null, matricola_rilasciata||null, matricola_scadenza||null, req.params.id];
      }
    }
    const r = await pool.query(q, params);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/users/:id/matricola', auth, async (req, res) => {
  try {
    if (!req.user.is_admin && req.user.id !== req.params.id)
      return res.status(403).json({ error: 'Accesso negato' });
    const { nr_matricola, matricola_rilasciata, matricola_scadenza } = req.body;
    const r = await pool.query(
      `UPDATE users SET nr_matricola=$1,matricola_rilasciata=$2,matricola_scadenza=$3 WHERE id=$4 RETURNING ${USER_COLS}`,
      [nr_matricola || null, matricola_rilasciata || null, matricola_scadenza || null, req.params.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/users/:id', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/users/:id/supervisore', auth, adminOnly, async (req, res) => {
  try {
    const { is_supervisore } = req.body;
    const r = await pool.query(`UPDATE users SET is_supervisore=$1 WHERE id=$2 RETURNING ${USER_COLS}`, [!!is_supervisore, req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Utente non trovato' });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── EXPENSES ──────────────────────────────────────────────────────────────────
app.get('/api/expenses', auth, supervisorOrAdmin, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT e.*, u.nome, u.cognome, u.email
       FROM expenses e JOIN users u ON e.user_id=u.id
       ORDER BY e.data DESC`
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/expenses/:userId', auth, async (req, res) => {
  try {
    if (!req.user.is_admin && !req.user.is_supervisore && req.user.id !== req.params.userId)
      return res.status(403).json({ error: 'Accesso negato' });
    const r = await pool.query('SELECT * FROM expenses WHERE user_id=$1 ORDER BY data DESC', [req.params.userId]);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/expenses', auth, async (req, res) => {
  try {
    const { user_id, luogo, data, solo_guida, note } = req.body;
    const uid = req.user.is_admin ? user_id : req.user.id;
    const id = uuidv4();
    const r = await pool.query(
      'INSERT INTO expenses (id,user_id,luogo,data,solo_guida,note,pagato,created_at) VALUES ($1,$2,$3,$4,$5,$6,FALSE,NOW()) RETURNING *',
      [id, uid, luogo, data, solo_guida || false, note || '']
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/expenses/:id', auth, async (req, res) => {
  try {
    const { luogo, data, solo_guida, note } = req.body;
    const r = await pool.query(
      'UPDATE expenses SET luogo=$1,data=$2,solo_guida=$3,note=$4 WHERE id=$5 RETURNING *',
      [luogo, data, solo_guida || false, note || '', req.params.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/expenses/:id/pagato', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query('UPDATE expenses SET pagato = NOT pagato WHERE id=$1 RETURNING *', [req.params.id]);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/expenses/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM expenses WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── MESSAGES (Admin → Operatori) ──────────────────────────────────────────────
app.get('/api/messages', auth, async (req, res) => {
  try {
    let r;
    if (req.user.is_admin || req.user.is_supervisore) {
      r = await pool.query('SELECT m.*, array_agg(mr.user_id) FILTER (WHERE mr.user_id IS NOT NULL) as read_by FROM messages m LEFT JOIN message_reads mr ON m.id=mr.message_id GROUP BY m.id ORDER BY m.created_at DESC');
    } else {
      r = await pool.query(
        `SELECT m.*, array_agg(mr.user_id) FILTER (WHERE mr.user_id IS NOT NULL) as read_by
         FROM messages m LEFT JOIN message_reads mr ON m.id=mr.message_id
         WHERE (m.is_broadcast=TRUE OR m.target_user_id=$1)
           AND m.id NOT IN (SELECT message_id FROM message_deletions WHERE user_id=$1)
         GROUP BY m.id ORDER BY m.created_at DESC`,
        [req.user.id]
      );
    }
    res.json(r.rows.map(m => ({ ...m, read_by: m.read_by || [] })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/messages/:id/delete', auth, async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO message_deletions (message_id,user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [req.params.id, req.user.id]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/messages/:id', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM messages WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/messages', auth, supervisorOrAdmin, async (req, res) => {
  try {
    const { testo, nome_file, mime_type, file_data, is_broadcast, target_user_id } = req.body;
    const id = uuidv4();
    const r = await pool.query(
      'INSERT INTO messages (id,testo,nome_file,mime_type,file_data,is_broadcast,target_user_id,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW()) RETURNING *',
      [id, testo, nome_file || null, mime_type || null, file_data || null, is_broadcast !== false, target_user_id || null]
    );
    res.json({ ...r.rows[0], read_by: [] });
    // Push notification
    const preview = (testo||'').substring(0, 80);
    if (is_broadcast !== false && !target_user_id) {
      const allUsers = await pool.query('SELECT onesignal_player_id FROM users WHERE is_admin=FALSE AND onesignal_player_id IS NOT NULL');
      const ids = allUsers.rows.map(u => u.onesignal_player_id);
      sendPush(ids, '📨 Nuovo messaggio', preview);
    } else if (target_user_id) {
      const ids = await getPushIds([target_user_id]);
      sendPush(ids, '📨 Nuovo messaggio', preview);
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/messages/:id/read', auth, async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO message_reads (message_id,user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [req.params.id, req.user.id]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── INCOMING MESSAGES (Operatori → Admin) ────────────────────────────────────
app.get('/api/incoming-messages', auth, supervisorOrAdmin, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM incoming_messages ORDER BY created_at DESC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/incoming-messages/mine', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM incoming_messages WHERE from_user_id=$1 ORDER BY created_at DESC', [req.user.id]);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/incoming-messages', auth, async (req, res) => {
  try {
    const { testo, nome_file, mime_type, file_data } = req.body;
    const id = uuidv4();
    const r = await pool.query(
      'INSERT INTO incoming_messages (id,from_user_id,from_name,from_email,testo,nome_file,mime_type,file_data,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW()) RETURNING *',
      [id, req.user.id, `${req.user.nome||''} ${req.user.cognome||''}`.trim() || req.user.email,
       req.user.email, testo, nome_file || null, mime_type || null, file_data || null]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/incoming-messages/:id/reply', auth, adminOnly, async (req, res) => {
  try {
    const { reply } = req.body;
    const r = await pool.query(
      'UPDATE incoming_messages SET reply=$1,reply_at=NOW() WHERE id=$2 RETURNING *',
      [reply, req.params.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/incoming-messages/:id', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM incoming_messages WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── DOCUMENTS ─────────────────────────────────────────────────────────────────
app.get('/api/documents/:userId', auth, async (req, res) => {
  try {
    if (!req.user.is_admin && !req.user.is_supervisore && req.user.id !== req.params.userId)
      return res.status(403).json({ error: 'Accesso negato' });
    const r = await pool.query('SELECT * FROM documents WHERE user_id=$1', [req.params.userId]);
    // Convert rows to object keyed by doc_key
    const docs = {};
    r.rows.forEach(d => {
      docs[d.doc_key] = { nome_file: d.nome_file, mime_type: d.mime_type, data: d.file_data, date: d.upload_date };
    });
    res.json(docs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/documents/:userId', auth, async (req, res) => {
  try {
    if (!req.user.is_admin && req.user.id !== req.params.userId)
      return res.status(403).json({ error: 'Accesso negato' });
    const { doc_key, nome_file, mime_type, file_data } = req.body;
    await pool.query(
      'INSERT INTO documents (user_id,doc_key,nome_file,mime_type,file_data,upload_date) VALUES ($1,$2,$3,$4,$5,NOW()) ON CONFLICT (user_id,doc_key) DO UPDATE SET nome_file=$3,mime_type=$4,file_data=$5,upload_date=NOW()',
      [req.params.userId, doc_key, nome_file, mime_type, file_data]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/documents/:userId/:key', auth, async (req, res) => {
  try {
    if (!req.user.is_admin && req.user.id !== req.params.userId)
      return res.status(403).json({ error: 'Accesso negato' });
    await pool.query('DELETE FROM documents WHERE user_id=$1 AND doc_key=$2', [req.params.userId, req.params.key]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── INFO ITEMS ────────────────────────────────────────────────────────────────
app.get('/api/info-items', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM info_items ORDER BY created_at');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/info-items', auth, adminOnly, async (req, res) => {
  try {
    const { text } = req.body;
    const id = uuidv4();
    const r = await pool.query('INSERT INTO info_items (id,text,created_at) VALUES ($1,$2,NOW()) RETURNING *', [id, text]);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/info-items/:id', auth, adminOnly, async (req, res) => {
  try {
    const { text } = req.body;
    const r = await pool.query('UPDATE info_items SET text=$1 WHERE id=$2 RETURNING *', [text, req.params.id]);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/info-items/:id', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM info_items WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── RULES ─────────────────────────────────────────────────────────────────────
app.get('/api/rules', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM rules ORDER BY sort_order ASC, created_at ASC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/rules/:id/move', auth, adminOnly, async (req, res) => {
  try {
    const { direction } = req.body;
    const all = await pool.query('SELECT id, sort_order FROM rules ORDER BY sort_order ASC, created_at ASC');
    const rows = all.rows;
    const idx = rows.findIndex(r => r.id === req.params.id);
    if (idx < 0) return res.status(404).json({ error: 'Not found' });
    const swapIdx = direction === 'up' ? idx - 1 : idx + 1;
    if (swapIdx < 0 || swapIdx >= rows.length) return res.json({ ok: true });
    const a = rows[idx], b = rows[swapIdx];
    const soA = a.sort_order === b.sort_order ? idx : a.sort_order;
    const soB = b.sort_order === a.sort_order ? swapIdx : b.sort_order;
    await pool.query('UPDATE rules SET sort_order=$1 WHERE id=$2', [soB, a.id]);
    await pool.query('UPDATE rules SET sort_order=$1 WHERE id=$2', [soA, b.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/rules', auth, adminOnly, async (req, res) => {
  try {
    const { title, text, pdf_data, pdf_name } = req.body;
    const id = uuidv4();
    const maxOrd = await pool.query('SELECT COALESCE(MAX(sort_order),0)+1 AS next FROM rules');
    const sortOrder = maxOrd.rows[0].next;
    const r = await pool.query(
      'INSERT INTO rules (id,title,text,pdf_data,pdf_name,sort_order,created_at) VALUES ($1,$2,$3,$4,$5,$6,NOW()) RETURNING *',
      [id, title, text, pdf_data || null, pdf_name || null, sortOrder]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/rules/:id', auth, adminOnly, async (req, res) => {
  try {
    const { title, text, pdf_data, pdf_name } = req.body;
    const r = await pool.query(
      'UPDATE rules SET title=$1,text=$2,pdf_data=$3,pdf_name=$4 WHERE id=$5 RETURNING *',
      [title, text, pdf_data || null, pdf_name || null, req.params.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/rules/:id', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM rules WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── RULES LOG ─────────────────────────────────────────────────────────────────
app.get('/api/rules-log', auth, async (req, res) => {
  try {
    let r;
    if (req.user.is_admin) {
      r = await pool.query('SELECT * FROM rules_log ORDER BY timestamp DESC');
    } else {
      r = await pool.query('SELECT * FROM rules_log WHERE user_id=$1 ORDER BY timestamp DESC', [req.user.id]);
    }
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/rules-log', auth, async (req, res) => {
  try {
    const { rule_id, rule_text, decision } = req.body;
    // Remove previous log for same user+rule, then insert new one
    await pool.query('DELETE FROM rules_log WHERE user_id=$1 AND rule_id=$2', [req.user.id, rule_id]);
    const id = uuidv4();
    const r = await pool.query(
      'INSERT INTO rules_log (id,user_id,user_name,user_email,rule_id,rule_text,decision,timestamp) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW()) RETURNING *',
      [id, req.user.id, `${req.user.nome||''} ${req.user.cognome||''}`.trim() || req.user.email,
       req.user.email, rule_id, rule_text, decision]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── URGENT MESSAGES ───────────────────────────────────────────────────────────
app.get('/api/urgent-messages', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM urgent_messages ORDER BY created_at DESC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/urgent-messages', auth, supervisorOrAdmin, async (req, res) => {
  try {
    const { testo, expires_at } = req.body;
    const id = uuidv4();
    const r = await pool.query(
      'INSERT INTO urgent_messages (id,testo,expires_at,created_at) VALUES ($1,$2,$3,NOW()) RETURNING *',
      [id, testo, expires_at]
    );
    const users = await pool.query('SELECT id FROM users WHERE is_admin=false');
    const ids = await getPushIds(users.rows.map(u => u.id));
    await sendPush(ids, '🚨 Messaggio Urgente', testo);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/urgent-messages/:id', auth, adminOnly, async (req, res) => {
  try {
    const { testo, expires_at } = req.body;
    const r = await pool.query(
      'UPDATE urgent_messages SET testo=$1,expires_at=$2 WHERE id=$3 RETURNING *',
      [testo, expires_at, req.params.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/urgent-messages/:id', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM urgent_messages WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GESTIONE UTENTI (block/unblock/reset-password) ───────────────────────────
app.patch('/api/users/:id/disclaimer', auth, async (req, res) => {
  try {
    if (!req.user.is_admin && req.user.id !== req.params.id)
      return res.status(403).json({ error: 'Accesso negato' });
    const { accepted } = req.body;
    const r = await pool.query(
      `UPDATE users SET disclaimer_accepted=$1, disclaimer_accepted_at=$2 WHERE id=$3 RETURNING ${USER_COLS}`,
      [accepted, accepted ? new Date() : null, req.params.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/users/:id/block', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(`UPDATE users SET blocked=TRUE WHERE id=$1 RETURNING ${USER_COLS}`, [req.params.id]);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/users/:id/unblock', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(`UPDATE users SET blocked=FALSE WHERE id=$1 RETURNING ${USER_COLS}`, [req.params.id]);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/users/:id/password', auth, adminOnly, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || password.length < 4) return res.status(400).json({ error: 'Password troppo corta (min 4 caratteri)' });
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(`UPDATE users SET password_hash=$1 WHERE id=$2 RETURNING ${USER_COLS}`, [hash, req.params.id]);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── TESSERE ASC ───────────────────────────────────────────────────────────────
app.get('/api/tessere/mine', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM tessere WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1', [req.user.id]);
    res.json(r.rows[0] || null);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/tessere', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM tessere ORDER BY created_at DESC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/tessere', auth, adminOnly, async (req, res) => {
  try {
    const { user_id } = req.body;
    if (!user_id) return res.status(400).json({ error: 'user_id mancante' });
    const id = uuidv4();
    const r = await pool.query(
      'INSERT INTO tessere (id, user_id, creata_da, created_at) VALUES ($1,$2,$3,NOW()) RETURNING *',
      [id, user_id, req.user.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/tessere/:id', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM tessere WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── RICHIESTE PASSWORD ────────────────────────────────────────────────────────
// POST /api/password-reset — pubblico, nessuna auth
app.post('/api/password-reset', async (req, res) => {
  try {
    const { nome, cognome, nuova_password_richiesta } = req.body;
    if (!nome || !cognome || !nuova_password_richiesta)
      return res.status(400).json({ error: 'Campi mancanti' });
    // Cerca utente per nome+cognome (case-insensitive)
    const ur = await pool.query(
      `SELECT id FROM users WHERE LOWER(nome)=LOWER($1) AND LOWER(cognome)=LOWER($2) AND is_admin=FALSE`,
      [nome, cognome]
    );
    const userId = ur.rows.length ? ur.rows[0].id : null;
    if (userId) {
      // Sovrascrivi eventuale richiesta precedente
      await pool.query('DELETE FROM richieste_password WHERE user_id=$1', [userId]);
    }
    const id = uuidv4();
    await pool.query(
      `INSERT INTO richieste_password (id,user_id,nome,cognome,nuova_password_richiesta,stato,data_richiesta)
       VALUES ($1,$2,$3,$4,$5,'in_attesa',NOW())`,
      [id, userId, nome, cognome, nuova_password_richiesta]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/password-reset', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM richieste_password ORDER BY data_richiesta DESC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/password-reset/:id/complete', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      `UPDATE richieste_password SET stato='completata', data_completamento=NOW() WHERE id=$1 RETURNING *`,
      [req.params.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── UTILITY / DB STATS ───────────────────────────────────────────────────────
app.get('/api/admin/db-stats', auth, adminOnly, async (req, res) => {
  try {
    const totalR = await pool.query(
      `SELECT pg_database_size(current_database()) as total_bytes,
              pg_size_pretty(pg_database_size(current_database())) as total_pretty`
    );
    const tablesR = await pool.query(
      `SELECT t.tablename,
              pg_total_relation_size(t.tablename::regclass) as size_bytes,
              pg_size_pretty(pg_total_relation_size(t.tablename::regclass)) as size_pretty,
              COALESCE(s.n_live_tup, 0) as rows
       FROM pg_catalog.pg_tables t
       LEFT JOIN pg_stat_user_tables s ON s.relname = t.tablename
       WHERE t.schemaname = 'public'
       ORDER BY size_bytes DESC`
    );
    res.json({ total: totalR.rows[0], tables: tablesR.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/db-backup', auth, adminOnly, async (req, res) => {
  try {
    const tables = await pool.query(
      `SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='public' ORDER BY tablename`
    );
    const backup = { exported_at: new Date().toISOString(), tables: {} };
    for (const { tablename } of tables.rows) {
      const r = await pool.query(`SELECT * FROM "${tablename}"`);
      backup.tables[tablename] = r.rows;
    }
    const json = JSON.stringify(backup, null, 2);
    const filename = `adsecurity-backup-${new Date().toISOString().substring(0,10)}.json`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/json');
    res.send(json);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── AMMINISTRAZIONE MENSILE ───────────────────────────────────────────────────
app.get('/api/admin/amministrazione', auth, adminOnly, async (req, res) => {
  try {
    const { mese, anno } = req.query;
    if (mese && anno) {
      const r = await pool.query('SELECT * FROM amministrazione_mensile WHERE mese=$1 AND anno=$2', [mese, anno]);
      return res.json(r.rows[0] || null);
    }
    const r = await pool.query('SELECT * FROM amministrazione_mensile ORDER BY anno, mese');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/amministrazione/anno/:anno', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM amministrazione_mensile WHERE anno=$1 ORDER BY mese', [req.params.anno]);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/amministrazione', auth, adminOnly, async (req, res) => {
  try {
    const { mese, anno, fatture, nn, numero_servizi_mese, costo_paghe_op, costo_paghe_op_b,
            costo_tax, costo_amm_paghe, costo_manager_security, costo_vestiario,
            costo_societa_varie, costi_vari, societa_varie_dettaglio, costi_vari_dettaglio } = req.body;
    const id = uuidv4();
    const r = await pool.query(`
      INSERT INTO amministrazione_mensile
        (id,mese,anno,fatture,nn,numero_servizi_mese,costo_paghe_op,costo_paghe_op_b,
         costo_tax,costo_amm_paghe,costo_manager_security,costo_vestiario,costo_societa_varie,costi_vari,
         societa_varie_dettaglio,costi_vari_dettaglio,created_at,updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NOW(),NOW())
      ON CONFLICT (mese,anno) DO UPDATE SET
        fatture=$4,nn=$5,numero_servizi_mese=$6,costo_paghe_op=$7,costo_paghe_op_b=$8,
        costo_tax=$9,costo_amm_paghe=$10,costo_manager_security=$11,costo_vestiario=$12,
        costo_societa_varie=$13,costi_vari=$14,societa_varie_dettaglio=$15,costi_vari_dettaglio=$16,updated_at=NOW()
      RETURNING *`,
      [id,mese,anno,fatture||0,nn||0,numero_servizi_mese||0,costo_paghe_op||0,costo_paghe_op_b||0,
       costo_tax||0,costo_amm_paghe||0,costo_manager_security||0,costo_vestiario||0,
       costo_societa_varie||0,costi_vari||0,societa_varie_dettaglio||'[]',costi_vari_dettaglio||'[]']
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/amministrazione/:mese/:anno', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM amministrazione_mensile WHERE mese=$1 AND anno=$2', [req.params.mese, req.params.anno]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/amministrazione/all', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM amministrazione_mensile');
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── NOTE OPERATORE ────────────────────────────────────────────────────────────
app.get('/api/notes', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM note_operatore WHERE user_id=$1 ORDER BY created_at DESC', [req.user.id]);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/notes', auth, async (req, res) => {
  try {
    const { titolo, testo } = req.body;
    if (!titolo) return res.status(400).json({ error: 'Titolo mancante' });
    const id = uuidv4();
    const r = await pool.query(
      'INSERT INTO note_operatore (id,user_id,titolo,testo,created_at,updated_at) VALUES ($1,$2,$3,$4,NOW(),NOW()) RETURNING *',
      [id, req.user.id, titolo, testo || '']
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/notes/:id', auth, async (req, res) => {
  try {
    const { titolo, testo } = req.body;
    const r = await pool.query(
      'UPDATE note_operatore SET titolo=$1,testo=$2,updated_at=NOW() WHERE id=$3 AND user_id=$4 RETURNING *',
      [titolo, testo || '', req.params.id, req.user.id]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Nota non trovata' });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/notes/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM note_operatore WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── CASSA ANTICIPI ────────────────────────────────────────────────────────────
const CA_SEL = `
  SELECT ca.*, u.nome as operatore_nome, u.cognome as operatore_cognome,
    (SELECT COALESCE(JSON_AGG(r ORDER BY r.created_at ASC),'[]'::json)
     FROM (SELECT id, data_rimborso::text as data, importo::float, nota, created_at FROM ca_rimborsi WHERE anticipo_id=ca.id) r
    ) as rimborsi,
    (SELECT COALESCE(JSON_AGG(l ORDER BY l.timestamp ASC),'[]'::json)
     FROM (SELECT id, timestamp, azione, dettaglio FROM ca_log WHERE anticipo_id=ca.id) l
    ) as log
  FROM cassa_anticipi ca JOIN users u ON ca.operatore_id=u.id`;

app.get('/api/cassa-anticipi', auth, adminOnly, async (req, res) => {
  try { const r=await pool.query(CA_SEL+' ORDER BY ca.created_at DESC'); res.json(r.rows); }
  catch(e){ res.status(500).json({error:e.message}); }
});

app.get('/api/cassa-anticipi/operatore', auth, async (req, res) => {
  try { const r=await pool.query(CA_SEL+' WHERE ca.operatore_id=$1 ORDER BY ca.created_at DESC',[req.user.id]); res.json(r.rows); }
  catch(e){ res.status(500).json({error:e.message}); }
});

app.post('/api/cassa-anticipi', auth, adminOnly, async (req, res) => {
  try {
    const {operatore_id,categoria,descrizione_varie,data_spesa,importo_totale,note_admin}=req.body;
    if(!operatore_id||!categoria||!data_spesa||!importo_totale) return res.status(400).json({error:'Campi obbligatori mancanti'});
    const id=uuidv4(), logId=uuidv4();
    await pool.query('INSERT INTO cassa_anticipi (id,operatore_id,categoria,descrizione_varie,data_spesa,importo_totale,note_admin,notifica_inviata) VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE)',
      [id,operatore_id,categoria,descrizione_varie||null,data_spesa,importo_totale,note_admin||'']);
    await pool.query('INSERT INTO ca_log (id,anticipo_id,timestamp,azione,dettaglio) VALUES ($1,$2,NOW(),$3,$4)',
      [logId,id,'Creazione',"Registrata dall'admin"]);
    const r=await pool.query(CA_SEL+' WHERE ca.id=$1',[id]);
    res.json(r.rows[0]);
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.put('/api/cassa-anticipi/:id', auth, adminOnly, async (req, res) => {
  try {
    const {operatore_id,categoria,descrizione_varie,data_spesa,importo_totale,note_admin}=req.body;
    await pool.query('UPDATE cassa_anticipi SET operatore_id=$1,categoria=$2,descrizione_varie=$3,data_spesa=$4,importo_totale=$5,note_admin=$6,notifica_inviata=TRUE,notifica_letta=FALSE,updated_at=NOW() WHERE id=$7',
      [operatore_id,categoria,descrizione_varie||null,data_spesa,importo_totale,note_admin||'',req.params.id]);
    await pool.query('INSERT INTO ca_log (id,anticipo_id,timestamp,azione,dettaglio) VALUES ($1,$2,NOW(),$3,$4)',
      [uuidv4(),req.params.id,'Modifica',"Dati aggiornati dall'admin"]);
    const r=await pool.query(CA_SEL+' WHERE ca.id=$1',[req.params.id]);
    res.json(r.rows[0]);
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.post('/api/cassa-anticipi/:id/rimborso', auth, adminOnly, async (req, res) => {
  try {
    const {data_rimborso,importo,nota}=req.body;
    if(!data_rimborso||!importo) return res.status(400).json({error:'Dati mancanti'});
    const ca=await pool.query('SELECT importo_totale,importo_rimborsato FROM cassa_anticipi WHERE id=$1',[req.params.id]);
    if(!ca.rows.length) return res.status(404).json({error:'Non trovato'});
    const residuo=parseFloat(ca.rows[0].importo_totale)-parseFloat(ca.rows[0].importo_rimborsato);
    if(parseFloat(importo)>residuo+0.01) return res.status(400).json({error:'Importo supera il residuo'});
    await pool.query('INSERT INTO ca_rimborsi (id,anticipo_id,data_rimborso,importo,nota) VALUES ($1,$2,$3,$4,$5)',
      [uuidv4(),req.params.id,data_rimborso,importo,nota||'']);
    await pool.query('UPDATE cassa_anticipi SET importo_rimborsato=importo_rimborsato+$1,updated_at=NOW() WHERE id=$2',[importo,req.params.id]);
    const det=`${_fmtAmt(parseFloat(importo))}${nota?' — '+nota:''}`;
    await pool.query('INSERT INTO ca_log (id,anticipo_id,timestamp,azione,dettaglio) VALUES ($1,$2,NOW(),$3,$4)',
      [uuidv4(),req.params.id,'Rimborso registrato',det]);
    const r=await pool.query(CA_SEL+' WHERE ca.id=$1',[req.params.id]);
    res.json(r.rows[0]);
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.patch('/api/cassa-anticipi/:id/notifica-letta', auth, async (req, res) => {
  try {
    await pool.query('UPDATE cassa_anticipi SET notifica_letta=TRUE,notifica_letta_il=NOW() WHERE id=$1',[req.params.id]);
    const now=new Date();
    const det=`Letta il ${now.toLocaleDateString('it-IT')} ${now.toLocaleTimeString('it-IT',{hour:'2-digit',minute:'2-digit'})}`;
    await pool.query('INSERT INTO ca_log (id,anticipo_id,timestamp,azione,dettaglio) VALUES ($1,$2,NOW(),$3,$4)',
      [uuidv4(),req.params.id,"Notifica letta dall'operatore",det]);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.delete('/api/cassa-anticipi/by-operatore/:userId', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM ca_rimborsi WHERE anticipo_id IN (SELECT id FROM cassa_anticipi WHERE operatore_id=$1)',[req.params.userId]);
    await pool.query('DELETE FROM ca_log WHERE anticipo_id IN (SELECT id FROM cassa_anticipi WHERE operatore_id=$1)',[req.params.userId]);
    await pool.query('DELETE FROM cassa_anticipi WHERE operatore_id=$1',[req.params.userId]);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.delete('/api/cassa-anticipi/:id', auth, adminOnly, async (req, res) => {
  try { await pool.query('DELETE FROM cassa_anticipi WHERE id=$1',[req.params.id]); res.json({ok:true}); }
  catch(e){ res.status(500).json({error:e.message}); }
});

function _fmtAmt(n){return '€'+n.toFixed(2).replace('.',',');}

// ── ONESIGNAL ─────────────────────────────────────────────────────────────────
app.get('/api/config', (req, res) => {
  res.json({ onesignal_app_id: process.env.ONESIGNAL_APP_ID || null });
});

app.post('/api/push-token', auth, async (req, res) => {
  try {
    const { player_id } = req.body;
    await pool.query('UPDATE users SET onesignal_player_id=$1 WHERE id=$2', [player_id, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

async function sendPush(playerIds, title, message) {
  const apiKey = process.env.ONESIGNAL_API_KEY;
  const appId  = process.env.ONESIGNAL_APP_ID;
  if (!apiKey || !appId || !playerIds || !playerIds.length) { console.log('Push skip: missing config or no ids'); return; }
  try {
    console.log('Push sending to:', playerIds, 'title:', title);
    const resp = await fetch('https://api.onesignal.com/notifications', {
      method: 'POST',
      headers: { 'Authorization': `Key ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        app_id: appId,
        include_subscription_ids: playerIds,
        headings: { en: title },
        contents: { en: message },
        url: 'https://alfasecurity.group'
      })
    });
    const data = await resp.json();
    console.log('Push response:', JSON.stringify(data));
  } catch(e) { console.error('Push error:', e.message); }
}

async function getPushIds(userIds) {
  if (!userIds || !userIds.length) return [];
  const r = await pool.query(
    `SELECT onesignal_player_id FROM users WHERE id=ANY($1) AND onesignal_player_id IS NOT NULL`,
    [userIds]
  );
  return r.rows.map(r => r.onesignal_player_id);
}

// ── SECURITY VESTIARIO ────────────────────────────────────────────────────────
app.get('/api/vestiario/mio', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM security_vestiario WHERE operatore_id=$1', [req.user.id]);
    res.json(r.rows[0] || null);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/vestiario', auth, async (req, res) => {
  try {
    const { giacca_taglia, giacca_possesso, giacca_radio,
            maglietta_taglia, maglietta_possesso, maglietta_radio,
            pantaloni_taglia, pantaloni_possesso, pantaloni_radio,
            felpa_taglia, felpa_possesso, felpa_radio,
            richiesta_capo, richiesta_motivo, richiesta_altro,
            foto1, foto2, foto3, radio_stato } = req.body;
    const u = await pool.query('SELECT nome, cognome FROM users WHERE id=$1', [req.user.id]);
    const nome = u.rows[0]?.nome || ''; const cognome = u.rows[0]?.cognome || '';
    const hasReq = !!(richiesta_capo);
    const existing = await pool.query('SELECT id FROM security_vestiario WHERE operatore_id=$1', [req.user.id]);
    if (existing.rows.length > 0) {
      const r = await pool.query(`UPDATE security_vestiario SET
        nome_operatore=$1, cognome_operatore=$2,
        giacca_taglia=$3, giacca_possesso=$4, giacca_radio=$5,
        maglietta_taglia=$6, maglietta_possesso=$7, maglietta_radio=$8,
        pantaloni_taglia=$9, pantaloni_possesso=$10, pantaloni_radio=$11,
        felpa_taglia=$12, felpa_possesso=$13, felpa_radio=$14,
        richiesta_capo=$15, richiesta_motivo=$16, richiesta_altro=$17,
        foto1=$18, foto2=$19, foto3=$20, radio_stato=$21,
        stato_richiesta=CASE WHEN $22 THEN 'in_valutazione' ELSE stato_richiesta END,
        motivazione_admin=CASE WHEN $22 THEN NULL ELSE motivazione_admin END,
        data_richiesta=CASE WHEN $22 THEN NOW() ELSE data_richiesta END
        WHERE operatore_id=$23 RETURNING *`,
        [nome, cognome,
         giacca_taglia||null, giacca_possesso||null, giacca_radio||null,
         maglietta_taglia||null, maglietta_possesso||null, maglietta_radio||null,
         pantaloni_taglia||null, pantaloni_possesso||null, pantaloni_radio||null,
         felpa_taglia||null, felpa_possesso||null, felpa_radio||null,
         richiesta_capo||null, richiesta_motivo||null, richiesta_altro||null,
         foto1||null, foto2||null, foto3||null, radio_stato||null, hasReq, req.user.id]);
      return res.json(r.rows[0]);
    }
    const id = uuidv4();
    const r = await pool.query(`INSERT INTO security_vestiario
      (id, operatore_id, nome_operatore, cognome_operatore,
       giacca_taglia, giacca_possesso, giacca_radio,
       maglietta_taglia, maglietta_possesso, maglietta_radio,
       pantaloni_taglia, pantaloni_possesso, pantaloni_radio,
       felpa_taglia, felpa_possesso, felpa_radio,
       richiesta_capo, richiesta_motivo, richiesta_altro,
       foto1, foto2, foto3, radio_stato, stato_richiesta, data_richiesta)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,
        CASE WHEN $24 THEN 'in_valutazione' ELSE NULL END,
        CASE WHEN $24 THEN NOW() ELSE NULL END) RETURNING *`,
      [id, req.user.id, nome, cognome,
       giacca_taglia||null, giacca_possesso||null, giacca_radio||null,
       maglietta_taglia||null, maglietta_possesso||null, maglietta_radio||null,
       pantaloni_taglia||null, pantaloni_possesso||null, pantaloni_radio||null,
       felpa_taglia||null, felpa_possesso||null, felpa_radio||null,
       richiesta_capo||null, richiesta_motivo||null, richiesta_altro||null,
       foto1||null, foto2||null, foto3||null, radio_stato||null, hasReq]);
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/admin/vestiario', auth, supervisorOrAdmin, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM security_vestiario ORDER BY cognome_operatore, nome_operatore');
    res.json(r.rows);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.patch('/api/admin/vestiario/:id/stato', auth, supervisorOrAdmin, async (req, res) => {
  try {
    const { stato_richiesta, motivazione_admin } = req.body;
    const r = await pool.query(
      'UPDATE security_vestiario SET stato_richiesta=$1, motivazione_admin=$2 WHERE id=$3 RETURNING *',
      [stato_richiesta, motivazione_admin||null, req.params.id]);
    const row = r.rows[0];
    if (row && row.operatore_id && (stato_richiesta === 'approvata' || stato_richiesta === 'non_approvata')) {
      const ids = await getPushIds([row.operatore_id]);
      const label = stato_richiesta === 'approvata' ? '✅ Approvata' : '❌ Non approvata';
      await sendPush(ids, 'Security Vestiario', `Richiesta vestiario ${label}${motivazione_admin ? ': ' + motivazione_admin : ''}`);
    }
    // Se modifica fatta da supervisore, notifica admin via messaggio
    if (!req.user.is_admin && req.user.is_supervisore && row) {
      const svNome = req.user.nome ? `${req.user.nome} ${req.user.cognome||''}`.trim() : req.user.email;
      const statoLabel = stato_richiesta === 'approvata' ? 'APPROVATA' : stato_richiesta === 'non_approvata' ? 'NON APPROVATA' : stato_richiesta;
      const msgId = require('crypto').randomUUID();
      const testo = `[SUPERVISORE ${svNome}] Ha modificato il vestiario di ${row.nome_operatore||''} ${row.cognome_operatore||''}: stato → ${statoLabel}${motivazione_admin ? ' | Note: '+motivazione_admin : ''}`;
      const adminR = await pool.query(`SELECT id FROM users WHERE is_admin=TRUE LIMIT 1`);
      if (adminR.rows.length) {
        await pool.query(
          'INSERT INTO incoming_messages (id,from_user_id,from_email,testo,created_at) VALUES ($1,$2,$3,$4,NOW())',
          [msgId, req.user.id, req.user.email, testo]
        );
      }
    }
    res.json(row);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/admin/magazzino-vestiario', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM magazzino_vestiario ORDER BY tipo_capo, taglia');
    res.json(r.rows);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/admin/magazzino-vestiario', auth, adminOnly, async (req, res) => {
  try {
    const { tipo_capo, taglia, quantita } = req.body;
    const q = parseInt(quantita)||0;
    const id = uuidv4();
    const r = await pool.query(`
      INSERT INTO magazzino_vestiario (id,tipo_capo,taglia,quantita_stock,quantita_disponibile,quantita_assegnata,data_aggiornamento)
      VALUES ($1,$2,$3,$4,$4,0,NOW())
      ON CONFLICT (tipo_capo,taglia) DO UPDATE SET
        quantita_stock=magazzino_vestiario.quantita_stock+$4,
        quantita_disponibile=magazzino_vestiario.quantita_disponibile+$4,
        data_aggiornamento=NOW()
      RETURNING *`, [id, tipo_capo, taglia, q]);
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.patch('/api/admin/magazzino-vestiario/:id', auth, adminOnly, async (req, res) => {
  try {
    const { quantita_stock, quantita_disponibile, quantita_assegnata } = req.body;
    const r = await pool.query(
      `UPDATE magazzino_vestiario SET quantita_stock=$1, quantita_disponibile=$2, quantita_assegnata=$3, data_aggiornamento=NOW() WHERE id=$4 RETURNING *`,
      [parseInt(quantita_stock)||0, parseInt(quantita_disponibile)||0, parseInt(quantita_assegnata)||0, req.params.id]);
    if (!r.rows.length) return res.status(404).json({error:'Non trovato'});
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.delete('/api/admin/magazzino-vestiario/:id', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM magazzino_vestiario WHERE id=$1', [req.params.id]);
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── PRIMA FORNITURE ───────────────────────────────────────────────────────────
app.get('/api/admin/prime-forniture', auth, adminOnly, async (req, res) => {
  try {
    const { search } = req.query;
    let q = 'SELECT * FROM prime_forniture';
    const params = [];
    if (search) {
      params.push('%' + search.toLowerCase() + '%');
      q += ` WHERE LOWER(COALESCE(nome_operatore,'')||' '||COALESCE(cognome_operatore,'')) LIKE $1`;
    }
    q += ' ORDER BY data_fornitura DESC';
    const r = await pool.query(q, params);
    res.json(r.rows);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/admin/prime-forniture', auth, adminOnly, async (req, res) => {
  try {
    const { operatore_id, giacca, maglietta, pantaloni, felpa, radio, note } = req.body;
    const u = await pool.query('SELECT nome, cognome FROM users WHERE id=$1', [operatore_id]);
    if (!u.rows.length) return res.status(404).json({error:'Operatore non trovato'});
    const op = u.rows[0];
    const adm = await pool.query('SELECT nome, cognome FROM users WHERE id=$1', [req.user.id]);
    const adminNome = adm.rows[0] ? (adm.rows[0].nome||'')+' '+(adm.rows[0].cognome||'') : 'Admin';
    const id = uuidv4();
    const r = await pool.query(
      `INSERT INTO prime_forniture (id,operatore_id,nome_operatore,cognome_operatore,admin_id,admin_nome,giacca,maglietta,pantaloni,felpa,radio,note,data_fornitura)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW()) RETURNING *`,
      [id, operatore_id, op.nome||'', op.cognome||'', req.user.id, adminNome.trim(),
       parseInt(giacca)||0, parseInt(maglietta)||0, parseInt(pantaloni)||0,
       parseInt(felpa)||0, parseInt(radio)||0, note||null]);
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/admin/prime-forniture/:id/invia', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM prime_forniture WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({error:'Fornitura non trovata'});
    const f = r.rows[0];
    const data = new Date(f.data_fornitura).toLocaleDateString('it-IT', {day:'2-digit',month:'2-digit',year:'numeric'});
    const righe = [];
    if (f.giacca > 0) righe.push(`• Giacca Security: ${f.giacca} pz`);
    if (f.maglietta > 0) righe.push(`• Maglietta Security: ${f.maglietta} pz`);
    if (f.pantaloni > 0) righe.push(`• Pantaloni Security: ${f.pantaloni} pz`);
    if (f.felpa > 0) righe.push(`• Felpa Security: ${f.felpa} pz`);
    if (f.radio > 0) righe.push(`• Radio: ${f.radio} pz`);
    const testo = `📦 FORNITURA VESTIARIO SECURITY\n\nData consegna: ${data}\n\n${righe.join('\n')}${f.note?'\n\nNote: '+f.note:''}\n\n—\nFornitura abbigliamento security in concordato col regolamento aziendale da Lei sottoscritto.`;
    const msgId = uuidv4();
    await pool.query(
      'INSERT INTO messages (id,testo,is_broadcast,target_user_id,created_at) VALUES ($1,$2,FALSE,$3,NOW())',
      [msgId, testo, f.operatore_id]);
    await pool.query('UPDATE prime_forniture SET messaggio_inviato=TRUE, messaggio_inviato_at=NOW() WHERE id=$1', [req.params.id]);
    const ids = await getPushIds([f.operatore_id]);
    await sendPush(ids, '📦 Fornitura Vestiario Security', `Data: ${data} — ${righe.length} articoli`);
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── HEALTH ────────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Backend in ascolto su porta ${PORT}`));
