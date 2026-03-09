-- OperatorApp Database Schema

CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(36) PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  is_admin BOOLEAN DEFAULT FALSE,
  nome VARCHAR(100),
  cognome VARCHAR(100),
  telefono VARCHAR(50),
  indirizzo TEXT,
  data_nascita DATE,
  codice_fiscale VARCHAR(20),
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS expenses (
  id VARCHAR(36) PRIMARY KEY,
  user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
  luogo TEXT NOT NULL,
  data DATE NOT NULL,
  solo_guida BOOLEAN DEFAULT FALSE,
  note TEXT,
  pagato BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS messages (
  id VARCHAR(36) PRIMARY KEY,
  testo TEXT NOT NULL,
  nome_file VARCHAR(255),
  mime_type VARCHAR(100),
  file_data TEXT,
  is_broadcast BOOLEAN DEFAULT TRUE,
  target_user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS message_reads (
  message_id VARCHAR(36) REFERENCES messages(id) ON DELETE CASCADE,
  user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (message_id, user_id)
);

CREATE TABLE IF NOT EXISTS message_deletions (
  message_id VARCHAR(36) REFERENCES messages(id) ON DELETE CASCADE,
  user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (message_id, user_id)
);

CREATE TABLE IF NOT EXISTS incoming_messages (
  id VARCHAR(36) PRIMARY KEY,
  from_user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
  from_name VARCHAR(200),
  from_email VARCHAR(255),
  testo TEXT NOT NULL,
  nome_file VARCHAR(255),
  mime_type VARCHAR(100),
  file_data TEXT,
  reply TEXT,
  reply_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS documents (
  user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
  doc_key VARCHAR(50) NOT NULL,
  nome_file VARCHAR(255),
  mime_type VARCHAR(100),
  file_data TEXT,
  upload_date TIMESTAMP DEFAULT NOW(),
  PRIMARY KEY (user_id, doc_key)
);

CREATE TABLE IF NOT EXISTS info_items (
  id VARCHAR(36) PRIMARY KEY,
  text TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rules (
  id VARCHAR(36) PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  text TEXT NOT NULL,
  pdf_data TEXT,
  pdf_name VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rules_log (
  id VARCHAR(36) PRIMARY KEY,
  user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
  user_name VARCHAR(200),
  user_email VARCHAR(255),
  rule_id VARCHAR(36) REFERENCES rules(id) ON DELETE CASCADE,
  rule_text TEXT,
  decision VARCHAR(20) NOT NULL,
  timestamp TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS urgent_messages (
  id VARCHAR(36) PRIMARY KEY,
  testo TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tessere (
  id VARCHAR(36) PRIMARY KEY,
  user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
  creata_da VARCHAR(36),
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS richieste_password (
  id VARCHAR(36) PRIMARY KEY,
  user_id VARCHAR(36) REFERENCES users(id) ON DELETE SET NULL,
  nome VARCHAR(100) NOT NULL,
  cognome VARCHAR(100) NOT NULL,
  nuova_password_richiesta VARCHAR(255) NOT NULL,
  stato VARCHAR(20) DEFAULT 'in_attesa',
  data_richiesta TIMESTAMP DEFAULT NOW(),
  data_completamento TIMESTAMP
);

-- Seed: admin user (password: 02382450225)
INSERT INTO users (id, email, password_hash, is_admin, nome, cognome, created_at)
VALUES (
  'admin-001',
  'Alfadetectives@Gmail.com',
  '$2b$10$6S5dqHJ/tdNh.q0zZPRS9exDo9DNKYoSPV2ORADPySOQvp40rz9g6',
  TRUE,
  'Admin',
  'AD Security',
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- Seed info_items
INSERT INTO info_items (id, text) VALUES
  ('info-001', 'Orari ufficio: Lunedi-Venerdi 09:00-18:00. Sabato 09:00-13:00.'),
  ('info-002', 'Per richiedere ferie o permessi contattare l''ufficio con almeno 7 giorni di anticipo.'),
  ('info-003', 'In caso di assenza improvvisa avvisare entro le 06:00 del giorno stesso al numero: 333 000 1234.'),
  ('info-004', 'Il tesserino di riconoscimento deve essere sempre indossato in modo visibile durante il servizio.'),
  ('info-005', 'Le divise devono essere sempre pulite e in ordine. Vietato presentarsi in servizio senza divisa completa.')
ON CONFLICT (id) DO NOTHING;

-- Seed rules
INSERT INTO rules (id, title, text) VALUES
  ('rule-001', 'Codice di Condotta', 'L''operatore si impegna a rispettare il codice di condotta aziendale in ogni circostanza.'),
  ('rule-002', 'Uso Cellulare', 'E'' vietato l''uso del cellulare personale durante le ore di servizio attivo salvo emergenze.'),
  ('rule-003', 'Gestione Incidenti', 'Qualsiasi incidente o anomalia deve essere comunicata immediatamente al responsabile di turno.'),
  ('rule-004', 'Riservatezza', 'L''operatore si impegna a mantenere la riservatezza su tutte le informazioni relative ai clienti.'),
  ('rule-005', 'Uso Divisa e Tesserino', 'L''uso improprio della divisa o del tesserino aziendale è causa di immediata sospensione.')
ON CONFLICT (id) DO NOTHING;
