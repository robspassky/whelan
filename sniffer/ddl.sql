CREATE TABLE IF NOT EXISTS main.sessions (
  id INTEGER PRIMARY KEY ASC AUTOINCREMENT,
  platform VARCHAR(50),
  vid VARCHAR(50) DEFAULT '',
  pid VARCHAR(50) DEFAULT '',
  bcid VARCHAR(50) DEFAULT '',
  hasAd boolean DEFAULT false,
  time LONG DEFAULT 0
);

CREATE TABLE IF NOT EXISTS main.requests(
  sessionId INTEGER,
  url VARCHAR(255),
  content VARCHAR(1024),
  time LONG
);

