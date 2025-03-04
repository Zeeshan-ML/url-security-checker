-- Table for Blacklisted URLs
CREATE TABLE IF NOT EXISTS blacklist (
  id INT AUTO_INCREMENT PRIMARY KEY,
  url VARCHAR(2083) NOT NULL,
  UNIQUE KEY url_unique (url(255))
);

-- Table for Whitelisted URLs
CREATE TABLE IF NOT EXISTS whitelist (
  id INT AUTO_INCREMENT PRIMARY KEY,
  url VARCHAR(2083) NOT NULL,
  UNIQUE KEY url_unique (url(255))
);

-- Table for storing URL analysis history
CREATE TABLE IF NOT EXISTS history (
  id INT AUTO_INCREMENT PRIMARY KEY,
  url VARCHAR(2083) NOT NULL,
  result VARCHAR(50),
  risk_level VARCHAR(50),
  analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for Behavioral Analysis
CREATE TABLE IF NOT EXISTS behavioral_analysis (
  id INT AUTO_INCREMENT PRIMARY KEY,
  target_url VARCHAR(2083) NOT NULL,
  redirects INT,
  mouse_hover_count INT,
  time_spent INT,
  right_click_blocked BOOLEAN,
  iframe_count INT,
  popups INT,
  auto_form_submissions INT,
  keystroke_listeners INT,
  clipboard_access BOOLEAN,
  obfuscated_links INT,
  risk_score INT,
  analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
