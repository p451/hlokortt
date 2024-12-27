const express = require('express');
const cors = require('cors');
const session = require('express-session');  // Tämä ennen SQLiteStorea
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const multer = require('multer');
const csv = require('csv-parse');
const path = require('path');
const fs = require('fs');

const app = express();

// Keep existing origins but add additional configuration
const corsOptions = {
  origin: ['https://hlokortti.netlify.app', 'http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'Accept',
    'Cache-Control',
    'Pragma',
    'Cookie',
    'Set-Cookie'
  ],
  exposedHeaders: ['Set-Cookie'],
  maxAge: 600 // Increase preflight cache time to 10 minutes
};

// Apply CORS middleware before routes
app.use(cors(corsOptions));

// Enable pre-flight requests for all routes
app.options('*', cors(corsOptions));

// Add this right after CORS configuration
app.use(session({
  store: new SQLiteStore({ db: 'employees.db', dir: './', table: 'sessions' }),
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: true, // Changed to true
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none', // Required for cross-origin
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true
  },
  name: 'sessionId', // Explicit session cookie name
  rolling: true // Refresh session with each request
}));

// Add this to parse JSON bodies
app.use(express.json({ limit: '1mb' }));

const helmet = require('helmet');
app.use(helmet());

// Multer storage configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = 'uploads';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

const dbPath = './employees.db';  // Changed from database.sqlite
const dbDir = './';

// Tarkistetaan hakemisto
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

// Tarkistetaan tietokantayhteys
const sessionsDb = new SQLiteStore({
    db: 'employees.db',  // Point to existing database
    dir: './',
    table: 'sessions'  // Specify sessions table
});

// Lisätään virheenkäsittely
sessionsDb.on('error', function(error) {
    console.error('Session store error:', error);
});

app.use((req, res, next) => {
  const allowedOrigins = [
    'http://localhost:3000',
    'https://hlokortti.netlify.app' 
  ];
  
  const origin = req.headers.origin;
  
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cookie, Set-Cookie');
  }
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json({ limit: '1mb' }));

const helmet = require('helmet');
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false
}));

// Add static file serving for uploads
app.use('/uploads', express.static('uploads'));

// Configure session after CORS
app.use(session({
  store: new SQLiteStore,
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

app.get('/api/placeholder/:width/:height', (req, res) => {
  const { width, height } = req.params;
  res.sendFile(path.join(__dirname, 'uploads', 'default-logo.png'));
});

app.use(express.json());

// Enable more detailed SQLite logging
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Connected to database successfully');
  }
});

// Database initialization
// Database initialization
db.serialize(() => {
  // Employees table
  db.run(`
    CREATE TABLE IF NOT EXISTS employees (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      name TEXT,
      company TEXT,
      email TEXT,
      membershipLevel TEXT DEFAULT 'BRONZE',
      validUntil TEXT,
      startDate TEXT,
      profileImage TEXT,
      profileImageAdded INTEGER DEFAULT 0,
      logoUrl TEXT DEFAULT '/api/placeholder/100/100',
      firstLogin INTEGER DEFAULT 1,
      isAdmin INTEGER DEFAULT 0
    )
  `);

  // Benefits table
  db.run(`
    CREATE TABLE IF NOT EXISTS benefits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      level TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      validUntil TEXT
    )
  `);

  // Privacy policy table
  db.run(`
    CREATE TABLE IF NOT EXISTS privacy_policy (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      content TEXT NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Tarkistetaan onko sarake jo olemassa
  db.get(
    `SELECT COUNT(*) as count FROM pragma_table_info('employees') 
     WHERE name = 'profileImageAdded'`,
    [],
    (err, row) => {
      if (err) {
        console.error('Error checking column existence:', err);
        return;
      }
      
      if (row && row.count === 0) {
        // Lisätään sarake jos sitä ei ole
        db.run(
          `ALTER TABLE employees 
           ADD COLUMN profileImageAdded INTEGER DEFAULT 0`,
          [],
          (err) => {
            if (err) {
              console.error('Error adding profileImageAdded column:', err);
            } else {
              console.log('Successfully added profileImageAdded column');
            }
          }
        );
      }
    }
  );

  // Lisätään oletustietosuojaseloste jos taulukko on tyhjä
  db.get('SELECT * FROM privacy_policy LIMIT 1', (err, row) => {
    if (!row) {
      db.run(`
        INSERT INTO privacy_policy (content) 
        VALUES (?)
      `, ['<h2>Tietosuojaseloste</h2><p>Tässä on sovelluksen tietosuojaseloste...</p>']);
    }
  });
});


// Database helper functions
const getUserByUsername = (username) => {
  return new Promise((resolve, reject) => {
    db.get('SELECT * FROM employees WHERE username = ?', [username], (err, row) => {
      if (err) {
        console.error('Database error in getUserByUsername:', err);
        reject(err);
        return;
      }
      resolve(row);
    });
  });
};


// Authentication middleware
const requireAuth = (req, res, next) => {
  console.log('Checking auth:', { sessionId: req.session.id, userId: req.session.userId });
  if (!req.session.userId) {
    console.log('Auth check failed: No userId in session');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

// Admin middleware
const requireAdmin = async (req, res, next) => {
  console.log('Checking admin rights:', { sessionId: req.session.id, userId: req.session.userId });
  if (!req.session.userId) {
    console.log('Admin check failed: No userId in session');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  db.get(
    'SELECT isAdmin FROM employees WHERE id = ?',
    [req.session.userId],
    (err, row) => {
      if (err) {
        console.error('Database error during admin check:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      if (!row || !row.isAdmin) {
        console.log('Admin check failed:', { row });
        return res.status(403).json({ error: 'Forbidden' });
      }
      next();
    }
  );
};

const checkAdmin = async (req, res, next) => {
  console.log('Admin check - Session:', req.session);
  
  if (!req.session || !req.session.userId || !req.session.isAdmin) {
    console.log('Admin check failed:', { 
      hasSession: !!req.session,
      userId: req.session?.userId,
      isAdmin: req.session?.isAdmin 
    });
    return res.status(403).json({ 
      success: false, 
      message: 'Unauthorized - Admin access required' 
    });
  }
  next();
};

// Apply to admin routes
app.use('/api/admin/*', checkAdmin);

app.post('/api/upload-profile-image', requireAuth, upload.single('profileImage'), async (req, res) => {
  console.log('Profile image upload attempt:', req.file);
  
  // Tarkista onko käyttäjällä jo kuva
  db.get(
    'SELECT profileImageAdded FROM employees WHERE id = ?',
    [req.session.userId],
    async (err, row) => {
      if (err) {
        console.error('Database error checking profile image status:', err);
        return res.status(500).json({ error: 'Server error' });
      }

      if (row.profileImageAdded) {
        return res.status(403).json({ error: 'Profile image can only be uploaded once' });
      }

      if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
      }

      try {
        const imageUrl = `/uploads/${req.file.filename}`;
        
        // Päivitä kuva ja merkitse profileImageAdded todeksi
        db.run(
          'UPDATE employees SET profileImage = ?, profileImageAdded = 1 WHERE id = ?',
          [imageUrl, req.session.userId],
          function(err) {
            if (err) {
              console.error('Database error updating profile image:', err);
              return res.status(500).json({ error: 'Failed to update profile image' });
            }
            console.log('Profile image updated successfully:', imageUrl);
            res.json({ 
              message: 'Profile image uploaded successfully',
              imageUrl: imageUrl
            });
          }
        );
      } catch (error) {
        console.error('Error handling profile image upload:', error);
        res.status(500).json({ error: 'Failed to upload profile image' });
      }
    }
  );
});

// Privacy policy endpoint
app.get('/api/privacy-policy', requireAuth, (req, res) => {
  db.get('SELECT content FROM privacy_policy ORDER BY updated_at DESC LIMIT 1', (err, row) => {
    if (err) {
      console.error('Database error fetching privacy policy:', err);
      return res.status(500).json({ error: 'Server error' });
    }
    if (!row) {
      return res.status(404).json({ error: 'Privacy policy not found' });
    }
    res.json({ content: row.content });
  });
});

app.get('/api/admin/available-logos', requireAdmin, (req, res) => {
  const uploadsDir = path.join(__dirname, 'uploads');
  fs.readdir(uploadsDir, (err, files) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to read logos directory' });
    }
    const logos = files.filter(file => file.startsWith('logo-'));
    res.json({ logos: logos.map(logo => `/uploads/${logo}`) });
  });
});

// Update privacy policy endpoint
app.put('/api/admin/privacy-policy', requireAdmin, (req, res) => {
  const { content } = req.body;
  
  if (!content) {
    return res.status(400).json({ error: 'Content is required' });
  }

  db.run(
    `INSERT INTO privacy_policy (content, updated_at) 
     VALUES (?, datetime('now'))`,
    [content],
    function(err) {
      if (err) {
        console.error('Database error updating privacy policy:', err);
        return res.status(500).json({ error: 'Failed to update privacy policy' });
      }

      res.json({ 
        message: 'Privacy policy updated successfully',
        id: this.lastID
      });
    }
  );
});

// Get all privacy policy versions endpoint (optional, for history)
app.get('/api/admin/privacy-policy/history', requireAdmin, (req, res) => {
  db.all(
    'SELECT id, content, updated_at FROM privacy_policy ORDER BY updated_at DESC',
    (err, rows) => {
      if (err) {
        console.error('Database error fetching privacy policy history:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      res.json(rows);
    }
  );
});

// Login endpoint with detailed logging
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log('Login attempt:', { username, password });

    const user = await getUserByUsername(username);
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Explicitly set session data
    req.session.userId = user.id;
    req.session.isAdmin = Boolean(user.isAdmin);
    
    // Force session save
    await new Promise((resolve) => req.session.save(resolve));

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        isAdmin: Boolean(user.isAdmin),
        name: user.name,
        company: user.company
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

app.options('/api/check-auth', cors(corsOptions));

app.get('/api/check-auth', cors(corsOptions), requireAuth, (req, res) => {
  console.log('Checking auth status for user:', req.session.userId);
  console.log('Session:', req.session);  // Lisätään debug-loki
  console.log('Headers:', req.headers);  // Lisätään debug-loki
  
  db.get(
    `SELECT id, name, company, email, membershipLevel, validUntil, startDate, 
            profileImage, logoUrl, firstLogin, isAdmin 
     FROM employees 
     WHERE id = ?`,
    [req.session.userId],
    (err, user) => {
      if (err) {
        console.error('Database error during auth check:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      if (!user) {
        console.log('User not found during auth check');
        return res.status(401).json({ error: 'Unauthorized' });
      }

      // Varmistetaan että profileImage ja logoUrl ovat aina määritelty
      user.profileImage = user.profileImage || '/api/placeholder/400/400';
      user.logoUrl = user.logoUrl || '/api/placeholder/100/100';

      // Asetetaan CORS-headerit eksplisiittisesti
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Allow-Origin', process.env.CORS_ORIGIN);
      
      res.json(user);
    }
  );
});

// Logout endpoint with logging
app.post('/api/logout', (req, res) => {
  console.log('Logout request for session:', req.session.id);
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ message: 'Logged out' });
  });
});



// File upload endpoints with logging
app.post('/api/admin/upload-employees', requireAdmin, upload.single('file'), (req, res) => {
  console.log('Employee file upload attempt');
  
  if (!req.file) {
    console.log('No file provided');
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const parser = csv.parse({ columns: true }, async (err, records) => {
    if (err) {
      console.error('CSV parsing error:', err);
      return res.status(400).json({ error: 'Invalid file format' });
    }

    try {
      const stmt = db.prepare(`
        INSERT OR REPLACE INTO employees (username, name, company, validUntil)
        VALUES (?, ?, ?, ?)
      `);

      for (const record of records) {
        stmt.run([
          record.username,
          record.name,
          record.company,
          record.validUntil
        ]);
      }

      stmt.finalize();
      console.log('Employees updated successfully');
      res.json({ message: 'Employees updated successfully' });
    } catch (error) {
      console.error('Database error during employee upload:', error);
      res.status(500).json({ error: 'Failed to update employees' });
    }
  });

  fs.createReadStream(req.file.path).pipe(parser);
});

app.post('/api/admin/upload-benefits', requireAdmin, upload.single('file'), (req, res) => {
  console.log('Benefits file upload attempt');
  
  if (!req.file) {
    console.log('No file provided');
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const parser = csv.parse({ columns: true }, (err, records) => {
    if (err) {
      console.error('CSV parsing error:', err);
      return res.status(400).json({ error: 'Invalid file format' });
    }

    try {
      const stmt = db.prepare(`
        INSERT OR REPLACE INTO benefits (title, description, validUntil)
        VALUES (?, ?, ?)
      `);

      for (const record of records) {
        stmt.run([
          record.title,
          record.description,
          record.validUntil
        ]);
      }

      stmt.finalize();
      console.log('Benefits updated successfully');
      res.json({ message: 'Benefits updated successfully' });
    } catch (error) {
      console.error('Database error during benefits upload:', error);
      res.status(500).json({ error: 'Failed to update benefits' });
    }
  });

  fs.createReadStream(req.file.path).pipe(parser);
});

// Password management endpoints with logging
app.post('/api/admin/reset-password', requireAdmin, async (req, res) => {
  const { userId, newPassword } = req.body;
  console.log('Password reset attempt for user:', userId);
  
  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    db.run(
      'UPDATE employees SET password = ? WHERE id = ?',
      [hashedPassword, userId],
      (err) => {
        if (err) {
          console.error('Database error during password reset:', err);
          return res.status(500).json({ error: 'Server error' });
        }
        console.log('Password reset successful');
        res.json({ message: 'Password reset successfully' });
      }
    );
  } catch (error) {
    console.error('Bcrypt error during password reset:', error);
    res.status(500).json({ error: 'Password hashing failed' });
  }
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  console.log('Password change attempt for user:', req.session.userId);

  try {
    db.get(
      'SELECT password FROM employees WHERE id = ?',
      [req.session.userId],
      async (err, user) => {
        if (err) {
          console.error('Database error during password change:', err);
          return res.status(500).json({ error: 'Server error' });
        }

        if (!user) {
          console.log('User not found during password change');
          return res.status(401).json({ error: 'User not found' });
        }

        try {
          const passwordMatch = await bcrypt.compare(currentPassword, user.password);
          if (!passwordMatch) {
            console.log('Invalid current password');
            return res.status(401).json({ error: 'Invalid current password' });
          }

          const hashedPassword = await bcrypt.hash(newPassword, 10);

          db.run(
            'UPDATE employees SET password = ? WHERE id = ?',
            [hashedPassword, req.session.userId],
            (err) => {
              if (err) {
                console.error('Database error updating password:', err);
                return res.status(500).json({ error: 'Server error' });
              }
              console.log('Password changed successfully');
              res.json({ message: 'Password changed successfully' });
            }
          );
        } catch (bcryptError) {
          console.error('Bcrypt error during password change:', bcryptError);
          res.status(500).json({ error: 'Password processing failed' });
        }
      }
    );
  } catch (error) {
    console.error('Unexpected error during password change:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Employee management endpoints with logging
app.put('/api/profile', requireAuth, (req, res) => {
  const { name } = req.body;
  console.log('Profile update attempt for user:', req.session.userId);

  db.run(
    'UPDATE employees SET name = ? WHERE id = ?',
    [name, req.session.userId],
    (err) => {
      if (err) {
        console.error('Database error during profile update:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      console.log('Profile updated successfully');
      res.json({ message: 'Profile updated successfully' });
    }
  );
});

const USER_FIELDS = `id, username, name, company, email, membershipLevel, 
                    validUntil, startDate, logoUrl, profileImage, 
                    firstLogin, isAdmin`;

                    app.get('/api/admin/employees', requireAdmin, (req, res) => {
                      db.all(
                        `SELECT ${USER_FIELDS} FROM employees`,
                        (err, employees) => {
                          if (err) {
                            console.error('Database error fetching employees:', err);
                            return res.status(500).json({ error: 'Server error' });
                          }
                          res.json(employees);
                        }
                      );
                    });

                    app.get('/api/admin/employees/:id', requireAdmin, (req, res) => {
                      console.log('Fetching employee:', req.params.id);
                      
                      db.get(
                        `SELECT ${USER_FIELDS} FROM employees WHERE id = ?`,
                        [req.params.id],
                        (err, employee) => {
                          if (err) {
                            console.error('Database error fetching employee:', err);
                            return res.status(500).json({ error: 'Server error' });
                          }
                          if (!employee) {
                            console.log('Employee not found');
                            return res.status(404).json({ error: 'Employee not found' });
                          }
                          res.json(employee);
                        }
                      );
                    });

app.put('/api/admin/employees/:id', requireAdmin, (req, res) => {
  const { 
    name, 
    company, 
    email,
    membershipLevel,
    validUntil,
    startDate,
    logoUrl
  } = req.body;

  const sql = `
    UPDATE employees 
    SET name = ?, 
        company = ?, 
        email = ?, 
        membershipLevel = ?,
        validUntil = ?, 
        startDate = ?,
        logoUrl = COALESCE(?, logoUrl)
    WHERE id = ?
  `;

  const params = [
    name, 
    company, 
    email, 
    membershipLevel, 
    validUntil, 
    startDate,
    logoUrl,
    req.params.id
  ];

  db.run(sql, params, function(err) {
    if (err) {
      console.error('Database error updating employee:', err);
      return res.status(500).json({ error: 'Server error' });
    }
    console.log('Employee updated successfully');
    res.json({ message: 'Employee updated successfully' });
  });
});

app.post('/api/admin/employees', requireAdmin, async (req, res) => {
  const { 
    username, 
    name, 
    company, 
    email,
    membershipLevel,
    validUntil, 
    startDate,
    password 
  } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO employees (
        username, password, name, company, email, membershipLevel, 
        validUntil, startDate, firstLogin
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [username, hashedPassword, name, company, email, membershipLevel, validUntil, startDate, 1],
      function(err) {
        if (err) {
          console.error('Database error creating employee:', err);
          if (err.code === 'SQLITE_CONSTRAINT') {
            return res.status(400).json({ error: 'Username already exists' });
          }
          return res.status(500).json({ error: 'Server error' });
        }
        
        // Haetaan luotu työntekijä
        db.get(
          'SELECT * FROM employees WHERE id = ?',
          [this.lastID],
          (err, employee) => {
            if (err) {
              console.error('Error fetching created employee:', err);
              return res.status(500).json({ error: 'Server error' });
            }
            res.json({
              id: this.lastID,
              message: 'Employee added successfully',
              employee
            });
          }
        );
      }
    );
  } catch (error) {
    console.error('Error creating employee:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/employees/:id', requireAdmin, (req, res) => {
  console.log('Deleting employee:', req.params.id);
  
  db.run(
    'DELETE FROM employees WHERE id = ?',
    [req.params.id],
    (err) => {
      if (err) {
        console.error('Database error deleting employee:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      console.log('Employee deleted successfully');
      res.json({ message: 'Employee deleted successfully' });
    }
  );
});

// Hae kaikki edut (admin)
app.get('/api/admin/benefits', requireAdmin, (req, res) => {
  db.all('SELECT * FROM benefits ORDER BY level, validUntil DESC', (err, benefits) => {
    if (err) {
      console.error('Database error fetching benefits:', err);
      return res.status(500).json({ error: 'Server error' });
    }
    res.json(benefits);
  });
});

app.post('/api/admin/upload-logo', requireAdmin, upload.single('file'), async (req, res) => {
  console.log('Logo upload attempt:', req.file);
  
  if (!req.file) {
    console.log('No file uploaded');
    return res.status(400).json({ error: 'No file uploaded' });
  }

  try {
    const imageUrl = `/uploads/${req.file.filename}`;
    console.log('Logo uploaded successfully:', imageUrl);
    res.json({ 
      message: 'Logo uploaded successfully',
      logoUrl: imageUrl
    });
  } catch (error) {
    console.error('Error handling logo upload:', error);
    res.status(500).json({ error: 'Failed to upload logo' });
  }
});

// Lisää uusi etu
app.post('/api/admin/benefits', requireAdmin, (req, res) => {
  const { level, title, description, validUntil } = req.body;

  db.run(
    'INSERT INTO benefits (level, title, description, validUntil) VALUES (?, ?, ?, ?)',
    [level, title, description, validUntil],
    function(err) {
      if (err) {
        console.error('Database error creating benefit:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      res.json({
        id: this.lastID,
        message: 'Benefit added successfully'
      });
    }
  );
});

// Päivitä etu
app.put('/api/admin/benefits/:id', requireAdmin, (req, res) => {
  const { title, description, validUntil, level } = req.body;
  const benefitId = req.params.id;

  db.run(
    'UPDATE benefits SET title = ?, description = ?, validUntil = ?, level = ? WHERE id = ?',
    [title, description, validUntil, level, benefitId],
    (err) => {
      if (err) {
        console.error('Database error updating benefit:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      res.json({ message: 'Benefit updated successfully' });
    }
  );
});

// Poista etu
app.delete('/api/admin/benefits/:id', requireAdmin, (req, res) => {
  const benefitId = req.params.id;

  db.run('DELETE FROM benefits WHERE id = ?', [benefitId], (err) => {
    if (err) {
      console.error('Database error deleting benefit:', err);
      return res.status(500).json({ error: 'Server error' });
    }
    res.json({ message: 'Benefit deleted successfully' });
  });
});

// Hae käyttäjän edut (perustuen jäsentasoon)
app.get('/api/benefits', requireAuth, (req, res) => {
  db.get(
    'SELECT membershipLevel FROM employees WHERE id = ?',
    [req.session.userId],
    (err, employee) => {
      if (err) {
        console.error('Database error fetching employee level:', err);
        return res.status(500).json({ error: 'Server error' });
      }

      if (!employee) {
        return res.status(404).json({ error: 'Employee not found' });
      }

      db.all(
        'SELECT * FROM benefits WHERE level = ? AND validUntil >= date("now") ORDER BY validUntil DESC',
        [employee.membershipLevel],
        (err, benefits) => {
          if (err) {
            console.error('Database error fetching benefits:', err);
            return res.status(500).json({ error: 'Server error' });
          }
          res.json(benefits);
        }
      );
    }
  );
});



// Server startup
const PORT = process.env.PORT || 4000;  // Muutettu 3001 -> 8080
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// 1. Combine session debugging middlewares
app.use((req, res, next) => {
  console.log('Session debug:', {
    sessionId: req.sessionID,
    userId: req.session?.userId,
    isAdmin: req.session?.isAdmin,
    path: req.path,
    method: req.method,
    hasSession: !!req.session,
    cookies: req.headers.cookie
  });
  next();
});

// 2. Error handling middleware at the end
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: err.message 
  });
});

// 3. Export after all middleware/routes
module.exports = { app, getUserByUsername, db };
