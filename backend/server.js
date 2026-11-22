require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.SECRET_KEY) {
  console.error('Chýba token.');
  process.exit(1);
}

app.use(cors());
app.use(express.json());

// --- AUTH MIDDLEWARE ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ message: 'Chýba autorizačný token.' });
  }

  jwt.verify(token, process.env.SECRET_KEY, (err, payload) => {
    if (err || !payload?.userId) {
      return res.status(403).json({ message: 'Neplatný alebo expirovaný token.' });
    }
    req.userId = payload.userId;
    next();
  });
}

// --- REGISTRÁCIA ---
app.post('/api/register', async (req, res) => {
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const phone = typeof req.body.phone === 'string' ? req.body.phone.trim() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';

  if (!name || !email || !phone || !password) {
    return res.status(400).json({ message: 'Vyplňte prosím všetky povinné polia.' });
  }

  if (password.length < 5) {
    return res.status(400).json({ message: 'Heslo musí mať aspoň 5 znakov.' });
  }

  try {
    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'Email už existuje.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await pool.query(
      `INSERT INTO users (name, email, phone, password)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, email, role, profile_complete`,
      [name, email, phone, hashedPassword]
    );

    res.status(201).json({ message: 'Registrácia úspešná', user: newUser.rows[0] });
    } catch (error) {
        if (error?.code === '23505') {
          if (error?.constraint === 'users_phone_key' || error?.constraint?.includes('phone')) {
            return res.status(409).json({ message: 'Telefónne číslo sa už používa.' });
          }
          if (error?.constraint === 'users_email_key' || error?.constraint?.includes('email')) {
            return res.status(409).json({ message: 'Email už existuje.' });
          }
          return res.status(409).json({ message: 'Údaj sa už používa.' });
        }
        console.error(error);
        res.status(500).json({ message: 'Chyba servera pri registrácii.' });
      }
});

// --- LOGIN ---
app.post('/api/login', async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';

  if (!email || !password) {
    return res.status(400).json({ message: 'Vyplňte prosím email a heslo.' });
  }

  try {
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(401).json({ message: 'Nesprávny email alebo heslo.' });
    }

    const user = userResult.rows[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ message: 'Nesprávny email alebo heslo.' });
    }

    const token = jwt.sign({ userId: user.id }, process.env.SECRET_KEY, { expiresIn: '1h' });

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        profile_complete: user.profile_complete,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Chyba servera pri prihlásení.' });
  }
});

// --- DOPLNENIE ÚDAJOV (CHRÁNENÉ JWT TOKENOM) ---
app.post('/api/additional-info', authenticateToken, async (req, res) => {
  const { age, gender, role, monthly_income } = req.body;
  const userId = req.userId;

  try {
    const result = await pool.query(
      `UPDATE users
       SET age = $1, gender = $2, role = $3, monthly_income = $4, profile_complete = TRUE
       WHERE id = $5
       RETURNING id, name, email, age, gender, role, monthly_income, profile_complete`,
      [age, gender, role, monthly_income, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Používateľ sa nenašiel.' });
    }

    res.json({ message: 'Údaje uložené', user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Chyba servera pri ukladaní údajov.' });
  }
});

// --- ŠTART SERVERA ---
app.listen(PORT, () => {
  console.log(`Server beží na http://localhost:${PORT}`);
});