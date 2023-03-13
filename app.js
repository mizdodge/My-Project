const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const helmet = require('helmet');
const morgan = require('morgan');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Sequelize, DataTypes } = require('sequelize');
const port = 3294;

// middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(helmet());
app.use(morgan('combined'));
app.use(cors());

// inisialisasi user data
const users = [
  { id: 1, username: 'john', password: '$2b$10$vP2Q/2a/ovTH.G/a0IwDVO1rNztYhrZZiL0o9abfz.FdjGosC6/NW' } // password: password123
];

// function untuk mengambil user berdasarkan username
function getUser(username) {
  return users.find(user => user.username === username);
}

// function untuk memeriksa apakah password cocok
async function checkPassword(password, hashedPassword) {
  return await bcrypt.compare(password, hashedPassword);
}

// middleware untuk autentikasi
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

//endpoint untuk error kalau tidak ada target
app.get("/",async(req,res)=>{
    res.sendStatus(404);
})

// endpoint untuk login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = getUser(username);

  if (!user) return res.sendStatus(401);

  if (await checkPassword(password, user.password)) {
    const accessToken = jwt.sign({ username: user.username }, process.env.ACCESS_TOKEN_SECRET);
    res.json({ accessToken });
  } else {
    res.sendStatus(401);
  }
});

// endpoint untuk mengambil data user
app.get('/users', authenticateToken, (req, res) => {
  res.json(users);
});

// endpoint untuk mengambil data user berdasarkan id
app.get('/users/:id', authenticateToken, (req, res) => {
  const user = users.find(user => user.id === parseInt(req.params.id));

  if (!user) return res.sendStatus(404);

  res.json(user);
});

// endpoint untuk membuat data user baru
app.post('/users', authenticateToken, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) return res.sendStatus(400);

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: users.length + 1, username, password: hashedPassword };
  users.push(newUser);

  res.json(newUser);
});

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});
