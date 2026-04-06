require('dotenv').config();
const express = require('express');
const app = express();
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');
const cors = require('cors');

app.use(cors());
app.use(express.json());

app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 4000;
connectDB(process.env.MONGO_URI || 'mongodb://localhost:27017/auth_project')
  .then(()=> app.listen(PORT, ()=> console.log(`Auth server running on ${PORT}`)))
  .catch(err=> console.error('DB connection error', err));
