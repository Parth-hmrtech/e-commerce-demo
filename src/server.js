const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
console.log(process.env.PORT); // Correct

const app = require('./app');
const pool = require('./config/db');

const PORT = process.env.PORT ;

pool.connect()
  .then(() => {
    console.log('Connected to PostgreSQL');
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => {
    console.error('Connection failed', err);
  });