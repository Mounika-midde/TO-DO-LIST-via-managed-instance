const mysql = require('mysql2');
require('dotenv').config();

// Connection WITHOUT database
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
}).promise();

async function createDatabaseIfNotExists() {
  try {
    await connection.query(`CREATE DATABASE IF NOT EXISTS \`${process.env.DB_NAME}\``);
    console.log(`Database '${process.env.DB_NAME}' checked/created.`);
  } catch (err) {
    console.error('Error creating database:', err);
  } finally {
    await connection.end();
  }
}

// Then create a pool that connects directly to the database
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  namedPlaceholders: true,
}).promise();

// Function to create table
async function createTodosTableIfNotExists() {
  try {
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS todos (
        id VARCHAR(36) PRIMARY KEY,
        todo VARCHAR(50) NOT NULL
      )
    `);
    console.log("'todos' table checked/created.");
  } catch (err) {
    console.error('Error creating todos table:', err);
  }
}

// Run
(async () => {
  await createDatabaseIfNotExists();
  await createTodosTableIfNotExists();
})();

module.exports ={pool}