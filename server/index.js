const express = require('express');
const cors = require('cors');
const { TodoRouter } = require('./routers/taskRoute'); // ✅ Correct file name

const app = express();

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL,
  methods:["PUT","POST","GET", "DELETE"],
  credentials: true
}));
app.use(express.json());

// Routes
app.use('/api', TodoRouter);

// Start the server
app.listen(8080,"0.0.0.0", () => {
  console.log('Server is running on port 8080');
});
