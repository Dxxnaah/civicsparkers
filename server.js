// server.js
const path = require('path');
const express = require('express');
const helmet = require('helmet');

const { complaintsRouter, servePhoto } = require('./routes/complaints');
const { UploadRejected } = require('./middleware/uploadValidator');

const app = express();
const PORT = process.env.PORT || 3000;

// Security headers (defense in depth, alongside the file-upload pipeline).
// A tight Content-Security-Policy also means that even if an attacker's
// payload somehow ended up rendered on a page, inline scripts still
// couldn't execute.
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // inline styles used in the demo UI
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
      },
    },
  })
);

app.use(express.json({ limit: '20kb' })); // small limit: this app only accepts short text fields as JSON
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api/complaints', complaintsRouter);
app.get('/uploads/:id', servePhoto);

// Centralized error handler. Upload rejections get a clean 400 with a
// safe message; anything unexpected gets a generic 500 with no internal
// details (stack traces / file paths) leaked to the client.
app.use((err, req, res, next) => {
  if (err instanceof UploadRejected) {
    return res.status(err.statusCode).json({ error: err.message });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request too large.' });
  }
  console.error(err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

app.listen(PORT, () => {
  console.log(`CivicSparkers running at http://localhost:${PORT}`);
});
