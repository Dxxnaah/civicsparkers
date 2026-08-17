// routes/complaints.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

const store = require('../data/store');
const {
  multerUpload,
  verifyAndSanitizeImage,
  UploadRejected,
  UPLOAD_DIR,
} = require('../middleware/uploadValidator');

const router = express.Router();

// Throttle the upload endpoint specifically: it's the most expensive
// (disk + image processing) and most attractive to abuse.
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many complaints submitted from this network. Please try again later.' },
});

const CATEGORIES = new Set([
  'Broken streetlight',
  'Pothole',
  'Water leak / flooding',
  'Garbage / sanitation',
  'Other',
]);

function cleanText(value, maxLen) {
  if (typeof value !== 'string') return '';
  // Strip control characters and cap length. We do NOT try to strip HTML
  // here -- the frontend renders this with textContent, never innerHTML,
  // so escaping happens safely at render time instead of being lossy here.
  return value.replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, maxLen);
}

// POST /api/complaints  (multipart/form-data: photo, description, location, category, reporterName)
router.post(
  '/',
  uploadLimiter,
  (req, res, next) => {
    multerUpload(req, res, (err) => {
      if (err) return next(err instanceof UploadRejected ? err : new UploadRejected(err.message));
      next();
    });
  },
  verifyAndSanitizeImage,
  (req, res) => {
    const description = cleanText(req.body.description, 500);
    const location = cleanText(req.body.location, 200);
    const reporterName = cleanText(req.body.reporterName, 80);
    const category = CATEGORIES.has(req.body.category) ? req.body.category : 'Other';

    if (!description) {
      return res.status(400).json({ error: 'Please describe the issue.' });
    }
    if (!location) {
      return res.status(400).json({ error: 'Please provide a location.' });
    }

    const complaint = {
      id: require('crypto').randomUUID(),
      category,
      description,
      location,
      reporterName: reporterName || 'Anonymous',
      status: 'Reported',
      createdAt: new Date().toISOString(),
      photo: {
        filename: req.savedFile.filename,
        mimetype: req.savedFile.mimetype,
        size: req.savedFile.size,
      },
    };

    store.addComplaint(complaint);

    res.status(201).json({
      id: complaint.id,
      category: complaint.category,
      description: complaint.description,
      location: complaint.location,
      reporterName: complaint.reporterName,
      status: complaint.status,
      createdAt: complaint.createdAt,
      photoUrl: `/uploads/${complaint.id}`,
    });
  }
);

// GET /api/complaints
router.get('/', (req, res) => {
  const complaints = store.getAll().map((c) => ({
    id: c.id,
    category: c.category,
    description: c.description,
    location: c.location,
    reporterName: c.reporterName,
    status: c.status,
    createdAt: c.createdAt,
    photoUrl: `/uploads/${c.id}`,
  }));
  res.json(complaints);
});

// Serves a complaint's photo. Mounted separately in server.js as
// GET /uploads/:id (kept out of /api so it reads cleanly as a resource URL).
//
// Note this is keyed by COMPLAINT ID, never by raw filename from the URL.
// The actual on-disk filename is looked up server-side from the store,
// so a client can never request an arbitrary path on disk.
function servePhoto(req, res) {
  const complaint = store.getById(req.params.id);
  if (!complaint) return res.status(404).json({ error: 'Not found' });

  const filePath = path.join(UPLOAD_DIR, complaint.photo.filename);

  // Defense in depth, even though the filename only ever came from
  // crypto.randomUUID() on our own server.
  if (path.dirname(filePath) !== UPLOAD_DIR || !fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Not found' });
  }

  res.set({
    'Content-Type': complaint.photo.mimetype,
    'X-Content-Type-Options': 'nosniff', // never let the browser MIME-sniff this response
    'Content-Disposition': 'inline; filename="complaint-photo"',
    'Cache-Control': 'public, max-age=86400, immutable',
  });
  fs.createReadStream(filePath).pipe(res);
}

module.exports = { complaintsRouter: router, servePhoto };
