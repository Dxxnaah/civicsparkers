// data/store.js
// Minimal JSON-file-backed store for complaint records.
// Kept deliberately simple so the project's attention stays on the
// file-upload security pipeline (middleware/uploadValidator.js),
// which is the assignment's focus.

const fs = require('fs');
const path = require('path');

const DB_FILE = path.join(__dirname, 'complaints.json');

function readAll() {
  if (!fs.existsSync(DB_FILE)) return [];
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    return raw.trim() ? JSON.parse(raw) : [];
  } catch (err) {
    console.error('Failed to read complaints store, starting fresh:', err.message);
    return [];
  }
}

function writeAll(complaints) {
  fs.writeFileSync(DB_FILE, JSON.stringify(complaints, null, 2), 'utf8');
}

function addComplaint(complaint) {
  const complaints = readAll();
  complaints.unshift(complaint); // newest first
  writeAll(complaints);
  return complaint;
}

function getAll() {
  return readAll();
}

function getById(id) {
  return readAll().find((c) => c.id === id) || null;
}

module.exports = { addComplaint, getAll, getById };
