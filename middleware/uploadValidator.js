// middleware/uploadValidator.js
//
// SECURE FILE UPLOAD VALIDATION
// ------------------------------
// This is the security control the assignment asks us to demonstrate.
// A naive upload handler trusts the client-supplied filename, extension
// and MIME type, and writes the file into a folder the web server can
// execute from. Every one of those trust decisions is attacker-controlled
// and has a well-known exploit attached to it:
//
//   Attacker move                          -> Defense implemented here
//   -------------------------------------------------------------------
//   Rename shell.php to shell.jpg          -> magic-byte content sniffing
//                                              (file-type), not extension
//   Fake the Content-Type header           -> magic-byte check ignores the
//                                              client-supplied MIME entirely
//   Upload a "GIFAR" / polyglot image       -> image is decoded and
//   (valid image header + embedded HTML/JS/    RE-ENCODED with sharp; any
//    PHP payload appended after it)            trailing/embedded bytes that
//                                              aren't real pixel data are
//                                              discarded in the process
//   Path traversal via filename             -> original filename is never
//   ("../../server.js")                        used; a random UUID name is
//                                              generated server-side
//   Overwrite an existing file              -> random UUID filename makes
//                                              collisions cryptographically
//                                              unlikely
//   Huge file / decompression bomb          -> multer file-size limit +
//                                              sharp dimension cap
//   Served file executes in the browser     -> saved outside the static
//   (stored XSS via SVG/HTML upload,           web root, served through a
//    or MIME-sniffed as HTML)                  dedicated route that sets an
//                                              explicit Content-Type and
//                                              X-Content-Type-Options: nosniff
//
// The result: even a fully malicious file that passes the extension and
// declared-MIME checks cannot survive the decode-and-re-encode step,
// because sharp only understands actual raster image data.

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const sharp = require('sharp');
const { fromBuffer } = require('file-type');

const UPLOAD_DIR = path.join(__dirname, '..', 'uploads'); // NOT under /public
const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB
const MAX_DIMENSION = 1600; // px, longest side after resize

// Only raster formats we can safely re-encode. Deliberately excludes SVG
// (XML, can carry <script>) and anything else that isn't a pixel format.
const ALLOWED = {
  'image/jpeg': { ext: 'jpg', sharpFormat: 'jpeg' },
  'image/png': { ext: 'png', sharpFormat: 'png' },
  'image/webp': { ext: 'webp', sharpFormat: 'webp' },
};
const ALLOWED_EXTENSIONS = new Set(['.jpg', '.jpeg', '.png', '.webp']);

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

class UploadRejected extends Error {
  constructor(message) {
    super(message);
    this.name = 'UploadRejected';
    this.statusCode = 400;
  }
}

// --- Layer 1: cheap, early rejection based on what the client claims ---
// This is NOT trusted as the real check (client can lie), it just avoids
// wasting work on obviously wrong uploads before we touch the file bytes.
const multerUpload = multer({
  storage: multer.memoryStorage(), // buffer only; nothing hits disk yet
  limits: { fileSize: MAX_FILE_BYTES, files: 1 },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      return cb(new UploadRejected('Unsupported file extension. Use JPG, PNG, or WEBP.'));
    }
    if (!Object.prototype.hasOwnProperty.call(ALLOWED, file.mimetype)) {
      return cb(new UploadRejected('Unsupported declared file type.'));
    }
    cb(null, true);
  },
}).single('photo');

// --- Layer 2: the real check — inspect the actual bytes, then rebuild
//     the image from scratch so nothing but genuine pixel data survives.
async function verifyAndSanitizeImage(req, res, next) {
  try {
    if (!req.file) {
      // Photo is required for a complaint report in this app.
      return next(new UploadRejected('A photo of the issue is required.'));
    }

    // Magic-byte detection: what is this file ACTUALLY, ignoring the
    // filename and the Content-Type header the browser sent.
    const detected = await fromBuffer(req.file.buffer);
    if (!detected || !Object.prototype.hasOwnProperty.call(ALLOWED, detected.mime)) {
      return next(new UploadRejected(
        'The uploaded file does not look like a genuine JPG, PNG, or WEBP image.'
      ));
    }

    // Cross-check: does what the browser claimed match what the bytes say?
    // A mismatch is a strong spoofing signal (e.g. .jpg extension on a
    // file whose real header is something else entirely).
    if (detected.mime !== req.file.mimetype) {
      return next(new UploadRejected('Declared file type does not match file contents.'));
    }

    // Decode + re-encode. This is the step that neutralizes polyglot
    // files: a genuine JPEG header followed by injected HTML/JS/PHP will
    // decode fine as an image, but sharp only reads the pixel data and
    // writes out a clean new file — the trailing payload is dropped.
    // A corrupted or non-image file will throw here and be rejected.
    const safe = ALLOWED[detected.mime];
    const cleaned = await sharp(req.file.buffer)
      .rotate() // normalize EXIF orientation, then metadata is stripped below
      .resize({
        width: MAX_DIMENSION,
        height: MAX_DIMENSION,
        fit: 'inside',
        withoutEnlargement: true,
      })
      .toFormat(safe.sharpFormat, { quality: 82 })
      .toBuffer();

    // Server-generated filename only. The client's original filename is
    // discarded entirely, so there is nothing here for a path-traversal
    // or overwrite attack to act on.
    const filename = `${crypto.randomUUID()}.${safe.ext}`;
    const destination = path.join(UPLOAD_DIR, filename);

    // Defense in depth: even though the name is server-generated, confirm
    // the resolved path still lands inside UPLOAD_DIR before writing.
    if (path.dirname(destination) !== UPLOAD_DIR) {
      return next(new UploadRejected('Invalid upload destination.'));
    }

    fs.writeFileSync(destination, cleaned);

    req.savedFile = {
      filename,
      mimetype: detected.mime,
      size: cleaned.length,
    };
    next();
  } catch (err) {
    if (err instanceof UploadRejected) return next(err);
    // sharp throws here for corrupt/non-image buffers that slipped past
    // the earlier checks -- treat that as a rejected upload, not a 500.
    next(new UploadRejected('The uploaded file could not be processed as a valid image.'));
  }
}

module.exports = { multerUpload, verifyAndSanitizeImage, UploadRejected, UPLOAD_DIR };
