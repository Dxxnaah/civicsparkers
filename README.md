##  Live Demo

[🌐 Open CivicSparkers Live] : (https://civicsparkers.onrender.com) 

# CivicSparkers — Secure Civic Complaint Reporting System

**Track:** Strong Institutions — civic complaint reporting
**Course context:** Web Exploitation and Defence
**Security control implemented:** Secure File Upload Validation

A resident reports a civic issue — a broken streetlight, a pothole, a leak —
with a category, a location, a short description, and a **photo**. The
photo is the interesting part of this build: it is the one field in the
form that is not plain text, and file upload is consistently one of the
highest-value entry points for attackers against a web application. This
project's whole security case study is built around making that one field
safe.

---

## 1. Why file upload, specifically

An upload endpoint is dangerous because it asks the server to do three
risky things at once:

1. Accept bytes from a stranger.
2. Store those bytes on disk.
3. Later serve those bytes back out to other users' browsers.

If any one of the trust decisions in that pipeline is left to the
client — the filename, the declared file type, where the file gets
written, how it gets served — the endpoint becomes exploitable. This maps
directly to **OWASP's Unrestricted File Upload** risk (part of the
Top 10 category *A03/A05 — Injection / Security Misconfiguration*,
and its own entry in the OWASP File Upload Cheat Sheet).

### Attacks this endpoint is built to resist

| Attack | What it looks like | Defense in this project |
|---|---|---|
| Extension spoofing | `shell.php` renamed to `shell.jpg` | Extension **and** declared MIME type are checked, but neither is trusted as the real answer |
| Content-Type spoofing | `curl -F "photo=@shell.jpg;type=image/jpeg"` | The file's real type is read from its **magic bytes**, ignoring the header the client sent |
| Polyglot / GIFAR-style files | A valid image header with an HTML/JS/PHP payload appended after it | The file is **decoded and re-encoded** with `sharp`; only genuine pixel data survives, any appended payload is discarded |
| Path traversal via filename | `../../../server.js` as the "filename" | The original filename is **never used** — a `crypto.randomUUID()` name is generated server-side |
| Overwriting existing files | Uploading a file with a name that collides with something important | Same random-UUID naming makes collisions effectively impossible |
| Decompression bomb / huge image | A tiny file that decodes into a gigantic bitmap | `sharp` caps the re-encoded image to 1600px on the long side; multer caps upload size at 5 MB |
| Stored file gets executed | Uploading `evil.html`/`evil.svg` and linking directly to it so it renders/executes in a victim's browser | Only raster formats (JPG/PNG/WEBP) are accepted — **no SVG, no HTML** — files are stored **outside** the web root and served through a controlled route with an explicit `Content-Type` and `X-Content-Type-Options: nosniff` |
| Reading arbitrary files via the "download" route | `GET /uploads/../../etc/passwd`-style requests | The serving route is keyed by **complaint ID**, looked up server-side; the client never supplies a raw filename or path at all |

### Where this sits in the code

- `middleware/uploadValidator.js` — the whole pipeline, heavily commented,
  is the file to read for the write-up.
- `routes/complaints.js` — wires the pipeline into the `POST /api/complaints`
  route, and serves photos back out through `GET /uploads/:id`.
- `server.js` — adds `helmet` (security headers / CSP) and centralized
  error handling that never leaks stack traces to the client.

### The pipeline, in order

```
client upload
    │
    ▼
① multer (memory storage only — nothing touches disk yet)
    │  - rejects if extension not in { .jpg, .jpeg, .png, .webp }
    │  - rejects if declared MIME not in the same whitelist
    │  - rejects if file > 5 MB
    ▼
② magic-byte detection (file-type package reads the actual header bytes)
    │  - rejects if the real file type isn't a genuine JPG/PNG/WEBP
    │  - rejects if the real type doesn't match what the client declared
    ▼
③ decode + re-encode (sharp)
    │  - normalizes orientation, strips all metadata
    │  - resizes to a safe max dimension
    │  - re-encodes to a clean JPG/PNG/WEBP buffer
    │  - throws (→ rejected) on anything that isn't a real, intact image
    ▼
④ random filename, written outside the static web root
    │  - crypto.randomUUID() + verified extension
    │  - original filename is discarded entirely
    ▼
⑤ stored, and only ever served back via GET /uploads/:complaintId
       (never by raw filename; explicit Content-Type; nosniff header)
```

A file has to survive all five stages to ever reach disk, and even then
it can only be retrieved through one controlled route.

---

## 2. Other defense-in-depth touches (secondary to the main focus)

- **Helmet** sets a restrictive Content-Security-Policy and standard
  security headers on every response.
- **Rate limiting** (`express-rate-limit`) throttles the upload endpoint
  specifically, since it's the most expensive one to abuse.
- **Output-side XSS protection**: the frontend (`public/app.js`) renders
  every user-supplied field (description, location, name) with
  `textContent`, never `innerHTML`, so a malicious complaint description
  can never execute as markup in another visitor's browser.
- **Centralized error handling**: rejected uploads return a clean, generic
  message; unexpected errors return a generic 500 with details only in the
  server log, never in the response body.

---

## 3. Running it

```bash
npm install
node server.js
# open http://localhost:3000
```

Data is stored in `data/complaints.json` (created on first submission);
photos are stored in `uploads/` (created on first submission, outside
`public/`, so they are never directly web-accessible except through the
`/uploads/:id` route).

## 4. Demonstrating the security control

A few curl commands to show the validator rejecting hostile input
(the kind of thing to run live in a demo/viva):

```bash
# 1. A genuine photo — accepted
curl -X POST http://localhost:3000/api/complaints \
  -F "category=Broken streetlight" -F "location=Gandhipuram" \
  -F "description=Streetlight out for a week" \
  -F "photo=@real-photo.jpg;type=image/jpeg"

# 2. A PHP payload renamed to .jpg with a spoofed Content-Type — rejected
printf '<?php system($_GET["c"]); ?>' > fake-shell.jpg
curl -X POST http://localhost:3000/api/complaints \
  -F "category=Other" -F "location=Test" -F "description=test" \
  -F "photo=@fake-shell.jpg;type=image/jpeg"
# -> 400 { "error": "The uploaded file does not look like a genuine JPG, PNG, or WEBP image." }

# 3. A real JPG with a deliberately mismatched declared type — rejected
curl -X POST http://localhost:3000/api/complaints \
  -F "category=Other" -F "location=Test" -F "description=test" \
  -F "photo=@real-photo.jpg;type=image/png;filename=real-photo.png"
# -> 400 { "error": "Declared file type does not match file contents." }

# 4. An oversized file — rejected
head -c 6000000 /dev/urandom > big.jpg
curl -X POST http://localhost:3000/api/complaints \
  -F "category=Other" -F "location=Test" -F "description=test" \
  -F "photo=@big.jpg;type=image/jpeg"
# -> 400 { "error": "File too large" }
```

Then inspect `uploads/` — every stored file has a random UUID name with
no trace of the client's original filename, and `data/complaints.json`
confirms no original filename was ever persisted either.

---

## 5. Project structure

```
civicsparkers/
├── server.js                    # Express app, helmet, error handling
├── routes/complaints.js         # POST /api/complaints, GET /uploads/:id
├── middleware/uploadValidator.js  # ← the security control (read this first)
├── data/store.js                # tiny JSON-file store for complaint records
├── public/                      # frontend: index.html, styles.css, app.js
└── uploads/                     # sanitized photos live here (not web-servable directly)
```

## 6. Idea attribution

Idea and problem statement adapted from the "CivicSparkers" team entry
(Strong Institutions track) in the Tech for Good 2026 hackathon mentor
briefing: reporting a civic issue like a broken streetlight with a photo,
description, and location.
