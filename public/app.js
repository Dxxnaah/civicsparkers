// public/app.js
(() => {
  const form = document.getElementById('complaint-form');
  const status = document.getElementById('form-status');
  const dropzone = document.getElementById('dropzone');
  const photoInput = document.getElementById('photo');
  const hint = document.getElementById('dropzone-hint');
  const preview = document.getElementById('photo-preview');
  const grid = document.getElementById('ticket-grid');
  const emptyMsg = document.getElementById('log-empty');
  const submitBtn = form.querySelector('.submit-btn');

  const MAX_BYTES = 5 * 1024 * 1024;
  const ALLOWED_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp']);

  // --- dropzone interactions (client-side UX only; the server re-checks
  //     everything from scratch and never trusts these client checks) ---
  function showPreview(file) {
    const url = URL.createObjectURL(file);
    preview.src = url;
    preview.hidden = false;
    hint.textContent = `${file.name} — ${(file.size / 1024).toFixed(0)} KB`;
  }

  photoInput.addEventListener('change', () => {
    const file = photoInput.files[0];
    if (!file) return;
    if (!ALLOWED_TYPES.has(file.type)) {
      setStatus('That file type will be rejected by the server — please choose a JPG, PNG, or WEBP.', 'error');
      return;
    }
    if (file.size > MAX_BYTES) {
      setStatus('That file is over the 5 MB limit and will be rejected — please choose a smaller photo.', 'error');
      return;
    }
    setStatus('', null);
    showPreview(file);
  });

  ['dragover', 'dragenter'].forEach((evt) =>
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add('is-active');
    })
  );
  ['dragleave', 'drop'].forEach((evt) =>
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.remove('is-active');
    })
  );
  dropzone.addEventListener('drop', (e) => {
    const file = e.dataTransfer.files[0];
    if (file) {
      photoInput.files = e.dataTransfer.files;
      photoInput.dispatchEvent(new Event('change'));
    }
  });

  function setStatus(message, tone) {
    status.textContent = message;
    if (tone) status.dataset.tone = tone;
    else delete status.dataset.tone;
  }

  // --- submit ---
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    setStatus('Submitting…', null);
    submitBtn.disabled = true;

    try {
      const formData = new FormData(form);
      const res = await fetch('/api/complaints', { method: 'POST', body: formData });
      const data = await res.json();

      if (!res.ok) {
        setStatus(data.error || 'Something went wrong. Please try again.', 'error');
        return;
      }

      setStatus(`Filed as case ${data.id.slice(0, 8)} — thank you.`, 'ok');
      form.reset();
      preview.hidden = true;
      hint.textContent = 'Drop a photo here, or click to choose one — JPG, PNG or WEBP, up to 5 MB.';
      prependCase(data);
      emptyMsg.hidden = true;
    } catch (err) {
      setStatus('Network error — please try again.', 'error');
    } finally {
      submitBtn.disabled = false;
    }
  });

  // --- case log rendering ---
  // Every piece of user-supplied text is set via textContent, never
  // innerHTML, so a malicious description can never execute as markup —
  // this is the XSS-safe counterpart to the server-side upload checks.
  function buildTicket(c) {
    const el = document.createElement('article');
    el.className = 'ticket';

    const img = document.createElement('img');
    img.className = 'ticket__photo';
    img.src = c.photoUrl;
    img.alt = `Photo submitted for case ${c.id.slice(0, 8)}`;
    img.loading = 'lazy';

    const body = document.createElement('div');
    body.className = 'ticket__body';

    const meta = document.createElement('div');
    meta.className = 'ticket__meta';

    const idEl = document.createElement('span');
    idEl.className = 'ticket__id';
    idEl.textContent = `CASE ${c.id.slice(0, 8).toUpperCase()}`;

    const stamp = document.createElement('span');
    stamp.className = 'stamp';
    stamp.dataset.status = c.status;
    stamp.textContent = c.status;

    meta.append(idEl, stamp);

    const category = document.createElement('h3');
    category.className = 'ticket__category';
    category.textContent = c.category;

    const desc = document.createElement('p');
    desc.className = 'ticket__desc';
    desc.textContent = c.description;

    const foot = document.createElement('div');
    foot.className = 'ticket__foot';

    const loc = document.createElement('span');
    loc.textContent = c.location;

    const who = document.createElement('span');
    who.textContent = c.reporterName;

    foot.append(loc, who);
    body.append(meta, category, desc, foot);
    el.append(img, body);
    return el;
  }

  function prependCase(c) {
    grid.prepend(buildTicket(c));
  }

  async function loadCases() {
    try {
      const res = await fetch('/api/complaints');
      const cases = await res.json();
      grid.innerHTML = '';
      if (!cases.length) {
        emptyMsg.hidden = false;
        return;
      }
      emptyMsg.hidden = true;
      cases.forEach((c) => grid.append(buildTicket(c)));
    } catch (err) {
      emptyMsg.hidden = false;
      emptyMsg.textContent = 'Could not load the case log — refresh to try again.';
    }
  }

  loadCases();
})();
