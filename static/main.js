const SEV_ICONS = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', safe: '✅' };
const TYPE_ICONS = {
  backdoor: '🚪', malware: '💀', sabotage: '💣', typosquat: '🎭',
  vulnerability: '⚠️', new_package: '🆕', single_maintainer: '👤',
  high_velocity: '🚀', not_found: '❓', 'dependency confusion': '🔗'
};

// ── Escaping ───────────────────────────────────────────────────────────────
// Tool listings, package names and detection descriptions are user-supplied at
// this point, so every value interpolated into markup goes through esc() and
// every href through safeUrl(). Never build HTML with raw interpolation.
function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safeUrl(url) {
  if (!url) return '';
  try {
    const parsed = new URL(url, window.location.origin);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') ? parsed.href : '';
  } catch {
    return '';
  }
}

function csrfHeaders() {
  const token = document.querySelector('meta[name="csrf-token"]')?.content;
  return token ? { 'X-CSRF-Token': token } : {};
}

const CSRF = csrfHeaders();

// ── Tools directory ─────────────────────────────────────────────────────────
function toolMonogram(name) {
  return esc((name || '?').trim().charAt(0).toUpperCase());
}

// The tile a logo sits on is an explicit property of the entry, not something
// guessed from the file extension: a white-on-transparent mark needs a dark
// tile, a dark monochrome mark needs the default light one. `logo_tile` lives in
// data/detections/tools.json and defaults to "light".
function logoTileClass(logo, tile) {
  return tile === 'dark' ? ' tool-logo-dark' : '';
}

function toolLogo(t) {
  const src = safeUrl(t.logo);
  if (!src) return `<div class="tool-logo tool-logo-mono" aria-hidden="true">${toolMonogram(t.name)}</div>`;
  return `<div class="tool-logo${logoTileClass(t.logo, t.logo_tile)}"><img src="${esc(src)}" alt="" loading="lazy" onerror="this.parentNode.className='tool-logo tool-logo-mono';this.remove()"></div>`;
}

function renderToolsInto(el, tools) {
  if (!tools.length) {
    el.innerHTML = `<div class="empty-state"><div class="empty-icon">🧰</div>
      <div class="empty-title">No listings yet</div>
      <div class="empty-sub">The directory is empty.</div></div>`;
    return;
  }
  el.innerHTML = tools.map(t => {
    const href = safeUrl(t.url);
    const tags = [
      t.category ? `<span class="tag-mono">${esc(t.category)}</span>` : '',
      t.pricing_model ? `<span class="tag-mono">${esc(t.pricing_model)}</span>` : ''
    ].filter(Boolean).join('');
    return `
    <div class="tool-card">
      <div class="tool-top">
        ${toolLogo(t)}
        <div class="tool-headings">
          <span class="tool-type ${esc(t.cls)}">${esc(t.type)}</span>
          ${t.sponsored ? '<span class="tool-sponsored">Sponsored</span>' : ''}
        </div>
      </div>
      <div class="tool-name">${esc(t.name)}</div>
      <div class="tool-desc">${esc(t.desc)}</div>
      ${tags ? `<div class="tool-tags">${tags}</div>` : ''}
      ${href ? `<a class="tool-link" href="${esc(href)}" target="_blank" rel="noopener nofollow">Learn more →</a>` : ''}
    </div>`;
  }).join('') + toolsCtaHtml();
}

// The "list your tool" card is rendered in the same pass as the directory so it
// always lands last, and always appears even when the directory is empty.
function toolsCtaHtml() {
  const cta = document.getElementById('tools-cta-data');
  const price = cta?.dataset.price || '';
  const days = cta?.dataset.days || '30';
  return `
  <div class="tool-card tool-card-cta">
    <div class="tool-cta-plus" aria-hidden="true">+</div>
    <div class="tool-name">Have a developer tool?</div>
    <div class="tool-desc">Get your product in front of developers using PkgPeek.
      ${price ? `<br><strong>${esc(price)}</strong> for a ${esc(days)}-day listing.` : ''}
    </div>
    <a class="tool-link" href="/submit-tool">List your tool →</a>
  </div>`;
}

async function loadAndRenderTools(id) {
  const el = document.getElementById(id);
  if (!el) return;
  try {
    const res = await fetch('/api/tools');
    const tools = await res.json();
    renderToolsInto(el, tools);
  } catch (e) {
    console.error('Failed to load tools', e);
    el.innerHTML = `<div class="empty-state"><div class="empty-icon">📡</div>
      <div class="empty-title">Could not load the directory</div>
      <div class="empty-sub">Check your connection and reload.</div></div>`;
  }
}

// ── Stats ──────────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();
    document.getElementById('stat-known').textContent = d.total_known_malicious.toLocaleString();
    document.getElementById('stat-critical').textContent = d.critical.toLocaleString();
    document.getElementById('stat-targets').textContent = d.typosquat_targets.toLocaleString();
  } catch {
    /* stats are decorative; a failure should not break the page */
  }
}

// ── Tabs ───────────────────────────────────────────────────────────────────
function showTab(name, btn) {
  ['flagged', 'direct', 'peer'].forEach(t => {
    const el = document.getElementById(`tab-${t}`);
    if (el) el.style.display = t === name ? 'block' : 'none';
  });
  document.querySelectorAll('.t-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
}

// ── Example ────────────────────────────────────────────────────────────────
const EXAMPLE_PKG = {
  name: "demo-app",
  version: "1.0.0",
  dependencies: {
    "express": "^4.18.2",
    "lodash": "^4.17.15",
    "axios": "^0.21.0",
    "ua-parser-js": "^0.7.29",
    "colors": "^1.4.44-liberty-2",
    "event-stream": "^3.3.6",
    "mongoose": "^7.0.0",
    "jsonwebtoken": "^8.5.1",
    "mongose": "^1.0.0"
  },
  devDependencies: {
    "jest": "^29.0.0",
    "eslint": "^8.0.0"
  }
};

function updatePrismHighlight() {
  const input = document.getElementById('pkg-input').value;
  const highlightEl = document.getElementById('pkg-highlight');
  let escaped = esc(input);
  if (escaped[escaped.length - 1] === '\n') escaped += ' ';
  highlightEl.innerHTML = escaped;
  if (window.Prism) Prism.highlightElement(highlightEl);
}

function loadExample() {
  const ta = document.getElementById('pkg-input');
  ta.value = JSON.stringify(EXAMPLE_PKG, null, 2);
  updatePrismHighlight();
}

async function loadExampleAndScan() {
  loadExample();
  document.getElementById('scanner').scrollIntoView({ behavior: 'smooth' });
  await new Promise(r => setTimeout(r, 600));
  startScan();
}

function clearAll() {
  const ta = document.getElementById('pkg-input');
  ta.value = '';
  updatePrismHighlight();
  document.getElementById('results-feed').style.display = 'none';
  document.getElementById('empty-feed').style.display = 'block';
  hideErr();
}

// ── Loading animation ──────────────────────────────────────────────────────
let stepTimer;
const STEPS = ['lstep-db', 'lstep-osv', 'lstep-typo', 'lstep-npm'];
const MSGS = [
  'Checking PkgPeek detections…',
  'Querying OSV advisories…',
  'Detecting typosquats…',
  'Fetching npm metadata…'
];

function startSteps() {
  STEPS.forEach(s => document.getElementById(s).className = 'lstep');
  let i = 0;
  stepTimer = setInterval(() => {
    if (i > 0) document.getElementById(STEPS[i - 1]).className = 'lstep done';
    if (i < STEPS.length) {
      document.getElementById(STEPS[i]).className = 'lstep active';
      document.getElementById('loader-msg').textContent = MSGS[i];
      i++;
    } else clearInterval(stepTimer);
  }, 850);
}

function stopSteps() {
  clearInterval(stepTimer);
  STEPS.forEach(s => document.getElementById(s).className = 'lstep');
}

// ── Scan ───────────────────────────────────────────────────────────────────
async function startScan() {
  const input = document.getElementById('pkg-input').value.trim();
  if (!input) { showErr('Please paste your package.json content.'); return; }

  hideErr();
  document.getElementById('empty-feed').style.display = 'none';
  document.getElementById('results-feed').style.display = 'none';
  document.getElementById('loading').classList.add('visible');
  document.getElementById('scan-btn').disabled = true;
  startSteps();

  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...CSRF },
      body: JSON.stringify({ packageJson: input })
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Scan failed');
    renderResults(data);
  } catch (e) {
    showErr(e.message);
    document.getElementById('empty-feed').style.display = 'block';
  } finally {
    document.getElementById('loading').classList.remove('visible');
    document.getElementById('scan-btn').disabled = false;
    stopSteps();
  }
}

function showErr(msg) {
  const el = document.getElementById('error-strip');
  el.textContent = '⚠ ' + msg;
  el.classList.add('visible');
}

function hideErr() { document.getElementById('error-strip').classList.remove('visible'); }

// ── Render results ─────────────────────────────────────────────────────────
function renderResults(data) {
  const { summary, direct, indirect } = data;
  const allFlagged = [...direct, ...indirect].filter(p => !p.safe);

  const score = summary.risk_score;
  const riskLabel = score === 0 ? 'All Clear' : score < 20 ? 'Low Risk' : score < 50 ? 'Moderate Risk' : score < 80 ? 'High Risk' : 'Critical Risk';
  const riskColor = score === 0 ? 'var(--green)' : score < 20 ? '#60c0a0' : score < 50 ? 'var(--yellow)' : score < 80 ? 'var(--orange)' : 'var(--red)';

  document.getElementById('rs-num').textContent = score;
  document.getElementById('rs-num').style.color = riskColor;
  document.getElementById('rs-title').textContent = riskLabel;
  document.getElementById('rs-meta').textContent = `${summary.flagged} of ${summary.total_packages} packages flagged`;

  const tags = document.getElementById('sev-tags');
  tags.innerHTML = '';
  const bySev = summary.by_severity;
  ['critical', 'high', 'medium', 'low'].forEach(s => {
    if (bySev[s]) tags.innerHTML += `<span class="sev-tag st-${s}">${SEV_ICONS[s]} ${bySev[s]} ${esc(s)}</span>`;
  });
  if (summary.safe) tags.innerHTML += `<span class="sev-tag st-safe">✅ ${summary.safe} safe</span>`;

  document.getElementById('tc-flagged').textContent = allFlagged.length;
  document.getElementById('tc-direct').textContent = direct.length;
  document.getElementById('tc-peer').textContent = indirect.length;

  buildList('list-flagged', allFlagged.length ? allFlagged : null, true);
  buildList('list-direct', direct);
  buildList('list-peer', indirect);

  document.getElementById('results-feed').style.display = 'block';
  showTab('flagged', document.querySelector('.t-btn'));
}

function buildList(id, pkgs, isFlagged) {
  const el = document.getElementById(id);
  if (!el) return;
  if (!pkgs || pkgs.length === 0) {
    el.innerHTML = `<div class="empty-state">
      <div class="empty-icon">${isFlagged ? '✅' : '📦'}</div>
      <div class="empty-title">${isFlagged ? 'No threats found' : 'Nothing here'}</div>
      <div class="empty-sub">${isFlagged ? 'All scanned packages appear clean.' : 'No packages in this category.'}</div>
    </div>`;
    return;
  }
  el.innerHTML = pkgs.map((p, i) => pkgCard(p, i)).join('');
}

function copySuggestion(cmd, btn) {
  navigator.clipboard.writeText(cmd).then(() => {
    const orig = btn.innerHTML;
    btn.innerHTML = '✓ Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.innerHTML = orig; btn.classList.remove('copied'); }, 2000);
  }).catch(() => {});
}

function buildSuggestionHtml(sugg) {
  if (!sugg) return '';
  const href = safeUrl(sugg.url);
  if (sugg.warning) {
    const ref = href ? `<a class="sugg-ref" href="${esc(href)}" target="_blank" rel="noopener">npm →</a>` : '';
    return `<div class="suggestion-bar suggestion-warn"><span class="sugg-warn-icon">⚠</span><span class="sugg-warn-text">${esc(sugg.reason)}</span>${ref}</div>`;
  }
  const label = `${sugg.name}${sugg.version ? '@' + sugg.version : ''}`;
  const cmd = sugg.install || `npm install ${sugg.name}`;
  // The command goes into an onclick attribute, so it is attribute-escaped by esc()
  // rather than interpolated raw.
  return `<div class="suggestion-bar">
    <span class="sugg-label">Use instead:</span>
    <button class="sugg-chip" onclick="copySuggestion(this.dataset.cmd, this)" data-cmd="${esc(cmd)}" title="Click to copy">📦 ${esc(label)}</button>
    <span class="sugg-reason">${esc(sugg.reason)}</span>
    ${href ? `<a class="sugg-ref" href="${esc(href)}" target="_blank" rel="noopener">npm →</a>` : ''}
  </div>`;
}

// Item 4: make every detection auditable. Source / evidence / detected date /
// affected versions, straight from the provenance the scanner attached.
function provenanceHtml(p) {
  if (!p) return '';
  const rows = [];
  const add = (label, value, url) => {
    if (!value) return;
    const body = url
      ? `<a href="${esc(safeUrl(url))}" target="_blank" rel="noopener">${esc(value)}</a>`
      : esc(value);
    rows.push(`<div class="prov-row"><span class="prov-key">${esc(label)}</span><span class="prov-val">${body}</span></div>`);
  };
  add('Source', p.source, null);
  add('Evidence', p.evidence, p.evidence_url);
  add('Advisory', p.advisory, p.evidence_url);
  add('Detected', p.detected, null);
  add('Affected versions', p.affected_versions, null);
  if (p.contributor) add('Reported by', p.contributor, null);
  if (!rows.length) return '';
  return `<div class="prov">${rows.join('')}</div>`;
}

function reportLinks(pkg) {
  const name = encodeURIComponent(pkg.name);
  const ver = encodeURIComponent(pkg.version || '');
  const detection = encodeURIComponent(pkg.flags?.[0]?.type || '');
  return `<div class="report-bar">
    <span class="report-lead">Detection looks wrong?</span>
    <a class="report-link" href="/report?package=${name}&version=${ver}&kind=correction&detection=${detection}">This looks wrong</a>
    <a class="report-link report-link-alt" href="/report?package=${name}&version=${ver}">Report this package</a>
  </div>`;
}

function pkgCard(pkg, idx) {
  const sev = pkg.max_severity || 'safe';
  const flags = pkg.flags || [];
  const cardId = `pc-${idx}-${pkg.name.replace(/[^a-z0-9]/gi, '')}`;

  const flagsHtml = flags.map(f => {
    const ref = safeUrl(f.reference);
    return `
    <div class="flag-row">
      <div class="flag-icon-box fib-${esc(f.severity)}">${TYPE_ICONS[f.type] || '⚠️'}</div>
      <div class="flag-content">
        <div class="flag-title-row">
          <span class="flag-title">${esc(f.title)}</span>
          <span class="flag-sev fs-${esc(f.severity)}">${esc((f.severity || '').toUpperCase())}</span>
        </div>
        <div class="flag-desc">${esc(f.description || '')}</div>
        ${provenanceHtml(f.provenance)}
        <div class="flag-foot">
          <span class="tag-mono">${esc(f.source)}</span>
          ${f.cve && f.cve !== 'N/A' ? `<span class="tag-mono">${esc(f.cve)}</span>` : ''}
          ${ref ? `<a class="tag-link" href="${esc(ref)}" target="_blank" rel="noopener">View advisory →</a>` : ''}
        </div>
      </div>
    </div>`;
  }).join('');

  return `
  <div class="pkg-card sev-${esc(sev)}" id="${esc(cardId)}">
    <div class="pkg-head" onclick="toggleCard(this)">
      <div class="pkg-icon pi-${esc(sev)}">${SEV_ICONS[sev] || '⚠️'}</div>
      <span class="pkg-name">${esc(pkg.name)}</span>
      <span class="pkg-ver">${esc(pkg.version || '*')}</span>
      <div class="pkg-right">
        ${flags.length ? `<span class="chip-sm c-issues">${flags.length} issue${flags.length > 1 ? 's' : ''}</span>` : '<span class="chip-sm c-clean">clean</span>'}
        <span class="chip-sm ${pkg.is_direct ? 'c-direct' : 'c-peer'}">${pkg.is_direct ? 'direct' : 'peer'}</span>
        <span class="chevron">▾</span>
      </div>
    </div>
    ${buildSuggestionHtml(pkg.suggestion)}
    ${flags.length ? `<div class="flag-list">${flagsHtml}</div>` : ''}
    ${reportLinks(pkg)}
  </div>`;
}

function toggleCard(head) {
  head.closest('.pkg-card').classList.toggle('open');
}

document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') startScan();
});

document.addEventListener('DOMContentLoaded', () => {
  const ta = document.getElementById('pkg-input');
  if (ta) {
    ta.addEventListener('input', updatePrismHighlight);
    ta.addEventListener('scroll', () => {
      document.getElementById('pkg-highlight-pre').scrollTop = ta.scrollTop;
      document.getElementById('pkg-highlight-pre').scrollLeft = ta.scrollLeft;
    });
  }
  loadStats();
  loadAndRenderTools('tools-main');
});

// ── Dev Modal ──────────────────────────────────────────────────────────────
function openDevModal() {
  const modal = document.getElementById('modal-dev');
  if (!modal) return;
  modal.style.display = 'flex';
  setTimeout(() => modal.classList.add('active'), 10);
}

function closeDevModal() {
  const modal = document.getElementById('modal-dev');
  if (!modal) return;
  modal.classList.remove('active');
  setTimeout(() => { modal.style.display = 'none'; }, 200);
}

document.addEventListener('click', e => {
  const modal = document.getElementById('modal-dev');
  if (modal && e.target === modal) closeDevModal();
});

// ── Service Worker for PWA ────────────────────────────────────────────────
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  });
}

// ── PWA Custom Install Button ─────────────────────────────────────────────
let deferredPrompt;
const installBtn = document.getElementById('install-pwa-btn');

window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault();
  deferredPrompt = e;
  if (installBtn) installBtn.style.display = 'inline-block';
});

if (installBtn) {
  installBtn.addEventListener('click', async () => {
    if (!deferredPrompt) return;
    deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;
    if (outcome === 'accepted') installBtn.style.display = 'none';
    deferredPrompt = null;
  });
}
