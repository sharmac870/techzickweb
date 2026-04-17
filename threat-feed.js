/* ============================================================
   TECHZICK — AI Sentinel Live Threat Feed
   Fetches CISA KEV every hour, merges with curated static
   threats, and auto-renders the blog feed + attack tracker.
   No build step. No backend. Pure client-side.
   ============================================================ */

const TechzickFeed = (() => {

  const KEV_URL  = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
  const CACHE_KEY = 'tz_kev_v2';
  const CACHE_TTL = 60 * 60 * 1000;        // 1 hour
  const SIX_MO_MS = 183 * 24 * 60 * 60 * 1000;
  const ACTIVE_MS =  30 * 24 * 60 * 60 * 1000;

  // ── Cache ─────────────────────────────────────────────────
  function readCacheFull() {
    try {
      const raw = localStorage.getItem(CACHE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  }

  function readCache() {
    const full = readCacheFull();
    if (!full) return null;
    return (Date.now() - full.ts < CACHE_TTL) ? full.data : null;
  }

  function writeCache(data) {
    try {
      localStorage.setItem(CACHE_KEY, JSON.stringify({ ts: Date.now(), data }));
    } catch {}
  }

  // ── Fetch CISA KEV ────────────────────────────────────────
  async function fetchKEV() {
    const cached = readCache();
    if (cached) return cached;

    const res  = await fetch(KEV_URL);
    if (!res.ok) throw new Error(`KEV HTTP ${res.status}`);
    const json = await res.json();

    const cutoff = Date.now() - SIX_MO_MS;
    const recent = json.vulnerabilities
      .filter(v => new Date(v.dateAdded).getTime() >= cutoff)
      .sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded));

    writeCache(recent);
    return recent;
  }

  // ── KEV entry → unified threat object ────────────────────
  function kevToThreat(kev) {
    const isRansomware = kev.knownRansomwareCampaignUse === 'Known';
    const type     = isRansomware ? 'Ransomware' : 'Zero-Day';
    const severity = isRansomware ? 'CRITICAL'   : 'HIGH';
    const isActive = (Date.now() - new Date(kev.dateAdded).getTime()) < ACTIVE_MS;

    const vuln = kev.vulnerabilityName.length > 64
      ? kev.vulnerabilityName.slice(0, 62) + '…'
      : kev.vulnerabilityName;

    return {
      id:             kev.cveID.toLowerCase(),
      cveID:          kev.cveID,
      date:           kev.dateAdded,
      title:          `${kev.cveID} — ${kev.vendorProject} ${kev.product}: ${vuln}`,
      type,
      severity,
      excerpt:        kev.shortDescription,
      tags:           [kev.cveID, kev.vendorProject, kev.product.split(' ')[0]].filter(Boolean),
      isActive,
      source:         'CISA KEV',
      sourceUrl:      'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      nvdUrl:         `https://nvd.nist.gov/vuln/detail/${kev.cveID}`,
      requiredAction: kev.requiredAction,
      dueDate:        kev.dueDate,
    };
  }

  // ── Helpers ───────────────────────────────────────────────
  function typeColor(type) {
    return { Ransomware: 'purple', 'Zero-Day': 'orange', 'AI/LLM Attack': 'cyan' }[type] || '';
  }

  function typeBadgeClass(type) {
    return {
      'Ransomware':    'Ransomware',
      'Zero-Day':      'Zero-Day',
      'Nation-State':  'Nation-State',
      'Data Breach':   'Data-Breach',
      'AI/LLM Attack': 'AI-Attack',
      'Supply Chain':  'Supply-Chain',
      'Compliance':    'Compliance',
      'Regulatory':    'Compliance',
    }[type] || 'Zero-Day';
  }

  function esc(s) {
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ── Blog card HTML ────────────────────────────────────────
  function blogCardHTML(t, isFeatured) {
    const color   = typeColor(t.type);
    const catCls  = color ? `blog-category blog-category--${color}` : 'blog-category';
    const tagCls  = (isFeatured && color) ? `blog-tag blog-tag--${color}` : 'blog-tag';
    const linkCls = (isFeatured && color) ? `card-link card-link--${color}` : 'card-link';
    const dotCls  = (isFeatured && color) ? `author-dot author-dot--${color}` : 'author-dot';
    const isLive  = t.source === 'CISA KEV';
    const excerpt = t.excerpt.length > 185 ? t.excerpt.slice(0, 183) + '…' : t.excerpt;
    const href    = isLive ? esc(t.nvdUrl)    : `threat-intel.html#${t.anchor || t.id}`;
    const target  = isLive ? 'target="_blank" rel="noopener"' : '';
    const label   = isLive ? 'NVD Details'    : 'Full Details';

    const activeBadge = t.isActive
      ? `<div class="blog-breaking-badge"><span class="pulse-dot"></span><span class="mono">ACTIVE</span></div>`
      : '';

    const authorSlot = isLive
      ? `<span class="feed-source-badge mono">CISA KEV</span>`
      : `<span class="mono">AI Sentinel</span>`;

    return `
      <article class="blog-card${isFeatured ? ' blog-card--featured' : ''}">
        <div class="blog-card-top">
          <span class="${catCls}">${esc(t.type)}</span>
          <time class="blog-date mono" datetime="${esc(t.date)}">${esc(t.date)}</time>
        </div>
        ${activeBadge}
        <h3 class="blog-title">${esc(t.title)}</h3>
        <p class="blog-excerpt">${esc(excerpt)}</p>
        <div class="blog-tags">
          ${t.tags.slice(0, 4).map(tag => `<span class="${tagCls}">${esc(tag)}</span>`).join('')}
        </div>
        <div class="blog-footer">
          <div class="blog-author">
            <span class="${dotCls}"></span>
            ${authorSlot}
          </div>
          <a href="${href}" class="${linkCls}" ${target}>${label} <span aria-hidden="true">→</span></a>
        </div>
      </article>`;
  }

  // ── Tracker card HTML ─────────────────────────────────────
  function trackerCardHTML(t) {
    const statusClass = t.isActive ? 'Active' : 'Patched';
    const statusText  = t.isActive ? '● Active' : '● Patched';
    const action      = t.requiredAction || '';
    const due         = t.dueDate
      ? ` <span style="color:var(--cyan);margin-left:6px;">Due: ${esc(t.dueDate)}</span>`
      : '';

    return `
      <article class="attack-card" data-type="${esc(t.type)}" id="${esc(t.id)}">
        <div class="attack-meta">
          <span class="attack-date">${esc(t.date)}</span>
          <span class="severity-badge ${esc(t.severity)}">${esc(t.severity)}</span>
          <span class="type-badge ${typeBadgeClass(t.type)}">${esc(t.type)}</span>
          <span class="attack-status ${statusClass}">${statusText}</span>
        </div>
        <div class="attack-body">
          <h2 class="attack-title">${esc(t.title)}</h2>
          <p class="attack-summary">${esc(t.excerpt)}</p>
          <div class="attack-tags">
            ${t.tags.map(tag => `<span class="attack-tag">${esc(tag)}</span>`).join('')}
          </div>
          ${action ? `<div class="attack-impact"><strong>Required Action:</strong> ${esc(action)}${due}</div>` : ''}
        </div>
        <div class="attack-actions">
          <a class="ti-source-link" href="${esc(t.sourceUrl)}" target="_blank" rel="noopener">
            <svg viewBox="0 0 12 12" fill="none"><path d="M2 10L10 2M10 2H6M10 2v4" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
            CISA KEV
          </a>
          <a class="ti-source-link" href="${esc(t.nvdUrl)}" target="_blank" rel="noopener">
            <svg viewBox="0 0 12 12" fill="none"><path d="M2 10L10 2M10 2H6M10 2v4" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
            NVD Details
          </a>
        </div>
      </article>`;
  }

  // ── Loading skeletons ─────────────────────────────────────
  function blogSkeleton(n) {
    return Array.from({ length: n }, () => `
      <article class="blog-card skel-card" aria-hidden="true">
        <div class="skel-line" style="width:30%"></div>
        <div class="skel-line" style="width:85%;height:20px;margin-top:10px"></div>
        <div class="skel-line" style="width:60%;height:14px;margin-top:6px"></div>
        <div class="skel-line" style="width:100%;height:52px;margin-top:14px;border-radius:6px"></div>
      </article>`).join('');
  }

  function trackerSkeleton() {
    return `<div class="skel-tracker-msg">
      <span class="pulse-dot"></span>
      <span class="mono" style="font-size:.78rem;color:var(--text-dim)">
        Fetching CISA KEV live feed…
      </span>
    </div>`;
  }

  // ── Reveal animation ──────────────────────────────────────
  function animateIn(container) {
    const obs = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) { e.target.classList.add('visible'); obs.unobserve(e.target); }
      });
    }, { threshold: 0.08, rootMargin: '0px 0px -20px 0px' });

    container.querySelectorAll('.blog-card, .attack-card').forEach((el, i) => {
      el.classList.add('reveal');
      const d = i % 4;
      if (d) el.classList.add(`reveal-delay-${d}`);
      obs.observe(el);
    });
  }

  // ── Merge live + static, deduplicate by CVE ID ───────────
  function mergeThreats(live, statics) {
    const liveCVEs = new Set(live.map(t => t.cveID.toUpperCase()));
    const filtered = statics.filter(t => {
      const m = t.title.match(/CVE-\d{4}-\d+/i);
      return !m || !liveCVEs.has(m[0].toUpperCase());
    });
    return [...live, ...filtered]
      .sort((a, b) => new Date(b.date) - new Date(a.date));
  }

  // ══ BLOG INIT (index.html) ════════════════════════════════
  async function initBlog() {
    const grid    = document.getElementById('blog-grid');
    const countEl = document.getElementById('threat-count');
    if (!grid) return;

    grid.innerHTML = blogSkeleton(4);

    const statics = (typeof THREATS !== 'undefined') ? THREATS : [];
    let live = [];

    try {
      live = (await fetchKEV()).map(kevToThreat);
    } catch (err) {
      console.warn('[AI Sentinel] CISA KEV unavailable — using static data.', err);
    }

    const merged = mergeThreats(live, statics);
    const top4   = merged.slice(0, 4);

    if (top4.length === 0) {
      grid.innerHTML = '<p style="color:var(--text-dim);text-align:center;padding:32px 0;">No recent threats available.</p>';
      return;
    }

    grid.innerHTML = top4.map((t, i) => blogCardHTML(t, i === 0)).join('');
    animateIn(grid);

    if (countEl) countEl.textContent = merged.length;
  }

  // ══ TRACKER INIT (threat-intel.html) ═════════════════════
  async function initTracker() {
    const liveGrid  = document.getElementById('live-kev-grid');
    const liveCount = document.getElementById('live-kev-count');
    const lastEl    = document.getElementById('live-kev-updated');
    const lastFull  = document.getElementById('live-kev-catalog-date');
    if (!liveGrid) return;

    liveGrid.innerHTML = trackerSkeleton();

    try {
      const kev     = await fetchKEV();
      const threats = kev.map(kevToThreat);

      liveGrid.innerHTML = threats.map(trackerCardHTML).join('');
      animateIn(liveGrid);

      if (liveCount) liveCount.textContent = threats.length;

      // Show cache age
      const full = readCacheFull();
      if (lastEl && full) {
        const mins = Math.round((Date.now() - full.ts) / 60000);
        lastEl.textContent = mins < 1 ? 'just now' : `${mins}m ago`;
      }
      if (lastFull && kev.length) {
        lastFull.textContent = kev[0].dateAdded;
      }

      // Recompute stats bar after live cards are in DOM
      if (typeof computeTrackerStats === 'function') computeTrackerStats();

    } catch (err) {
      liveGrid.innerHTML = `
        <div style="padding:20px 0;color:var(--text-dim);font-size:.875rem;">
          Live feed unavailable.
          <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
             target="_blank" rel="noopener" style="color:var(--cyan);margin-left:6px;">
            View on CISA →
          </a>
        </div>`;
      console.warn('[AI Sentinel] Tracker KEV fetch failed:', err);
    }
  }

  // ── Auto-init on DOM ready ────────────────────────────────
  function init() { initBlog(); initTracker(); }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  return { refresh: init };

})();
