/* ============================================================
   TECHZICK — Main JavaScript
   ============================================================ */

/* ── Nav: scroll state ── */
const navBar = document.querySelector('.nav-bar');
window.addEventListener('scroll', () => {
  navBar?.classList.toggle('scrolled', window.scrollY > 20);
}, { passive: true });

/* ── Nav: hamburger menu ── */
const hamburger = document.getElementById('hamburger');
const navMenu   = document.getElementById('nav-menu');

if (hamburger && navMenu) {
  hamburger.addEventListener('click', () => {
    const isOpen = navMenu.classList.toggle('open');
    hamburger.classList.toggle('open', isOpen);
    hamburger.setAttribute('aria-expanded', String(isOpen));
  });
  navMenu.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', () => {
      navMenu.classList.remove('open');
      hamburger.classList.remove('open');
      hamburger.setAttribute('aria-expanded', 'false');
    });
  });
}

/* ── Footer year ── */
const yearEl = document.getElementById('year');
if (yearEl) yearEl.textContent = String(new Date().getFullYear());

/* ── Hero: particle canvas ── */
(function initCanvas() {
  const canvas = document.getElementById('heroCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let W, H, particles;

  function resize() {
    W = canvas.width  = canvas.offsetWidth;
    H = canvas.height = canvas.offsetHeight;
  }

  function makeParticle() {
    return {
      x:  Math.random() * W,
      y:  Math.random() * H,
      r:  Math.random() * 1.5 + 0.3,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      a:  Math.random(),
    };
  }

  function init() {
    resize();
    particles = Array.from({ length: 90 }, makeParticle);
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);

    // Draw connecting lines
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 140) {
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(0, 212, 255, ${0.06 * (1 - dist / 140)})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }

    // Draw particles
    particles.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0, 212, 255, ${p.a * 0.5})`;
      ctx.fill();

      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > W) p.vx *= -1;
      if (p.y < 0 || p.y > H) p.vy *= -1;
    });

    requestAnimationFrame(draw);
  }

  init();
  draw();
  window.addEventListener('resize', resize, { passive: true });
})();

/* ── Hero: typed text animation ── */
(function initTyped() {
  const el = document.getElementById('typed-text');
  if (!el) return;

  const phrases = [
    'Built for the Cloud.',
    'GRC on Autopilot.',
    'Full Stack. Zero Trust.',
    'Data Security at Scale.',
    'Audit-Ready. Always.',
  ];

  let phraseIdx = 0;
  let charIdx   = 0;
  let deleting  = false;
  let paused    = false;

  // Create cursor element
  const cursor = document.createElement('span');
  cursor.className = 'cursor';
  el.parentNode.insertBefore(cursor, el.nextSibling);

  function tick() {
    const current = phrases[phraseIdx];

    if (paused) {
      paused = false;
      deleting = true;
      setTimeout(tick, 60);
      return;
    }

    if (!deleting) {
      el.textContent = current.slice(0, charIdx + 1);
      charIdx++;
      if (charIdx === current.length) {
        paused = true;
        setTimeout(tick, 2000);
        return;
      }
      setTimeout(tick, 65);
    } else {
      el.textContent = current.slice(0, charIdx - 1);
      charIdx--;
      if (charIdx === 0) {
        deleting = false;
        phraseIdx = (phraseIdx + 1) % phrases.length;
        setTimeout(tick, 400);
        return;
      }
      setTimeout(tick, 35);
    }
  }

  setTimeout(tick, 800);
})();

/* ── Stats counter ── */
function animateCounter(el, target, duration) {
  let start = null;
  function step(ts) {
    if (!start) start = ts;
    const progress = Math.min((ts - start) / duration, 1);
    const ease = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(ease * target);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/* ── Scroll reveal + stat counters ── */
(function initReveal() {
  const revealEls = document.querySelectorAll('.reveal');
  const statEls   = document.querySelectorAll('.stat-num[data-target]');
  const counted   = new WeakSet();

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.15, rootMargin: '0px 0px -40px 0px' });

  revealEls.forEach(el => observer.observe(el));

  // Stat counter observer
  const statObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting && !counted.has(entry.target)) {
        counted.add(entry.target);
        const target = parseInt(entry.target.dataset.target, 10);
        animateCounter(entry.target, target, 1800);
        statObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.5 });

  statEls.forEach(el => statObserver.observe(el));

  // Auto-add reveal class to section elements
  const autoReveal = document.querySelectorAll(
    '.service-card, .grc-step, .differentiator, .tech-cat, .contact-item, .blog-card'
  );
  autoReveal.forEach((el, i) => {
    el.classList.add('reveal');
    const delay = (i % 4);
    if (delay) el.classList.add(`reveal-delay-${delay}`);
    observer.observe(el);
  });
})();

/* ── Contact form ── */
const contactForm = document.getElementById('contact-form');
if (contactForm) {
  contactForm.addEventListener('submit', (e) => {
    e.preventDefault();

    const data     = new FormData(contactForm);
    const name     = (data.get('name')    || '').toString().trim();
    const email    = (data.get('email')   || '').toString().trim();
    const company  = (data.get('company') || '').toString().trim();
    const service  = (data.get('service') || '').toString().trim();
    const message  = (data.get('message') || '').toString().trim();

    const subject = encodeURIComponent(`[Techzick] Inquiry from ${name || 'Prospect'} — ${company || 'Unknown Co.'}`);
    const body    = encodeURIComponent(
      `Name: ${name}\nEmail: ${email}\nCompany: ${company}\nService: ${service || 'Not specified'}\n\nMessage:\n${message}`
    );

    window.location.href = `mailto:Team@techzick.com?subject=${subject}&body=${body}`;
  });
}
