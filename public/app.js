const form = document.getElementById('checkForm');
const urlInput = document.getElementById('urlInput');
const resultCard = document.getElementById('resultCard');
const verdictBadge = document.getElementById('verdictBadge');
const normalizedUrl = document.getElementById('normalizedUrl');
const scoreText = document.getElementById('scoreText');
const checksEl = document.getElementById('checks');
const rawEl = document.getElementById('raw');
const historyList = document.getElementById('historyList');
const exampleBtns = document.querySelectorAll('.example');
const copyBtn = document.getElementById('copyBtn');
const shareBtn = document.getElementById('shareBtn');

function renderResult(data) {
  resultCard.classList.remove('hidden');
  normalizedUrl.textContent = data.normalized;
  scoreText.textContent = `Score: ${data.score}`;
  verdictBadge.textContent = data.verdict;
  verdictBadge.className = 'badge';
  if (data.verdict === 'Safe') verdictBadge.classList.add('safe');
  else if (data.verdict === 'Suspicious') verdictBadge.classList.add('suspicious');
  else verdictBadge.classList.add('danger');

  checksEl.innerHTML = '';
  (data.checks || []).forEach(c => {
    const div = document.createElement('div');
    div.className = 'check';
    if (c.ok) div.classList.add('ok');
    else if (c.weight >= 3) div.classList.add('bad');
    else div.classList.add('warn');

    div.innerHTML = `
      <div>
        <div class="name">${c.name}</div>
        <div class="msg">${c.message}</div>
      </div>
      <div style="text-align:right;color:var(--muted);font-size:13px">
        ${c.ok ? 'OK' : 'Flag'} ${c.ok ? '' : `(+${c.weight})`}
      </div>
    `;
    checksEl.appendChild(div);
  });

  rawEl.textContent = JSON.stringify(data, null, 2);
  saveHistory(data);
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();
  if (!url) return;
  resultCard.classList.add('hidden');
  try {
    const res = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    if (!res.ok) {
      const err = await res.json();
      alert(err.error || 'Error checking URL');
      return;
    }
    const data = await res.json();
    renderResult(data);
  } catch (err) {
    alert('Network error');
  }
});

exampleBtns.forEach(b => b.addEventListener('click', () => {
  urlInput.value = b.textContent;
  urlInput.focus();
}));

// History in localStorage
function saveHistory(data) {
  const key = 'url-checker-history';
  const raw = JSON.parse(localStorage.getItem(key) || '[]');
  raw.unshift({ time: Date.now(), input: data.input, normalized: data.normalized, verdict: data.verdict, score: data.score });
  localStorage.setItem(key, JSON.stringify(raw.slice(0, 20)));
  renderHistory();
}

function renderHistory() {
  const key = 'url-checker-history';
  const raw = JSON.parse(localStorage.getItem(key) || '[]');
  historyList.innerHTML = '';
  raw.forEach(entry => {
    const li = document.createElement('li');
    li.innerHTML = `<div style="max-width:180px;overflow:hidden;text-overflow:ellipsis">${entry.normalized}</div><div style="text-align:right"><div style="font-weight:600">${entry.verdict}</div><div style="color:var(--muted);font-size:12px">Score ${entry.score}</div></div>`;
    li.addEventListener('click', () => {
      urlInput.value = entry.input;
    });
    historyList.appendChild(li);
  });
}
renderHistory();

copyBtn.addEventListener('click', async () => {
  const txt = normalizedUrl.textContent;
  try {
    await navigator.clipboard.writeText(txt);
    copyBtn.textContent = 'Copied';
    setTimeout(()=> copyBtn.textContent = 'Copy', 1500);
  } catch(e) {
    alert('Copy failed');
  }
});

shareBtn.addEventListener('click', async () => {
  const txt = `${normalizedUrl.textContent} — ${verdictBadge.textContent}`;
  if (navigator.share) {
    try {
      await navigator.share({ title: 'URL Check', text: txt });
    } catch (e) {}
  } else {
    alert('Share not supported in this browser; try copy instead.');
  }
});
