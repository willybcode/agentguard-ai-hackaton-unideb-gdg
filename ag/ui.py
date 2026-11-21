"""The demo web page, served as one string.

This is a *demo harness*, deliberately separate from the library. It exists to
show what the policy does, not to be embedded anywhere. The product surface is
``ag.guard`` (Python), ``python -m ag`` (CLI) and the optional HTTP wrapper.
"""

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentGuard — policy gate for LLM tool calls</title>
<style>
  :root {
    --bg:#0a0e13; --bg2:#0e141b; --panel:#131a22; --panel2:#182029;
    --line:#243040; --line2:#2f3d4f; --ink:#e6edf3; --dim:#8b9bb0; --dim2:#5d6b7d;
    --red:#ff5d5d; --green:#3fd68a; --amber:#ffc857; --blue:#5ab0ff; --violet:#a78bfa;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    --radius:10px;
  }
  * { box-sizing: border-box; }
  body {
    margin:0; background:var(--bg); color:var(--ink);
    font:15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    -webkit-font-smoothing:antialiased;
  }
  a { color:var(--blue); text-decoration:none; }
  a:hover { text-decoration:underline; }

  /* ---------- header ---------- */
  header {
    position:sticky; top:0; z-index:20;
    background:rgba(10,14,19,.92); backdrop-filter:blur(10px);
    border-bottom:1px solid var(--line); padding:14px 26px;
  }
  .head-row { display:flex; align-items:center; gap:16px; flex-wrap:wrap; }
  .brand { display:flex; align-items:baseline; gap:9px; }
  .brand b { font-size:17px; letter-spacing:-.2px; }
  .brand span { color:var(--dim); font-size:12.5px; }
  .spacer { flex:1; }
  .chips { display:flex; gap:6px; flex-wrap:wrap; }
  .chip {
    font-family:var(--mono); font-size:11px; padding:3px 9px; border-radius:999px;
    border:1px solid var(--line); color:var(--dim); background:var(--bg2);
  }
  .chip.on { color:var(--green); border-color:#1d4a33; background:#0d1f17; }
  .chip.warn { color:var(--amber); border-color:#4a3f1d; background:#1f1b0d; }
  .chip.blue { color:var(--blue); border-color:#1e3a5f; background:#101c2b; }

  /* ---------- layout ---------- */
  main { max-width:1520px; margin:0 auto; padding:22px 26px 70px; }
  .cols { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1.05fr); gap:20px; }
  @media (max-width:1080px) { .cols { grid-template-columns:1fr; } }

  .card {
    background:var(--panel); border:1px solid var(--line);
    border-radius:var(--radius); overflow:hidden;
  }
  .card > h2 {
    margin:0; padding:12px 16px; font-size:12px; letter-spacing:.9px;
    text-transform:uppercase; color:var(--dim); font-weight:700;
    border-bottom:1px solid var(--line); background:var(--bg2);
    display:flex; align-items:center; gap:8px;
  }
  .card > h2 .rt { margin-left:auto; text-transform:none; letter-spacing:0; font-weight:500; }
  .body { padding:16px; }

  /* ---------- composer ---------- */
  textarea {
    width:100%; min-height:76px; resize:vertical; padding:12px 14px;
    border-radius:9px; border:1px solid var(--line); background:var(--bg2);
    color:var(--ink); font:inherit; line-height:1.5;
  }
  textarea:focus { outline:2px solid var(--blue); outline-offset:-1px; border-color:transparent; }
  .actions { display:flex; gap:9px; margin-top:11px; flex-wrap:wrap; }
  button {
    padding:10px 15px; border-radius:8px; border:1px solid var(--line);
    background:var(--panel2); color:var(--ink); font:inherit; font-weight:550;
    cursor:pointer; transition:border-color .12s, background .12s;
  }
  button:hover:not(:disabled) { border-color:var(--blue); }
  button.primary { background:#1d4ed8; border-color:#1d4ed8; }
  button.primary:hover:not(:disabled) { background:#2563eb; }
  button.ghost { background:transparent; }
  button:disabled { opacity:.45; cursor:not-allowed; }
  kbd {
    font-family:var(--mono); font-size:10.5px; padding:1px 5px; border-radius:4px;
    border:1px solid var(--line2); color:var(--dim); margin-left:5px;
  }

  /* ---------- samples ---------- */
  .sample-group { margin-top:14px; }
  .sample-group h3 {
    margin:0 0 8px; font-size:10.5px; letter-spacing:.9px; text-transform:uppercase;
    color:var(--dim2); font-weight:700;
  }
  .samples { display:grid; grid-template-columns:1fr 1fr; gap:7px; }
  @media (max-width:640px) { .samples { grid-template-columns:1fr; } }
  .sample {
    text-align:left; padding:9px 11px; border-radius:8px; border:1px solid var(--line);
    background:var(--bg2); cursor:pointer; display:flex; gap:9px; align-items:flex-start;
    transition:border-color .12s, background .12s;
  }
  .sample:hover:not(:disabled) { border-color:var(--blue); background:#101922; }
  .sample .id {
    font-family:var(--mono); font-size:9.5px; color:var(--blue);
    padding-top:2px; flex:0 0 34px;
  }
  .sample.safe .id { color:var(--green); }
  .sample .txt { min-width:0; }
  .sample .t { font-size:13px; line-height:1.35; display:block; }
  .sample .n { font-size:11px; color:var(--dim2); display:block; margin-top:2px; }

  /* ---------- stepper ---------- */
  .stepper { display:flex; gap:0; padding:14px 16px 4px; }
  .stage { flex:1; position:relative; text-align:center; }
  .stage .dot {
    width:26px; height:26px; border-radius:50%; margin:0 auto 6px;
    border:2px solid var(--line2); background:var(--bg2);
    display:flex; align-items:center; justify-content:center;
    font-size:11px; color:var(--dim2); font-weight:700;
    transition:all .18s;
  }
  .stage .lbl {
    font-size:10px; letter-spacing:.7px; text-transform:uppercase;
    color:var(--dim2); font-weight:700;
  }
  .stage.active .dot { border-color:var(--blue); color:var(--blue); background:#101c2b; }
  .stage.active .lbl { color:var(--blue); }
  .stage.done .dot { border-color:var(--green); background:#0d2a1d; color:var(--green); }
  .stage.done .lbl { color:var(--green); }
  .stage.stop .dot { border-color:var(--red); background:#2c1214; color:var(--red); }
  .stage.stop .lbl { color:var(--red); }
  .stage::after {
    content:''; position:absolute; top:13px; left:calc(50% + 18px); right:calc(-50% + 18px);
    height:2px; background:var(--line); z-index:0;
  }
  .stage:last-child::after { display:none; }
  .stage.done::after { background:var(--green); }

  /* ---------- log ---------- */
  .log {
    font-family:var(--mono); font-size:12px; line-height:1.7;
    padding:12px 16px 16px; max-height:340px; overflow-y:auto;
    scrollbar-width:thin; scrollbar-color:var(--line2) transparent;
  }
  .log:empty::before {
    content:'idle — pick a prompt and run';
    color:var(--dim2); font-style:italic;
  }
  .ln { display:flex; gap:8px; padding:1px 0; }
  .ln .ts { color:var(--dim2); flex:0 0 52px; }
  .ln .mk { flex:0 0 48px; font-weight:700; }
  .ln .tx { min-width:0; overflow-wrap:anywhere; color:#cfe0f5; }
  .ln.plan .mk { color:var(--blue); }
  .ln.exec .mk { color:var(--green); }
  .ln.stop .mk { color:var(--red); }
  .ln.human .mk { color:var(--amber); }
  .ln.err .mk { color:var(--red); }
  .ln.note .mk { color:var(--violet); }
  .ln .why { color:var(--dim); }

  /* ---------- results ---------- */
  .score { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:10px; }
  .stat { background:var(--bg2); border:1px solid var(--line); border-radius:9px; padding:12px 14px; }
  .stat .k { font-size:10px; letter-spacing:.8px; text-transform:uppercase; color:var(--dim2); font-weight:700; }
  .stat .v { font-size:23px; font-weight:700; margin-top:3px; font-variant-numeric:tabular-nums; }
  .stat.bad .v { color:var(--red); }
  .stat.good .v { color:var(--green); }
  .stat.warn .v { color:var(--amber); }

  .compare { display:grid; grid-template-columns:1fr 1fr; gap:1px; background:var(--line); }
  @media (max-width:820px) { .compare { grid-template-columns:1fr; } }
  .side { background:var(--bg2); padding:13px 15px; }
  .side h3 {
    margin:0 0 9px; font-size:10.5px; letter-spacing:.9px; text-transform:uppercase;
    font-weight:700; color:var(--dim2);
  }
  .side.danger h3 { color:var(--red); }
  .side.safe h3 { color:var(--green); }
  .step {
    font-family:var(--mono); font-size:12px; padding:6px 0;
    border-bottom:1px dashed #1b2431; display:flex; gap:8px; flex-wrap:wrap;
  }
  .step:last-child { border-bottom:none; }
  .step .m { font-weight:700; flex:0 0 42px; }
  .step .m.exec { color:var(--green); }
  .step .m.stop { color:var(--red); }
  .step .m.err { color:var(--red); }
  .step .t { color:#cfe0f5; }
  .step .a { color:var(--dim); overflow-wrap:anywhere; }
  .step .r { flex:0 0 100%; padding-left:50px; font-size:11px; color:var(--amber); }
  .step .why { flex:0 0 100%; padding-left:50px; font-size:11px; color:var(--dim); }
  .audit {
    font-family:var(--mono); font-size:11px; color:var(--dim2);
    padding:9px 15px; border-top:1px solid var(--line);
  }
  .audit .ok { color:var(--green); }
  .audit .no { color:var(--red); }

  .empty { color:var(--dim2); padding:26px 16px; text-align:center; font-size:13px; }
  footer {
    color:var(--dim2); font-size:12px; padding:0 26px 40px; max-width:1520px; margin:0 auto;
  }
  code {
    font-family:var(--mono); font-size:12px; background:#101c2b;
    padding:1.5px 5px; border-radius:4px; color:#cfe0f5;
  }
  .hint { font-size:12px; color:var(--dim2); margin-top:9px; }
  .hint b { color:var(--dim); font-weight:550; }
</style>
</head>
<body>

<header>
  <div class="head-row">
    <div class="brand">
      <b>AgentGuard</b>
      <span>policy gate for LLM tool calls</span>
    </div>
    <div class="spacer"></div>
    <div class="chips" id="chips"></div>
  </div>
</header>

<main>
  <div class="cols">

    <!-- ---------------- left: compose ---------------- -->
    <section class="card">
      <h2>Try it <span class="rt"><a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/" target="_blank" rel="noopener">OWASP Agentic Top 10 ↗</a></span></h2>
      <div class="body">
        <textarea id="task" placeholder="Describe a task for the agent, or pick one below…" spellcheck="false"></textarea>
        <div class="actions">
          <button class="primary" id="run">Run both agents<kbd>⏎</kbd></button>
          <button class="ghost" id="clear">Clear</button>
        </div>

        <div class="sample-group">
          <h3>Attack prompts — one per OWASP category</h3>
          <div class="samples" id="samples-attack"></div>
        </div>
        <div class="sample-group">
          <h3>Harmless prompts — should pass</h3>
          <div class="samples" id="samples-safe"></div>
        </div>

        <p class="hint">
          <b>Never executed.</b> Every tool call is simulated, so you can run any of these
          safely. Categories and mitigations are in the
          <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/" target="_blank" rel="noopener">OWASP Top 10 for Agentic Applications 2026</a>.
        </p>
      </div>
    </section>

    <!-- ---------------- right: live ---------------- -->
    <section class="card">
      <h2>Run <span class="rt" id="runstate"></span></h2>
      <div class="stepper" id="stepper">
        <div class="stage" data-stage="plan"><div class="dot">1</div><div class="lbl">Plan</div></div>
        <div class="stage" data-stage="policy"><div class="dot">2</div><div class="lbl">Policy</div></div>
        <div class="stage" data-stage="adjudicate"><div class="dot">3</div><div class="lbl">Adjudicate</div></div>
        <div class="stage" data-stage="execute"><div class="dot">4</div><div class="lbl">Execute</div></div>
      </div>
      <div class="log" id="log"></div>
    </section>
  </div>

  <div id="results" style="margin-top:20px"></div>
</main>

<footer>
  Categories from the <code>OWASP Top 10 for Agentic Applications 2026</code> (ASI01–ASI10).
  The runtime is also a CLI and a Python API — see the README. This page is only a demo harness.
</footer>

<script>
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const esc = (v) => String(v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const pretty = (o) => { const s = JSON.stringify(o); return (!s || s === '{}') ? '' : s; };
  const STORE = 'agentguard.v2';

  // ---------------------------------------------------------------- state
  let state = { task: '', results: null, log: [], meta: null };

  function save() {
    try { localStorage.setItem(STORE, JSON.stringify(state)); } catch (e) {}
  }
  function load() {
    try {
      const raw = localStorage.getItem(STORE);
      if (raw) state = Object.assign(state, JSON.parse(raw));
    } catch (e) {}
  }

  // ---------------------------------------------------------------- log
  const logEl = $('log');
  function stamp() {
    const d = new Date();
    return d.toTimeString().slice(0, 8);
  }
  function logLine(cls, mark, text, why) {
    const entry = { cls, mark, text, why: why || '', ts: stamp() };
    state.log.push(entry);
    if (state.log.length > 400) state.log.shift();
    appendLine(entry);
    logEl.scrollTop = logEl.scrollHeight;
  }
  function appendLine(e) {
    const div = document.createElement('div');
    div.className = 'ln ' + e.cls;
    div.innerHTML =
      `<span class="ts">${esc(e.ts)}</span>` +
      `<span class="mk">${esc(e.mark)}</span>` +
      `<span class="tx">${esc(e.text)}${e.why ? ' <span class="why">' + esc(e.why) + '</span>' : ''}</span>`;
    logEl.appendChild(div);
  }
  function renderLog() {
    logEl.innerHTML = '';
    state.log.forEach(appendLine);
    logEl.scrollTop = logEl.scrollHeight;
  }

  // ---------------------------------------------------------------- stepper
  const stages = ['plan', 'policy', 'adjudicate', 'execute'];
  const stepEls = {};
  document.querySelectorAll('.stage').forEach(s => { stepEls[s.dataset.stage] = s; });

  function resetStepper() {
    stages.forEach(s => { stepEls[s].className = 'stage'; });
    $('runstate').textContent = '';
  }
  function markStage(stage, cls) {
    if (!stepEls[stage]) return;
    const idx = stages.indexOf(stage);
    for (let i = 0; i < idx; i++) {
      if (!stepEls[stages[i]].classList.contains('stop')) stepEls[stages[i]].className = 'stage done';
    }
    stepEls[stage].className = 'stage ' + cls;
  }

  // ---------------------------------------------------------------- results
  function stepHtml(s) {
    const exec = s.outcome === 'executed' || s.outcome === 'approved';
    const mark = exec ? 'RUN' : (s.outcome === 'error' ? 'ERR' : 'STOP');
    const cls = exec ? 'exec' : (s.outcome === 'error' ? 'err' : 'stop');
    return `<div class="step">
      <span class="m ${cls}">${mark}</span>
      <span class="t">${esc(s.tool)}</span>(<span class="a">${esc(pretty(s.args))}</span>)
      ${s.rule ? `<span class="r">${esc(s.rule)}${s.asi ? ' · ' + esc(s.asi) : ''}</span>` : ''}
      ${s.reason ? `<span class="why">${esc(s.reason)}</span>` : ''}
    </div>`;
  }

  function sideHtml(run, danger) {
    const steps = run.steps.length
      ? run.steps.map(stepHtml).join('')
      : '<div class="step"><span class="a">no steps planned</span></div>';
    const a = run.audit;
    const chain = a.intact
      ? `<span class="ok">audit chain intact</span> · ${a.entries} entries · head ${esc(a.head)}…`
      : `<span class="no">AUDIT TAMPERED at #${a.tampered_at}</span>`;
    return `<div class="side ${danger ? 'danger' : 'safe'}">
      <h3>${danger ? 'Baseline — no policy' : 'Guarded — policy enforced'}</h3>
      ${steps}
      <div class="audit">${chain}</div>
    </div>`;
  }

  function renderResults(payload) {
    if (!payload) { $('results').innerHTML = ''; return; }
    const g = payload.guarded, b = payload.baseline;
    const stat = (label, value, tone) =>
      `<div class="stat ${tone || ''}"><div class="k">${esc(label)}</div><div class="v">${esc(value)}</div></div>`;

    $('results').innerHTML = `
      <div class="card">
        <h2>Result
          <span class="rt">${payload.adjudicator
            ? 'adjudicator ' + esc(payload.adjudicator)
            : 'adjudicator off'}</span>
        </h2>
        <div class="body" style="padding-bottom:0">
          <div class="score">
            ${stat('baseline landed', b.landed, b.landed ? 'bad' : '')}
            ${stat('guarded landed', g.landed, g.landed ? 'bad' : 'good')}
            ${stat('guarded blocked', g.blocked)}
            ${stat('injection seen', g.injection_seen ? 'yes' : 'no', g.injection_seen ? 'warn' : '')}
            ${g.adjudicated ? stat('adjudicated', g.adjudicated) : ''}
          </div>
        </div>
        <div class="compare" style="margin-top:16px">
          ${sideHtml(b, true)}
          ${sideHtml(g, false)}
        </div>
      </div>`;
  }

  // ---------------------------------------------------------------- samples
  function renderSamples(list) {
    const attack = $('samples-attack'), safe = $('samples-safe');
    attack.innerHTML = ''; safe.innerHTML = '';
    list.forEach(s => {
      const el = document.createElement('button');
      el.className = 'sample' + (s.asi ? '' : ' safe');
      el.innerHTML = `<span class="id">${esc(s.asi || 'safe')}</span>
        <span class="txt"><span class="t">${esc(s.label)}</span>
        <span class="n">${esc(s.note)}</span></span>`;
      el.title = s.task;
      el.onclick = () => {
        $('task').value = s.task;
        state.task = s.task;
        save();
        $('task').focus();
      };
      (s.asi ? attack : safe).appendChild(el);
    });
  }

  // ---------------------------------------------------------------- chips
  function renderChips(meta) {
    if (!meta) { $('chips').innerHTML = ''; return; }
    const bits = [];
    bits.push(`<span class="chip blue">${esc(meta.model || 'model')}</span>`);
    bits.push(meta.adjudicator
      ? `<span class="chip on">adjudicator ${esc(meta.adjudicator)}</span>`
      : `<span class="chip">no adjudicator</span>`);
    if (meta.fell_back) bits.push('<span class="chip warn">mock fallback</span>');
    $('chips').innerHTML = bits.join('');
  }

  // ---------------------------------------------------------------- running
  async function runStream(task) {
    resetStepper();
    state.log = [];
    logEl.innerHTML = '';
    $('runstate').textContent = 'running…';
    renderResults(null);

    logLine('note', 'TASK', task);
    markStage('plan', 'active');
    logLine('plan', 'PLAN', 'asking the planner for a tool plan');

    const url = '/api/stream?task=' + encodeURIComponent(task);
    let done = false;

    try {
      const res = await fetch(url);
      if (!res.ok || !res.body) throw new Error('stream unavailable');

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { value, done: fin } = await reader.read();
        if (fin) break;
        buffer += decoder.decode(value, { stream: true });

        let cut;
        while ((cut = buffer.indexOf('\n\n')) >= 0) {
          const chunk = buffer.slice(0, cut).trim();
          buffer = buffer.slice(cut + 2);
          if (!chunk.startsWith('data:')) continue;
          const event = JSON.parse(chunk.slice(5).trim());
          handleEvent(event);
          if (event.type === 'done') {
            done = true;
            $('runstate').textContent = '';
            renderResults(event.payload);
            state.results = event.payload;
            state.meta = event.payload;
            renderChips(event.payload);
            save();
          }
          if (event.type === 'error') {
            done = true;
            $('runstate').textContent = '';
            logLine('err', 'ERR', event.message);
            markStage('plan', 'stop');
          }
        }
      }
    } catch (e) {
      logLine('note', 'INFO', 'stream unavailable, falling back to a single request');
      try {
        const res = await fetch('/api/run', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({task}),
        });
        const payload = await res.json();
        renderResults(payload);
        state.results = payload; state.meta = payload;
        renderChips(payload); save();
        logLine('note', 'DONE', 'run complete');
        markStage('execute', 'done');
        done = true;
      } catch (e2) {
        logLine('err', 'ERR', String(e2.message || e2));
        markStage('plan', 'stop');
      }
    }

    $('runstate').textContent = done ? '' : 'incomplete';
  }

  function handleEvent(ev) {
    if (ev.type === 'start') {
      logLine('note', 'RUN', 'starting baseline and guarded agents');
      return;
    }
    if (ev.type === 'phase') {
      const side = ev.mode === 'guarded' ? 'guarded' : 'baseline';
      if (ev.phase === 'plan') {
        markStage('plan', 'active');
      } else if (ev.phase === 'planned') {
        logLine('plan', 'PLAN', `${side}: planner proposed ${ev.steps} step(s)`);
        markStage('policy', 'active');
      } else if (ev.phase === 'step') {
        logLine('note', 'STEP', `${side}: ${ev.tool}(${pretty(ev.args).slice(0, 80)})`);
        markStage('policy', 'active');
      } else if (ev.phase === 'done') {
        const r = ev.result || {};
        const tone = r.landed > 0 ? 'stop' : 'done';
        logLine(r.landed > 0 ? 'stop' : 'exec', 'DONE',
          `${side}: ${r.steps} step(s), ${r.landed} landed, ${r.blocked} blocked`);
        markStage('execute', tone);
      } else if (ev.phase === 'error') {
        logLine('err', 'ERR', `${side}: ${ev.reason}`);
        markStage('plan', 'stop');
      }
    }
  }

  // ---------------------------------------------------------------- wiring
  async function loadSamples() {
    try {
      const res = await fetch('/api/samples');
      const data = await res.json();
      renderSamples(data.samples || []);
    } catch (e) {}
  }

  $('run').onclick = () => {
    const task = $('task').value.trim();
    if (!task) { $('task').focus(); return; }
    state.task = task;
    save();
    const controls = document.querySelectorAll('button, textarea');
    controls.forEach(el => { el.disabled = true; });
    runStream(task).finally(() => {
      controls.forEach(el => { el.disabled = false; });
      if (state.meta) renderChips(state.meta);
    });
  };

  $('clear').onclick = () => {
    $('task').value = '';
    state = { task: '', results: null, log: [], meta: state.meta };
    save();
    logEl.innerHTML = '';
    resetStepper();
    renderResults(null);
    $('task').focus();
  };

  $('task').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); $('run').click(); }
  });

  // ---------------------------------------------------------------- boot
  load();
  loadSamples();
  if (state.task) $('task').value = state.task;
  renderLog();
  if (state.results) { renderResults(state.results); renderChips(state.meta); resetStepper(); }
  if (state.meta) renderChips(state.meta);
})();
</script>
</body>
</html>
"""
