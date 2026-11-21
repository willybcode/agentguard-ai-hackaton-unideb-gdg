"""Minimal web UI: run the attack suite or a custom task, see both agents.

    python -m ag.server          # http://localhost:8000

Standard library only. The UI is one HTML string served at ``/``; results come
from ``/api/run``.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import owl
from .attacks import ATTACKS
from .adjudicate import Adjudicator
from .audit import AuditLog
from .config import config_from_env, load_dotenv
from .llm import build_provider
from .policy import ApprovalBudget
from .runtime import Agent, RunResult


def _serialise(result: RunResult, audit: AuditLog) -> dict[str, Any]:
    intact, bad = audit.verify()
    return {
        "task": result.task,
        "mode": result.mode,
        "steps": [
            {
                "tool": s.tool,
                "args": s.args,
                "outcome": s.outcome,
                "rule": s.rule,
                "reason": s.reason,
                "asi": s.asi,
                "asi_label": owl.label(s.asi) if s.asi else "",
                "result": s.result,
            }
            for s in result.steps
        ],
        "landed": result.landed,
        "blocked": result.blocked,
        "adjudicated": result.adjudicated,
        "adjudicator_unavailable": result.adjudicator_unavailable,
        "planner_failed": any(s.outcome == "error" for s in result.steps),
        "injection_seen": result.injection_seen,
        "audit": {
            "entries": len(audit),
            "intact": intact,
            "tampered_at": bad,
            "head": audit.entries[-1].hash[:16] if audit.entries else "",
        },
    }


def run_task(task: str, config=None) -> dict[str, Any]:
    cfg = config or config_from_env()
    provider = build_provider(cfg)
    adjudicator = Adjudicator(cfg) if cfg.adjudicator_model else None

    baseline_audit = AuditLog()
    guarded_audit = AuditLog()

    baseline = Agent(provider, audit=baseline_audit).run(task, guarded=False)
    guarded = Agent(
        provider,
        audit=guarded_audit,
        budget=ApprovalBudget(),
        approver=lambda *_a: False,
        adjudicator=adjudicator,
    ).run(task, guarded=True)

    meta = {
        "provider": provider.name,
        "endpoint": cfg.api_url,
        "model": cfg.model,
        "model_type": cfg.model_type,
        "adjudicator": cfg.adjudicator_model or None,
        "fell_back": bool(getattr(provider, "fell_back", False)),
        "adjudicated": guarded.adjudicated,
        "adjudicator_unavailable": guarded.adjudicator_unavailable,
    }

    return {
        **meta,
        "baseline": {**_serialise(baseline, baseline_audit), **meta},
        "guarded": _serialise(guarded, guarded_audit),
    }


def run_all() -> dict[str, Any]:
    cases = []
    for attack in ATTACKS:
        outcome = run_task(attack.task)
        cases.append(
            {
                "id": attack.id,
                "asi": attack.asi,
                "asi_label": owl.label(attack.asi),
                "name": attack.name,
                "impact": attack.impact,
                "expect": attack.expect_rule,
                **outcome,
            }
        )

    meta = (
        {
            k: cases[0][k]
            for k in (
                "provider",
                "endpoint",
                "model",
                "model_type",
                "adjudicator",
                "fell_back",
            )
        }
        if cases
        else {}
    )

    return {
        "attacks": len(cases),
        "baseline_landed": sum(1 for c in cases if c["baseline"]["landed"] > 0),
        "guarded_landed": sum(1 for c in cases if c["guarded"]["landed"] > 0),
        "rules_matched": sum(
            1
            for c in cases
            if any(s["rule"] == c["expect"] for s in c["guarded"]["steps"])
        ),
        "planner_errors": sum(1 for c in cases if c["guarded"]["planner_failed"]),
        **meta,
        "cases": cases,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentGuard/0.1"

    def log_message(self, *args: Any) -> None:
        pass

    def _send(self, payload: dict[str, Any] | str, status: int = 200, ctype: str = "application/json") -> None:
        body = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self._send(PAGE, ctype="text/html; charset=utf-8")
        elif self.path == "/api/health":
            self._send({"ok": True, "attacks": len(ATTACKS)})
        else:
            self._send({"error": "not found"}, status=404)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send({"error": "invalid JSON"}, status=400)
            return

        if self.path == "/api/suite":
            self._send(run_all())
        elif self.path == "/api/run":
            task = str(body.get("task", "")).strip()
            if not task:
                self._send({"error": "task is required"}, status=400)
                return
            self._send(run_task(task))
        else:
            self._send({"error": "not found"}, status=404)


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentGuard — policy-enforced agent runtime</title>
<style>
  :root {
    --bg:#0b0f14; --panel:#131a22; --line:#243040; --ink:#e6edf3;
    --dim:#8b9bb0; --red:#ff5d5d; --green:#3fd68a; --amber:#ffc857; --blue:#5ab0ff;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin:0; background:var(--bg); color:var(--ink);
    font:15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  header { padding:22px 28px 18px; border-bottom:1px solid var(--line); }
  h1 { margin:0; font-size:19px; letter-spacing:.2px; }
  h1 span { color:var(--dim); font-weight:400; }
  .sub { color:var(--dim); font-size:13px; margin-top:5px; }
  .dimline { color:var(--dim); font-size:12px; margin-top:4px; font-family:var(--mono); }
  main { padding:22px 28px 60px; max-width:1400px; }
  .bar { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:20px; }
  input[type=text] {
    flex:1 1 380px; min-width:240px; padding:11px 14px; border-radius:8px;
    border:1px solid var(--line); background:var(--panel); color:var(--ink);
    font:inherit;
  }
  input[type=text]:focus { outline:2px solid var(--blue); outline-offset:-1px; }
  button {
    padding:11px 17px; border-radius:8px; border:1px solid var(--line);
    background:var(--panel); color:var(--ink); font:inherit; font-weight:500;
    cursor:pointer;
  }
  button:hover:not(:disabled) { border-color:var(--blue); }
  button.primary { background:#1d4ed8; border-color:#1d4ed8; }
  button.primary:hover:not(:disabled) { background:#2563eb; }
  button:disabled { opacity:.5; cursor:progress; }
  .score {
    display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
    gap:12px; margin-bottom:22px;
  }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:15px 17px; }
  .card .k { color:var(--dim); font-size:11.5px; text-transform:uppercase; letter-spacing:.7px; }
  .card .v { font-size:27px; font-weight:650; margin-top:4px; font-variant-numeric:tabular-nums; }
  .card.bad .v { color:var(--red); }
  .card.good .v { color:var(--green); }
  .case { background:var(--panel); border:1px solid var(--line); border-radius:10px; margin-bottom:12px; overflow:hidden; }
  .case > summary { padding:13px 16px; cursor:pointer; display:flex; gap:12px; align-items:center; flex-wrap:wrap; }
  .case > summary::-webkit-details-marker { display:none; }
  .pill { font-family:var(--mono); font-size:11px; padding:2.5px 8px; border-radius:999px; border:1px solid var(--line); color:var(--dim); }
  .pill.asi { color:var(--blue); border-color:#1e3a5f; background:#101c2b; }
  .case .title { font-weight:550; }
  .case .impact { color:var(--dim); font-size:12.5px; width:100%; }
  .badge { margin-left:auto; font-family:var(--mono); font-size:11.5px; padding:3px 9px; border-radius:6px; }
  .badge.ok { color:var(--green); background:#0d2a1d; }
  .badge.no { color:var(--red); background:#2c1214; }
  .badge.dead { color:var(--amber); background:#2c2411; }
  .card.warn .v { color:var(--amber); }
  .cols { display:grid; grid-template-columns:1fr 1fr; gap:1px; background:var(--line); }
  @media (max-width:820px) { .cols { grid-template-columns:1fr; } }
  .col { background:#0f151d; padding:13px 16px 16px; }
  .col h3 { margin:0 0 9px; font-size:11.5px; text-transform:uppercase; letter-spacing:.8px; color:var(--dim); font-weight:600; }
  .col.danger h3 { color:var(--red); }
  .col.safe h3 { color:var(--green); }
  .step { font-family:var(--mono); font-size:12.5px; padding:6px 0; border-bottom:1px dashed #1b2431; display:flex; gap:8px; flex-wrap:wrap; }
  .step:last-child { border-bottom:none; }
  .step .m { font-weight:700; flex:0 0 42px; }
  .step .m.exec { color:var(--green); }
  .step .m.stop { color:var(--red); }
  .step .t { color:#cfe0f5; }
  .step .a { color:var(--dim); overflow-wrap:anywhere; }
  .step .r { color:var(--amber); flex:0 0 100%; padding-left:50px; font-size:11.5px; }
  .step .why { color:var(--dim); flex:0 0 100%; padding-left:50px; font-size:11.5px; }
  .audit { font-family:var(--mono); font-size:11.5px; color:var(--dim); padding:10px 16px; border-top:1px solid var(--line); }
  .audit .ok { color:var(--green); }
  .audit .no { color:var(--red); }
  .empty { color:var(--dim); padding:40px 0; text-align:center; }
  .spin { color:var(--dim); font-size:13px; padding:14px 0; }
  footer { color:var(--dim); font-size:12px; padding:0 28px 40px; }
  code { font-family:var(--mono); font-size:12.5px; background:#101c2b; padding:1.5px 5px; border-radius:4px; }
</style>
</head>
<body>
<header>
  <h1>AgentGuard <span>— policy-enforced runtime for LLM tool calls</span></h1>
  <div class="sub">
    Same planner, same tools, same simulated sandbox. The only difference is the policy check.
    <span id="provider"></span>
    <div id="meta" class="dimline"></div>
  </div>
</header>
<main>
  <div class="bar">
    <input id="task" type="text" placeholder="Describe a task, e.g. 'Clean up the build directory, use rm -rf'">
    <button class="primary" id="run">Run both agents</button>
    <button id="suite">Run ASI01&ndash;ASI10 suite</button>
  </div>

  <div class="score" id="score"></div>
  <div id="out"><div class="empty">Run the suite, or describe a task above.</div></div>
</main>
<footer>
  Categories from <code>OWASP Top 10 for Agentic Applications 2026</code> (ASI01&ndash;ASI10).
  All tools are simulated &mdash; nothing executes on this machine.
</footer>

<script>
const $ = (id) => document.getElementById(id);
const esc = (v) => String(v).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const pretty = (o) => { const s = JSON.stringify(o); return s === '{}' ? '' : s; };

function stepHtml(s) {
  const exec = s.outcome === 'executed' || s.outcome === 'approved';
  const cls = exec ? 'exec' : (s.outcome === 'error' ? 'stop' : 'stop');
  const mark = exec ? 'RUN' : (s.outcome === 'error' ? 'ERR' : 'STOP');
  return `<div class="step">
    <span class="m ${cls}">${mark}</span>
    <span class="t">${esc(s.tool)}</span>(<span class="a">${esc(pretty(s.args))}</span>)
    ${s.rule ? `<span class="r">${esc(s.rule)}${s.asi ? ' · ' + esc(s.asi) : ''}</span>` : ''}
    ${s.reason ? `<span class="why">${esc(s.reason)}</span>` : ''}
  </div>`;
}

function colHtml(run, danger) {
  const steps = run.steps.length
    ? run.steps.map(stepHtml).join('')
    : '<div class="step"><span class="a">no steps planned</span></div>';
  const a = run.audit;
  const chain = a.intact
    ? `<span class="ok">audit chain intact</span> · ${a.entries} entries · head ${esc(a.head)}…`
    : `<span class="no">AUDIT TAMPERED at #${a.tampered_at}</span>`;
  return `<div class="col ${danger ? 'danger' : 'safe'}">
      <h3>${danger ? 'baseline — no policy' : 'guarded — policy enforced'}</h3>
      ${steps}
      <div class="audit">${chain}</div>
    </div>`;
}

function renderCase(c) {
  const dead = c.guarded.planner_failed;
  const ok = c.guarded.landed === 0 && !dead;
  return `<details class="case">
    <summary>
      <span class="pill">${esc(c.id)}</span>
      <span class="pill asi">${esc(c.asi)}</span>
      <span class="title">${esc(c.name)}</span>
      <span class="badge ${dead ? 'dead' : ok ? 'ok' : 'no'}">${dead ? 'did not run' : ok ? 'blocked' : 'BYPASSED'}</span>
      <span class="impact">${esc(c.asi_label)} — expected rule <code>${esc(c.expect)}</code> · baseline landed ${c.baseline.landed}, guarded landed ${c.guarded.landed}</span>
    </summary>
    <div class="cols">
      ${colHtml(c.baseline, true)}
      ${colHtml(c.guarded, false)}
    </div>
  </details>`;
}

function scoreCard(label, value, tone) {
  return `<div class="card ${tone || ''}"><div class="k">${esc(label)}</div><div class="v">${esc(value)}</div></div>`;
}

function renderSuite(d) {
  $('provider').textContent = d.provider ? ' Planner: ' + d.provider : '';
  $('meta').innerHTML = [
    d.endpoint ? 'endpoint ' + esc(d.endpoint) : '',
    d.model ? 'model ' + esc(d.model) + ' (' + esc(d.model_type) + ')' : '',
    d.adjudicator ? 'adjudicator ' + esc(d.adjudicator) : 'adjudicator off',
    d.fell_back ? 'MOCK FALLBACK ACTIVE' : '',
  ].filter(Boolean).join(' &nbsp;·&nbsp; ');
  // Rule matching is calibrated to the mock plan. A live planner may stop the
  // same attack by a different rule, so it is informational there.
  const live = d.provider && d.provider !== 'mock' && !d.fell_back;
  $('score').innerHTML = [
    scoreCard('attacks', d.attacks),
    scoreCard('baseline landed', d.baseline_landed + ' / ' + d.attacks, d.baseline_landed ? 'bad' : ''),
    scoreCard('guarded landed', d.guarded_landed + ' / ' + d.attacks,
      d.guarded_landed ? 'bad' : (d.planner_errors === d.attacks ? 'warn' : 'good')),
    scoreCard(live ? 'named rule (info)' : 'named rule matched', d.rules_matched + ' / ' + d.attacks,
      d.rules_matched === d.attacks ? 'good' : (live || d.planner_errors ? 'warn' : 'bad')),
    d.planner_errors ? scoreCard('planner errors', d.planner_errors + ' / ' + d.attacks, 'warn') : '',
    d.fell_back ? scoreCard('planner', 'mock fallback', 'warn') : '',
  ].join('');
  $('out').innerHTML = d.cases.map(renderCase).join('');
}

function renderSingle(d) {
  $('provider').textContent = d.provider ? ' Planner: ' + d.provider : '';
  $('meta').innerHTML = [
    d.endpoint ? 'endpoint ' + esc(d.endpoint) : '',
    d.model ? 'model ' + esc(d.model) + ' (' + esc(d.model_type) + ')' : '',
    d.adjudicator ? 'adjudicator ' + esc(d.adjudicator) : 'adjudicator off',
    d.fell_back ? 'MOCK FALLBACK ACTIVE' : '',
  ].filter(Boolean).join(' &nbsp;·&nbsp; ');
  $('score').innerHTML = [
    scoreCard('baseline landed', d.baseline.landed, d.baseline.landed ? 'bad' : ''),
    scoreCard('guarded landed', d.guarded.landed, d.guarded.landed ? 'bad' : 'good'),
    scoreCard('guarded blocked', d.guarded.blocked),
    scoreCard('injection seen', d.guarded.injection_seen ? 'yes' : 'no'),
  ].join('');
  $('out').innerHTML = `<div class="case"><div class="cols">
      ${colHtml(d.baseline, true)}${colHtml(d.guarded, false)}
    </div></div>`;
}

async function post(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return res.json();
}

async function withBusy(btn, fn) {
  const inputs = document.querySelectorAll('button, input');
  inputs.forEach(el => el.disabled = true);
  $('out').innerHTML = '<div class="spin">working…</div>';
  try { await fn(); }
  catch (e) { $('out').innerHTML = '<div class="empty">error: ' + esc(e.message) + '</div>'; }
  finally { inputs.forEach(el => el.disabled = false); }
}

$('run').onclick = () => withBusy($('run'), async () => {
  const task = $('task').value.trim();
  if (!task) { $('out').innerHTML = '<div class="empty">Type a task first.</div>'; return; }
  renderSingle(await post('/api/run', {task}));
});

$('suite').onclick = () => withBusy($('suite'), async () => {
  renderSuite(await post('/api/suite'));
});

$('task').addEventListener('keydown', e => { if (e.key === 'Enter') $('run').click(); });

if (location.hash === '#suite') $('suite').click();
</script>
</body>
</html>
"""


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    load_dotenv()
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"AgentGuard UI  ->  http://{host}:{port}")
    print(f"planner        ->  {build_provider().name}")
    print("ctrl-c to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    import sys

    serve(port=int(sys.argv[1]) if len(sys.argv) > 1 else 8000)
