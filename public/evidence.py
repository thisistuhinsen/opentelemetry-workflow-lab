"""Small, dependency-free recorder and local viewer for workflow runs.

The supplied root is the dedicated evidence directory (for example,
``<output>/evidence``). The recorder only stores command arguments, redacted
stdout/stderr, explicitly supplied result metadata, and phase events. It never
captures stdin, request bodies, or the process environment.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

_AUTH_PATTERNS = (
    re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(
        r"(?i)(\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)\b\s*[:=]\s*)([^\s,;]+)"
    ),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,})\b"),
)
_INDEX_LOCK = threading.RLock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temp.write_text(content, encoding="utf-8", newline="\n")
        os.replace(temp, path)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _log_preview(path: Path, limit: int = 8000) -> str:
    """Read only a bounded tail for the inline viewer; full logs stay on disk."""
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(max(0, size - 32768), os.SEEK_SET)
            text = stream.read().decode("utf-8", errors="replace")
    except OSError:
        return ""
    if len(text) > limit:
        return (
            "[Showing final 8,000 characters. Open the full log file for earlier output.]\n" + text[-limit:]
        )
    return text


def _safe_json_for_script(value: Any) -> str:
    # Prevent untrusted text from closing the JSON script element or creating
    # HTML parser ambiguities. The viewer uses textContent for all rendered data.
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


_VIEWER = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light"><title>Workflow Lab · Run Evidence</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;color:#e9eef5;background:#10151d;font-synthesis:none}
*{box-sizing:border-box}body{margin:0}a{color:#8bd5ca}button,input{font:inherit}.shell{max-width:1440px;margin:auto;padding:28px clamp(16px,4vw,52px) 56px}
header{display:flex;align-items:center;justify-content:space-between;gap:20px;border-bottom:1px solid #293342;padding-bottom:22px}.brand{display:flex;align-items:center;gap:13px}.mark{width:40px;height:40px;border-radius:12px;background:linear-gradient(145deg,#77e0c1,#4387b5);display:grid;place-items:center;color:#10151d;font-weight:900;font-size:21px}.eyebrow{color:#91a3b8;font-size:11px;text-transform:uppercase;letter-spacing:.16em;font-weight:700}.title{font-size:21px;font-weight:750;margin-top:3px}.local{color:#99a9ba;font-size:12px}.intro{display:flex;justify-content:space-between;align-items:end;gap:20px;margin:30px 0 18px}.intro h1{font-size:clamp(24px,4vw,36px);letter-spacing:-.04em;margin:0}.intro p{margin:8px 0 0;color:#aab8c7}.stats{display:flex;gap:10px}.stat{min-width:95px;padding:12px 15px;background:#171f2a;border:1px solid #2a3544;border-radius:12px}.stat b{font-size:21px;display:block}.stat span{font-size:11px;color:#94a4b6}.toolbar{display:flex;gap:10px;margin:20px 0 15px}.toolbar input{background:#171f2a;color:inherit;border:1px solid #344255;border-radius:9px;padding:11px 13px;min-width:220px;max-width:440px;flex:1}.toolbar button,.tab{background:#1b2633;color:#dce7f1;border:1px solid #344255;border-radius:8px;padding:9px 12px;cursor:pointer}.toolbar button:hover,.tab:hover{border-color:#80cbb9}.layout{display:grid;grid-template-columns:minmax(230px,320px) minmax(0,1fr);gap:16px;align-items:start}.panel{background:#151c26;border:1px solid #293545;border-radius:14px;overflow:hidden}.panel-head{padding:14px 16px;border-bottom:1px solid #293545;color:#aebccc;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em}.run-list{max-height:70vh;overflow:auto}.run{display:block;width:100%;text-align:left;border:0;border-bottom:1px solid #252e3a;background:transparent;color:inherit;padding:14px 15px;cursor:pointer}.run:hover,.run[aria-current=true]{background:#202b37}.run-title{font-size:13px;font-weight:700;overflow-wrap:anywhere}.run-meta{font-size:11px;color:#95a6b8;margin-top:6px}.pill{display:inline-flex;align-items:center;border-radius:999px;padding:3px 8px;background:#263441;color:#9ee0cb;font-size:10px;text-transform:uppercase;font-weight:750}.pill.failed{background:#442b31;color:#ffaaa9}.pill.running{background:#423820;color:#ffd786}.empty{padding:26px;color:#9babbc;line-height:1.55}.detail{padding:20px}.detail-top{display:flex;justify-content:space-between;gap:18px;align-items:start}.detail h2{margin:0;font-size:20px;overflow-wrap:anywhere}.muted{color:#9babbc;font-size:12px;line-height:1.65}.story{margin:12px 0 18px;line-height:1.55;color:#c4d0dc;white-space:pre-wrap;overflow-wrap:anywhere}.links{display:flex;gap:14px;font-size:12px;margin:10px 0 18px}.section-title{font-size:12px;text-transform:uppercase;letter-spacing:.1em;color:#96a8bc;margin:20px 0 9px}.timeline{border-left:1px solid #405264;margin-left:6px;padding-left:17px}.event{position:relative;padding:0 0 15px}.event:before{content:"";position:absolute;width:9px;height:9px;border-radius:50%;background:#72d0b4;left:-22px;top:4px;box-shadow:0 0 0 3px #20322f}.event strong{font-size:13px}.event small{display:block;color:#8496aa;margin-top:3px}.logtabs{display:flex;gap:7px;margin:8px 0}.logtabs button[aria-selected=true]{border-color:#73cbb3;background:#223c39}.log{margin:0;white-space:pre-wrap;overflow-wrap:anywhere;max-height:360px;overflow:auto;background:#0b1016;border:1px solid #2a3544;border-radius:10px;padding:14px;color:#c0d3e2;font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace}.command{padding:12px;background:#1a232e;border-radius:9px;margin:9px 0}.command code{display:block;white-space:pre-wrap;overflow-wrap:anywhere;color:#d5e3ed;font:12px/1.5 ui-monospace,Consolas,monospace}.command .links{margin:8px 0 0}.result{max-height:260px;overflow:auto;background:#0b1016;border:1px solid #2a3544;border-radius:10px;padding:14px;color:#bde5d7;font:12px/1.55 ui-monospace,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
@media(max-width:760px){header,.intro{align-items:flex-start;flex-direction:column}.stats{width:100%}.stat{flex:1}.layout{grid-template-columns:1fr}.run-list{max-height:32vh}.toolbar input{min-width:0}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
@media(max-width:760px){.toolbar{display:grid;grid-template-columns:1fr 1fr}.toolbar label,.toolbar input,.toolbar .muted{grid-column:1/-1}.toolbar input{width:100%;max-width:none}.links{flex-wrap:wrap}}
:focus-visible{outline:3px solid #80d9c1;outline-offset:2px}
</style></head><body><div class="shell"><header><div class="brand"><div class="mark" aria-hidden="true">W</div><div><div class="eyebrow">OpenTelemetry Workflow Lab</div><div class="title">Run evidence</div></div></div><div class="local">Local evidence · no network connection</div></header>
<section class="intro"><div><h1>Runs, made inspectable.</h1><p>Browse workflow phases, command output, and recorded result metadata.</p></div><div class="stats" aria-label="Run summary"><div class="stat"><b id="total">0</b><span>total runs</span></div><div class="stat"><b id="success">0</b><span>completed</span></div><div class="stat"><b id="failed">0</b><span>failed</span></div></div></section>
<div class="toolbar"><label class="eyebrow" for="filter" style="align-self:center">Filter runs</label><input id="filter" type="search" placeholder="Search story, status, or run ID" autocomplete="off"><button id="clear" type="button">Clear</button><button id="refresh" type="button">Refresh</button><span class="muted" style="align-self:center">Refreshes every 2 seconds while a run is active</span></div>
<div class="layout"><section class="panel" aria-label="Recorded runs"><div class="panel-head">Runs <span id="shown"></span></div><div class="run-list" id="runs" role="listbox" aria-label="Select a run"></div></section><main class="panel" id="detail" aria-live="polite"><div class="empty">Select a run to inspect its phase timeline, command logs, and result metadata. New evidence appears when the page is refreshed.</div></main></div></div>
<script id="evidence-data" type="application/json">__DATA__</script><script>
(()=>{const data=JSON.parse(document.getElementById('evidence-data').textContent),list=document.getElementById('runs'),detail=document.getElementById('detail'),filter=document.getElementById('filter');let saved={};try{saved=JSON.parse(sessionStorage.getItem('workflow-lab-view')||'{}')}catch{}filter.value=saved.filter||'';let selected=saved.selected||data.runs[0]?.id||'',activeLog=saved.activeLog||'';
const el=(tag,cls,txt)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(txt!==undefined)n.textContent=txt;return n};
document.getElementById('total').textContent=data.runs.length;document.getElementById('success').textContent=data.runs.filter(r=>['passed','completed','success'].includes(r.status)).length;document.getElementById('failed').textContent=data.runs.filter(r=>r.status==='failed'||r.status==='error').length;
function renderList(){list.replaceChildren();const q=filter.value.toLowerCase().trim(),rows=data.runs.filter(r=>(r.id+' '+(r.story||'')+' '+r.status+' '+r.command).toLowerCase().includes(q));document.getElementById('shown').textContent='· '+rows.length;for(const r of rows){const b=el('button','run');b.type='button';b.setAttribute('role','option');b.setAttribute('aria-current',String(r.id===selected));b.append(el('div','run-title',r.story||r.command||'Workflow run'));const meta=el('div','run-meta');meta.append(el('span','pill '+(['failed','error'].includes(r.status)?'failed':['running'].includes(r.status)?'running':''),r.status||'unknown'),document.createTextNode('  '+r.started_at+' · '+r.id.slice(0,8)));b.append(meta);b.onclick=()=>{selected=r.id;activeLog='';renderList();renderDetail(r)};list.append(b)}if(!rows.length)list.append(el('div','empty','No runs match this filter.'));if(!rows.some(r=>r.id===selected)){selected=rows[0]?.id||''}if(selected){const r=data.runs.find(x=>x.id===selected);if(r)renderDetail(r)}else detail.replaceChildren(el('div','empty','No run selected.'))}
function link(path,label){const a=el('a','',label);a.href=path;a.setAttribute('download','');return a}
function renderDetail(r){detail.replaceChildren();const box=el('div','detail'),top=el('div','detail-top'),heading=el('div');heading.append(el('h2','',r.story||'Workflow run'),el('div','muted',r.id+' · started '+r.started_at+(r.finished_at?' · finished '+r.finished_at:'')));top.append(heading,el('span','pill '+(['failed','error'].includes(r.status)?'failed':['running'].includes(r.status)?'running':''),r.status||'unknown'));box.append(top);if(r.command)box.append(el('div','story','Command: '+r.command));if(r.story)box.append(el('div','story',r.story));const links=el('div','links');links.append(link(r.files.run,'Run JSON'),link(r.files.events,'Event JSONL'));box.append(links);if(r.artifacts?.length){box.append(el('div','section-title','Artifacts'));const artifacts=el('div','links');for(const item of r.artifacts){if(typeof item.href==='string'&&!item.href.startsWith('/')&&!item.href.includes('..')&&!item.href.includes('\\')&&!/^[a-z][a-z0-9+.-]*:/i.test(item.href)){const a=link(item.href,item.label||'Artifact');a.removeAttribute('download');artifacts.append(a)}}box.append(artifacts)}box.append(el('div','section-title','Phase timeline'));const timeline=el('div','timeline');for(const e of r.events||[]){const row=el('div','event');row.append(el('strong','',e.message||e.type||'Event'),el('small','',(e.timestamp||'')+' · '+(e.status||'event')));timeline.append(row)}box.append(timeline);
if(r.commands?.length){box.append(el('div','section-title','Commands & logs'));for(const c of r.commands){const cmd=el('div','command');cmd.append(el('code','',Array.isArray(c.argv)?c.argv.join(' '):(c.argv||'')),el('div','muted',(c.exit_code===null?'running':'exit '+c.exit_code)+' · '+(c.duration_seconds??'')+'s'));const ls=el('div','links');ls.append(link(c.stdout,'stdout file'),link(c.stderr,'stderr file'));cmd.append(ls);const tabs=el('div','logtabs');for(const k of ['stdout','stderr']){const t=el('button','tab',k);t.type='button';t.setAttribute('aria-selected',String(activeLog===c.id+':'+k));t.onclick=()=>{activeLog=c.id+':'+k;renderDetail(r)};tabs.append(t)}cmd.append(tabs);if(activeLog.startsWith(c.id+':'))cmd.append(el('pre','log',c[activeLog.split(':')[1]+'_text']||'(empty)'));box.append(cmd)}}
if(r.result!==undefined){box.append(el('div','section-title','Result metadata'));box.append(el('pre','result',JSON.stringify(r.result,null,2)));if(r.files.result){const ls=el('div','links');ls.append(link(r.files.result,'result JSON'));box.append(ls)}}detail.append(box)}
filter.addEventListener('input',renderList);document.getElementById('clear').onclick=()=>{filter.value='';renderList();filter.focus()};document.getElementById('refresh').onclick=()=>location.reload();renderList();if(data.runs.some(r=>r.status==='running'))setInterval(()=>{try{sessionStorage.setItem('workflow-lab-view',JSON.stringify({filter:filter.value,selected,activeLog}))}catch{}location.reload()},2000)})();
</script></body></html>"""


class EvidenceRecorder:
    """Persist one run under a dedicated local evidence directory."""

    def __init__(self, root: Path, command: str, story: str | None = None, open_browser: bool = False):
        self.root = Path(root).expanduser().resolve()
        self.runs_dir = self.root / "runs"
        self.run_id = str(uuid.uuid4())
        self.directory = self.runs_dir / self.run_id
        self.directory.mkdir(parents=True, exist_ok=False)
        (self.directory / "commands").mkdir()
        self._lock = threading.RLock()
        self._last_index_refresh = 0.0
        self._redactions: list[str] = []
        self._events: list[dict[str, Any]] = []
        self._commands: list[dict[str, Any]] = []
        self._record = {
            "run_id": self.run_id,
            "command": str(command),
            "story": story,
            "status": "running",
            "started_at": _now(),
            "finished_at": None,
            "events": self._events,
            "commands": self._commands,
        }
        self._write_run()
        self._rebuild_index()
        if open_browser:
            webbrowser.open(self.index_path.as_uri())

    @property
    def index_path(self) -> Path:
        return self.root / "index.html"

    def set_redactions(self, tokens: list[str]) -> None:
        """Redact caller-supplied literal secrets from future command logs."""
        with self._lock:
            self._redactions = sorted({str(t) for t in tokens if t}, key=len, reverse=True)

    def _redact(self, text: str) -> str:
        for token in self._redactions:
            text = text.replace(token, "[REDACTED]")
        for pattern in _AUTH_PATTERNS:
            if pattern.groups:
                if pattern.groups == 2:
                    text = pattern.sub(lambda m: m.group(1) + "[REDACTED]", text)
                else:
                    text = pattern.sub(lambda m: m.group(1) + "[REDACTED]", text)
            else:
                text = pattern.sub("[REDACTED]", text)
        return text

    def _write_run(self) -> None:
        _atomic_json(self.directory / "run.json", self._record)

    def _rebuild_index(self, force: bool = False) -> None:
        with _INDEX_LOCK:
            now = time.monotonic()
            if not force and now - self._last_index_refresh < 0.5:
                return
            rows = []
            try:
                dirs = [p for p in self.runs_dir.iterdir() if p.is_dir() and not p.is_symlink()]
            except FileNotFoundError:
                dirs = []
            for run_dir in sorted(dirs, key=lambda p: p.name, reverse=True):
                manifest = run_dir / "run.json"
                if not manifest.is_file() or manifest.is_symlink():
                    continue
                try:
                    rec = json.loads(manifest.read_text(encoding="utf-8"))

                    def rel(path):
                        return path.relative_to(self.root).as_posix()

                    commands = []
                    for c in rec.get("commands", []):
                        stdout = run_dir / "commands" / c["stdout_name"]
                        stderr = run_dir / "commands" / c["stderr_name"]
                        commands.append(
                            {
                                **c,
                                "stdout": rel(stdout),
                                "stderr": rel(stderr),
                                "stdout_text": _log_preview(stdout),
                                "stderr_text": _log_preview(stderr),
                            }
                        )
                    result_path = run_dir / "result.json"
                    events_path = run_dir / "events.jsonl"
                    events = []
                    if events_path.is_file():
                        for line in events_path.read_text(encoding="utf-8").splitlines():
                            if line.strip():
                                events.append(json.loads(line))
                    rows.append(
                        {
                            "id": rec["run_id"],
                            "command": rec.get("command", ""),
                            "story": rec.get("story"),
                            "status": rec.get("status", "unknown"),
                            "started_at": rec.get("started_at", ""),
                            "finished_at": rec.get("finished_at"),
                            "events": events,
                            "commands": commands,
                            "artifacts": rec.get("artifacts", []),
                            "result": json.loads(result_path.read_text(encoding="utf-8"))
                            if result_path.is_file()
                            else rec.get("result"),
                            "files": {
                                "run": rel(manifest),
                                "events": rel(events_path),
                                "result": rel(result_path) if result_path.is_file() else None,
                            },
                        }
                    )
                except (OSError, ValueError, KeyError, TypeError):
                    # A concurrent writer may be between durable file updates;
                    # omit that row until its next refresh instead of breaking the index.
                    continue
            rows.sort(key=lambda row: (row["started_at"], row["id"]), reverse=True)
            html_doc = _VIEWER.replace("__DATA__", _safe_json_for_script({"runs": rows}))
            _atomic_text(self.index_path, html_doc)
            self._last_index_refresh = time.monotonic()

    def phase(self, message: str, status: str = "running", **metadata: Any) -> None:
        with self._lock:
            event = {
                "timestamp": _now(),
                "type": "phase",
                "message": str(message),
                "status": str(status),
                "metadata": metadata,
            }
            self._events.append(event)
            self._record["events"] = self._events
            event_path = self.directory / "events.jsonl"
            event_path.parent.mkdir(parents=True, exist_ok=True)
            with event_path.open("a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
            self._write_run()
            self._rebuild_index()

    def begin_native(self, argv: list[str]) -> str:
        """Create durable command/log records before launching a native process."""
        with self._lock:
            command_id = f"{len(self._commands) + 1:03d}"
            out_name, err_name = f"{command_id}.stdout.log", f"{command_id}.stderr.log"
            cmd = {
                "id": command_id,
                "argv": [self._redact(str(a)) for a in argv],
                "exit_code": None,
                "duration_seconds": None,
                "status": "running",
                "stdout_name": out_name,
                "stderr_name": err_name,
            }
            (self.directory / "commands" / out_name).write_bytes(b"")
            (self.directory / "commands" / err_name).write_bytes(b"")
            self._commands.append(cmd)
            self._record["commands"] = self._commands
            event = {
                "timestamp": _now(),
                "type": "command",
                "message": "Native command started",
                "status": "running",
                "command_id": command_id,
            }
            self._events.append(event)
            with (self.directory / "events.jsonl").open("a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
            self._write_run()
            self._rebuild_index(force=True)
            return command_id

    def append_native(self, command_id: str, stdout: str = "", stderr: str = "") -> None:
        """Append redacted output chunks from stdout/stderr reader threads."""
        with self._lock:
            cmd = next((c for c in self._commands if c["id"] == command_id), None)
            if cmd is None:
                raise KeyError(f"Unknown native command id: {command_id}")
            for name, chunk in ((cmd["stdout_name"], stdout), (cmd["stderr_name"], stderr)):
                if chunk:
                    with (self.directory / "commands" / name).open(
                        "a", encoding="utf-8", newline=""
                    ) as stream:
                        stream.write(self._redact(str(chunk)))
                        stream.flush()
            self._rebuild_index()

    def end_native(self, command_id: str, exit_code: int, duration_seconds: float) -> None:
        """Mark a streamed command complete and force the final index refresh."""
        with self._lock:
            cmd = next((c for c in self._commands if c["id"] == command_id), None)
            if cmd is None:
                raise KeyError(f"Unknown native command id: {command_id}")
            cmd["exit_code"] = int(exit_code)
            cmd["duration_seconds"] = float(duration_seconds)
            cmd["status"] = "completed" if exit_code == 0 else "failed"
            event = {
                "timestamp": _now(),
                "type": "command",
                "message": "Native command completed",
                "status": cmd["status"],
                "command_id": command_id,
                "exit_code": int(exit_code),
            }
            self._events.append(event)
            with (self.directory / "events.jsonl").open("a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
            self._write_run()
            self._rebuild_index(force=True)

    def native(
        self, argv: list[str], stdout: str, stderr: str, exit_code: int, duration_seconds: float
    ) -> None:
        command_id = self.begin_native(argv)
        self.append_native(command_id, stdout, stderr)
        self.end_native(command_id, exit_code, duration_seconds)

    def result(self, data: dict[str, Any]) -> None:
        with self._lock:
            # Round-trip validates JSON serializability and detaches caller mutation.
            frozen = json.loads(json.dumps(data, ensure_ascii=False))
            _atomic_json(self.directory / "result.json", frozen)
            self._record["result"] = frozen
            self._write_run()
            self._rebuild_index()

    def artifact(self, label: str, path: Path) -> None:
        """Link a file or directory contained by this evidence root."""
        resolved = Path(path).expanduser().resolve(strict=True)
        try:
            relative = resolved.relative_to(self.root).as_posix()
        except ValueError as exc:
            raise ValueError("Artifact must resolve inside the evidence root") from exc
        if not (resolved.is_file() or resolved.is_dir()):
            raise ValueError("Artifact must be an existing file or directory")
        with self._lock:
            artifacts = self._record.setdefault("artifacts", [])
            artifacts.append(
                {
                    "label": str(label),
                    "href": quote(relative, safe="/"),
                    "kind": "directory" if resolved.is_dir() else "file",
                }
            )
            self._write_run()
            self._rebuild_index(force=True)

    def finish(self, status: str, error: str | None = None) -> None:
        with self._lock:
            self._record["status"] = str(status)
            self._record["finished_at"] = _now()
            if error is not None:
                self._record["error"] = self._redact(str(error))
            self._write_run()
            self._rebuild_index(force=True)
