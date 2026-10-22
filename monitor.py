#!/usr/bin/env python3
"""Monitor de sites. Uso: monitor.py [check|report] [--config arquivo.json]
check  -> exit 1 se algo falhar. report -> sempre exit 0 (historico)."""
import json, os, re, subprocess, sys, time, urllib.request, urllib.error, datetime, ssl

mode = "check"
cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "checks.json")
args = sys.argv[1:]
while args:
    a = args.pop(0)
    if a in ("check", "report"): mode = a
    elif a == "--config": cfg_path = args.pop(0)
cfg = json.load(open(cfg_path))
DELAY = float(os.environ.get("RETRY_DELAY", cfg["retry_delay"]))
UA = "Mozilla/5.0 (compatible; monitor-sites/1.0; +https://github.com/scrincwb/monitor-sites)"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None

def fetch(url, follow=True):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    op = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
    t = time.time()
    try:
        r = op.open(req, timeout=cfg["timeout"])
        code, body = r.status, r.read()
    except urllib.error.HTTPError as e:
        code, body = e.code, e.read()
    return code, body.decode("utf-8", "replace"), time.time() - t

def evaluate(item, code, body):
    if code != 200: return f"HTTP {code} (esperado 200)"
    for m in cfg["bad_markers"]:
        if m.lower() in body.lower(): return f"marcador proibido encontrado: {m!r}"
    if item.get("json"):
        try: data = json.loads(body)
        except Exception: return "JSON invalido"
        if item.get("json_key") and (not isinstance(data, dict) or item["json_key"] not in data):
            return f"JSON sem chave {item['json_key']!r}"
    if item.get("contains") and item["contains"] not in body: return f"texto esperado ausente: {item['contains']!r}"
    mc = item.get("min_count")
    if mc and body.lower().count(mc["text"].lower()) < mc["n"]: return f"menos de {mc['n']} ocorrencias de {mc['text']!r} (sem resultados?)"
    return None

failures, rows, ssl_rows, sec_rows = [], [], [], []

for item in cfg["urls"]:
    url, times, reasons, ok, best = item["url"], [], [], False, None
    for n in range(cfg["attempts"]):
        try:
            code, body, dt = fetch(url)
            err = evaluate(item, code, body)
        except Exception as e:
            dt, err = cfg["timeout"], f"erro de conexao: {type(e).__name__}: {e}"
        times.append(dt)
        if not err and dt > cfg["max_seconds"]: err = f"lento: {dt:.1f}s > {cfg['max_seconds']}s"
        if not err: ok = True; break
        reasons.append(f"tentativa {n+1}: {err}")
        if n < cfg["attempts"] - 1: time.sleep(DELAY)
    rows.append((url, ok, times, reasons))
    if not ok: failures.append(f"{url} -> {reasons[-1]}")

for url in cfg["must_not_be_200"]:
    res = None
    for n in range(cfg["attempts"]):
        try: code = fetch(url, follow=False)[0]
        except Exception as e: code = f"erro {type(e).__name__}"
        res = code
        if code != 200: break
        if n < cfg["attempts"] - 1: time.sleep(DELAY)
    bad = res == 200
    sec_rows.append((url, res, bad))
    if bad: failures.append(f"{url} -> EXPOSTO (HTTP 200, esperado 403)")

def cert_days(host, connect):
    cmd = ["openssl", "s_client", "-connect", f"{connect or host}:443", "-servername", host, "-verify_hostname", host]
    p = subprocess.run(cmd, input=b"", capture_output=True, timeout=30)
    out = p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")
    m = re.search(r"Verify return code: (\d+) \(([^)]*)\)", out)
    verify = (m.group(1) == "0", m.group(2)) if m else (False, "sem resposta")
    x = subprocess.run(["openssl", "x509", "-noout", "-enddate"], input=p.stdout, capture_output=True)
    d = re.search(r"notAfter=(.*)", x.stdout.decode())
    if not d: raise RuntimeError("certificado nao lido")
    end = datetime.datetime.strptime(d.group(1).strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
    return (end - datetime.datetime.now(datetime.timezone.utc)).days, verify

for h in cfg["ssl_hosts"]:
    label = h.get("label", h["host"])
    try:
        days, (vok, vmsg) = cert_days(h["host"], h.get("connect"))
        problem = None
        if days < cfg["ssl_min_days"]: problem = f"vence em {days} dias"
        elif not vok: problem = f"cadeia/hostname invalido: {vmsg}"
    except Exception as e:
        days, vok, vmsg, problem = None, False, "", f"erro SSL: {e}"
    ssl_rows.append((label, days, vok, problem))
    if problem: failures.append(f"SSL {label} -> {problem}")

now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
L = [f"## {'Monitor' if mode=='check' else 'Relatorio diario'} - {now}", ""]
L.append("**Resultado: " + ("TUDO OK**" if not failures else f"{len(failures)} FALHA(S)**"))
if failures:
    L += ["", "### Falhas"] + [f"- {f}" for f in failures]
L += ["", "### URLs", "", "| URL | Status | Tempo (s) por tentativa |", "|---|---|---|"]
for url, ok, times, reasons in rows:
    L.append(f"| {url} | {'OK' if ok else 'FALHOU'} | {' / '.join(f'{t:.2f}' for t in times)} |")
L += ["", "### Exposicao (nao pode ser 200)", "", "| URL | HTTP | Status |", "|---|---|---|"]
for url, code, bad in sec_rows: L.append(f"| {url} | {code} | {'EXPOSTO' if bad else 'OK'} |")
L += ["", "### Certificados SSL", "", "| Host | Dias para vencer | Cadeia | Status |", "|---|---|---|---|"]
for label, days, vok, problem in ssl_rows:
    L.append(f"| {label} | {days if days is not None else '?'} | {'OK' if vok else 'invalida'} | {problem or 'OK'} |")
text = "\n".join(L) + "\n"
print(text)
p = os.environ.get("GITHUB_STEP_SUMMARY")
if p: open(p, "a").write(text)
for f in failures: print(f"::error::{f}")
sys.exit(1 if (failures and mode == "check") else 0)
