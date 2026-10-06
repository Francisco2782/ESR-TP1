#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
runner.py — automatiza assignments feitos no CORE Network Emulator (CORE dentro de Docker).

    XML  ->  descobre a sessão CORE  ->  executa (vcmd)  ->  terminal real (kitty/konsole)
         ->  highlights  ->  screenshots (spectacle)  ->  Wireshark  ->  results/<alínea>/

Uso:
    ./runner.py assignment_tp1.xml                    # corre tudo (sessão CORE já em Runtime)
    ./runner.py assignment_tp1.xml --only 5.3,6.2     # só algumas alíneas
    ./runner.py assignment_tp1.xml --plan             # valida o XML e mostra o plano
    ./runner.py assignment_tp1.xml --watch            # espera pelo hook de Runtime do CORE
    ./runner.py assignment_tp1.xml --watch --auto     # idem, mas também deteta sessões novas sozinho

Ver README.md para o formato do XML e a instalação do Session Hook.
"""
from __future__ import annotations

import argparse
import ast
import csv
import itertools
import json
import math
import operator
import os
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import textwrap
import time
import ipaddress
import xml.etree.ElementTree as ET
from pathlib import Path
from subprocess import PIPE, STDOUT, DEVNULL

# ----------------------------------------------------------------------------
# Constantes / utilitários
# ----------------------------------------------------------------------------
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
CYAN, GREEN, YELLOW, RED = "\033[36m", "\033[32m", "\033[33m", "\033[31m"
HL_SGR = {  # estilo do highlight no terminal
    "yellow": "\033[1;30;43m", "green": "\033[1;30;42m", "red": "\033[1;97;41m",
    "cyan": "\033[1;30;46m", "magenta": "\033[1;97;45m", "blue": "\033[1;97;44m",
}
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
VAR_RE = re.compile(r"\{\{\s*([A-Za-z_]\w*)\s*(?::([^{}|]*))?(?:\|([^{}]*))?\}\}")

STEP_TAGS = {"Node", "Link", "Sleep", "Tcpdump", "Timeline", "Stop", "Screenshot", "Manual",
             "Ask", "Wireshark", "Measure", "Compute", "Set", "Table", "IOGraph", "Repeat", "Pull"}
DOC_TAGS = {"Question", "Evidence", "Title", "Description", "Note"}
ALLOWED = {
    "Alinea": STEP_TAGS | DOC_TAGS,
    "Tcpdump": STEP_TAGS | DOC_TAGS,
    "Repeat": STEP_TAGS | {"Command", "Highlight"},
    "Node": {"Command", "Highlight", "Repeat", "Sleep"},
    "Timeline": {"At"},
    "At": STEP_TAGS,
    "Wireshark": {"File", "Filter", "Color", "Column", "DecodeAs", "Goto"},
    "IOGraph": {"Series", "Ref"},
    "Table": {"Columns", "Row"},
}

LOGF = None


class RunnerError(Exception):
    pass


def log(msg: str, color: str = CYAN) -> None:
    line = f"{color}[runner]{RESET} {msg}"
    print(line, file=sys.stderr, flush=True)
    if LOGF:
        LOGF.write(ANSI_RE.sub("", line) + "\n")
        LOGF.flush()


def sanitize(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s or "").strip("_") or "x"


def clean_text(t) -> str:
    return textwrap.dedent(t or "").strip()


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def clean_output(out: str) -> list[str]:
    out = strip_ansi(out).replace("\r\n", "\n")
    lines = []
    for l in out.split("\n"):
        if "\r" in l:  # barras de progresso (curl, etc.)
            parts = [p for p in l.split("\r") if p.strip()]
            l = parts[-1] if parts else ""
        lines.append(l.rstrip())
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def to_num(s: str):
    try:
        f = float(s)
        return int(f) if re.fullmatch(r"-?\d+", s.strip()) else f
    except ValueError:
        return s


# ----------------------------------------------------------------------------
# Highlights
# ----------------------------------------------------------------------------
class Hl:
    def __init__(self, el: ET.Element, expand):
        pat = expand(clean_text(el.text))
        flags = 0 if el.get("case") == "true" else re.IGNORECASE
        self.rx = re.compile(pat, flags)
        self.mode = el.get("mode", "line")  # line | match
        self.sgr = HL_SGR.get(el.get("color", "yellow"), HL_SGR["yellow"])


def hl_line(line: str, hls: list[Hl]) -> str:
    spans = []
    for h in hls:
        if h.mode == "line":
            if h.rx.search(line):
                return f"{h.sgr}{line}{RESET}"
        else:
            for m in h.rx.finditer(line):
                if m.end() > m.start():
                    spans.append((m.start(), m.end(), h.sgr))
    if not spans:
        return line
    spans.sort()
    out, pos = [], 0
    for s, e, sgr in spans:
        if s < pos:
            continue
        out.append(line[pos:s])
        out.append(f"{sgr}{line[s:e]}{RESET}")
        pos = e
    out.append(line[pos:])
    return "".join(out)


# ----------------------------------------------------------------------------
# Expressões seguras (Compute)
# ----------------------------------------------------------------------------
_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.Div: operator.truediv, ast.Pow: operator.pow, ast.Mod: operator.mod,
        ast.FloorDiv: operator.floordiv}
_FUNCS = {"mean": lambda *a: sum(a) / len(a), "round": round, "min": min, "max": max,
          "sum": lambda *a: sum(a), "abs": abs, "sqrt": math.sqrt}


def safe_eval(expr: str, names: dict):
    def ev(n):
        if isinstance(n, ast.Expression):
            return ev(n.body)
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)):
            return n.value
        if isinstance(n, ast.Name):
            if n.id not in names:
                raise RunnerError(f"Compute: variável '{n.id}' não definida")
            try:
                return float(names[n.id])
            except (TypeError, ValueError):
                raise RunnerError(f"Compute: variável '{n.id}' não é numérica ({names[n.id]!r})")
        if isinstance(n, ast.BinOp) and type(n.op) in _OPS:
            return _OPS[type(n.op)](ev(n.left), ev(n.right))
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, (ast.USub, ast.UAdd)):
            return -ev(n.operand) if isinstance(n.op, ast.USub) else ev(n.operand)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in _FUNCS:
            return _FUNCS[n.func.id](*[ev(a) for a in n.args])
        raise RunnerError(f"Compute: expressão não permitida: {expr}")
    return ev(ast.parse(expr, mode="eval"))


# ----------------------------------------------------------------------------
# PCAP (parser mínimo para estatísticas e gráficos de débito)
# ----------------------------------------------------------------------------
def read_pcap(path: Path) -> list[tuple[float, int]]:
    data = path.read_bytes()
    m = data[:4]
    if m in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end, nano = "<", m == b"\x4d\x3c\xb2\xa1"
    elif m in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end, nano = ">", m == b"\xa1\xb2\x3c\x4d"
    elif m == b"\x0a\x0d\x0d\x0a":  # pcapng -> tshark
        r = subprocess.run(["tshark", "-r", str(path), "-T", "fields", "-e", "frame.time_epoch",
                            "-e", "frame.len"], capture_output=True, text=True)
        if r.returncode:
            raise RunnerError(f"pcapng requer tshark: {r.stderr.strip()}")
        return [(float(a), int(b)) for a, b in (l.split() for l in r.stdout.splitlines() if l.strip())]
    else:
        raise RunnerError(f"formato de captura desconhecido: {path}")
    pk, off = [], 24
    while off + 16 <= len(data):
        sec, frac, incl, orig = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16 + incl
        pk.append((sec + frac / (1e9 if nano else 1e6), orig))
    if not pk:
        raise RunnerError(f"captura vazia: {path}")
    return pk


# ----------------------------------------------------------------------------
# Topologia CORE (session-deployed.xml)
# ----------------------------------------------------------------------------
class Topology:
    def __init__(self):
        self.names: set[str] = set()
        self.links: list[tuple[str, str, str, str]] = []  # (nodeA, ifA, nodeB, ifB)

    @staticmethod
    def parse(xml_text: str) -> "Topology":
        root = ET.fromstring(xml_text)
        t, idmap = Topology(), {}
        for el in root.iter():
            tag = el.tag.split("}")[-1]
            if tag in ("device", "network", "node") and el.get("name") and el.get("id") is not None:
                idmap[el.get("id")] = el.get("name")
                t.names.add(el.get("name"))
        for el in root.iter():
            if el.tag.split("}")[-1] != "link":
                continue
            n1, n2 = idmap.get(el.get("node1")), idmap.get(el.get("node2"))
            i1 = i2 = None
            for ch in el:
                tg = ch.tag.split("}")[-1]
                nm = ch.get("name") or (f"eth{ch.get('id')}" if ch.get("id") is not None else None)
                if tg in ("iface1", "interface_one", "interface1"):
                    i1 = nm
                elif tg in ("iface2", "interface_two", "interface2"):
                    i2 = nm
            if n1 and n2:
                t.links.append((n1, i1, n2, i2))
        return t

    def iface(self, node: str, peer: str):
        for a, ia, b, ib in self.links:
            if a == node and b == peer and ia:
                return ia
            if b == node and a == peer and ib:
                return ib
        return None

    def has_link(self, x: str, y: str) -> bool:
        return any({a, b} == {x, y} for a, _, b, _ in self.links)


# ----------------------------------------------------------------------------
# Gestão de janelas (KDE: kdotool em Wayland / xdotool em X11)
# ----------------------------------------------------------------------------
class WM:
    def __init__(self):
        self.tool = "kdotool" if shutil.which("kdotool") else ("xdotool" if shutil.which("xdotool") else None)

    @staticmethod
    def _run(args):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=10)
            return r.returncode, r.stdout.strip()
        except Exception:
            return 1, ""

    def find(self, pattern: str):
        if not self.tool:
            return None
        if self.tool == "kdotool":
            rc, out = self._run(["kdotool", "search", "--name", pattern])
            if rc or not out:
                rc, out = self._run(["kdotool", "search", pattern])
        else:
            rc, out = self._run(["xdotool", "search", "--onlyvisible", "--name", pattern])
        ids = [l.strip() for l in out.splitlines() if l.strip()]
        return ids[-1] if ids else None

    def wait(self, pattern: str, timeout: float = 20):
        if not self.tool:
            time.sleep(min(timeout, 4))
            return None
        end = time.time() + timeout
        while time.time() < end:
            wid = self.find(pattern)
            if wid:
                return wid
            time.sleep(0.5)
        return None

    def activate(self, wid):
        if wid and self.tool:
            self._run([self.tool, "windowactivate", wid])

    def resize(self, wid, w, h):
        if wid and self.tool:
            self._run([self.tool, "windowsize", wid, str(w), str(h)])


# ----------------------------------------------------------------------------
# Estado por alínea
# ----------------------------------------------------------------------------
class Al:
    def __init__(self, el: ET.Element, results: Path):
        self.el = el
        self.id = el.get("id")
        self.title = el.get("title", "")
        self.dir = results / sanitize(self.id)
        self.files: list[Path] = []
        self.used: set[str] = set()
        self.failed = False

    def unique(self, base: str) -> str:
        b, n = base, 1
        while b in self.used:
            n += 1
            b = f"{base}_{n}"
        self.used.add(b)
        return b


# ----------------------------------------------------------------------------
# Runner
# ----------------------------------------------------------------------------
class Runner:
    # ---------------------------------------------------------------- init
    def __init__(self, args):
        self.args = args
        self.xml_path = Path(args.xml).resolve()
        self.base = self.xml_path.parent
        self.root = ET.parse(self.xml_path).getroot()
        self.validate()
        self.results = Path(args.results).resolve() if args.results else (self.base / self.cfg("Results", default="results"))
        self.group = args.group or self.root.get("group") or "PL00"
        self.profiles, self.profile = {}, None
        digit = (re.search(r"(\d)\D*$", self.group) or [None, "0"])[1]
        for p in self.root.findall("Profiles/Profile"):
            self.profiles[p.get("id")] = {k: p.get(k) for k in ("bw", "delay", "loss")}
            if digit in p.get("digits", "").split():
                self.profile = p.get("id")
        if args.profile:
            self.profile = args.profile
        pr = self.profiles.get(self.profile, {})
        self.vars: dict = {"GROUP": self.group, "PROFILE": self.profile or "?",
                           "PROFILE_BW": pr.get("bw", ""), "PROFILE_DELAY": pr.get("delay", ""),
                           "PROFILE_LOSS": pr.get("loss", "")}
        self.preset = set(self.vars)
        self.marks: dict = {}
        self.bg: dict = {}
        self.counter = itertools.count(1)
        self.wm = WM()
        self.term = args.terminal or self.cfg("Terminal", "name", "auto")
        if self.term == "auto":
            self.term = "kitty" if shutil.which("kitty") else "konsole"
        self.term_cols = int(self.cfg("Terminal", "cols", "150"))
        self.term_maxrows = int(self.cfg("Terminal", "maxrows", "55"))
        self.font = self.cfg("Terminal", "fontsize", "11")
        self.shot_delay = float(self.cfg("Screenshot", "delay", "0.8"))
        self.ws_size = (int(self.cfg("Wireshark", "width", "1600")), int(self.cfg("Wireshark", "height", "900")))
        self.prompt_tpl = self.cfg("Prompt", default="root@{node}:~# ")
        self.preamble_tpl = self.cfg("Preamble", default="")
        self.iface_cache: dict = {}
        self.topo = None
        self.container = self.session = self.tp1_root = self.display = None

    def cfg(self, tag, attr=None, default=""):
        el = self.root.find(f"Settings/{tag}")
        if el is None:
            return default
        if attr:
            return el.get(attr, default)
        return clean_text(el.text) or default

    def validate(self):
        for el in self.root.iter():
            if el.tag in ALLOWED:
                for ch in el:
                    if ch.tag not in ALLOWED[el.tag]:
                        raise RunnerError(f"<{ch.tag}> não é permitido dentro de <{el.tag}> "
                                          f"(alínea {self.owner_id(el)})")

    def owner_id(self, el):
        for a in self.root.findall("Alinea"):
            if el is a or el in a.iter():
                return a.get("id")
        return "?"

    # ---------------------------------------------------------- variáveis
    def expand(self, text, local=None) -> str:
        if text is None:
            return ""
        scope = {**self.vars, **(local or {})}

        def rep(m):
            name, spec, default = m.group(1), m.group(2), m.group(3)
            if name not in scope:
                if default is not None:
                    return default
                raise RunnerError(f"variável {{{{{name}}}}} não definida (ainda não foi calculada?)")
            v = scope[name]
            if spec:
                try:
                    return format(v, spec.strip())
                except (ValueError, TypeError):
                    pass
            return f"{v:.6g}" if isinstance(v, float) else str(v)
        return VAR_RE.sub(rep, text)

    def save_vars(self):
        self.results.mkdir(parents=True, exist_ok=True)
        data = {"vars": {k: v for k, v in self.vars.items() if k not in self.preset}, "marks": self.marks}
        (self.results / "vars.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def load_vars(self):
        f = self.results / "vars.json"
        if f.exists():
            try:
                d = json.loads(f.read_text(encoding="utf-8"))
                for k, v in d.get("vars", {}).items():
                    self.vars.setdefault(k, v)
                self.marks.update(d.get("marks", {}))
            except Exception:
                pass

    # ------------------------------------------------------------- docker
    @staticmethod
    def _run(cmd, timeout=300, input_text=None):
        try:
            p = subprocess.run(cmd, input=input_text, stdout=PIPE, stderr=STDOUT, text=True,
                               errors="replace", timeout=timeout)
            return p.returncode, p.stdout
        except subprocess.TimeoutExpired as e:
            out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            return 124, out + f"\n[timeout após {timeout:g}s]"
        except FileNotFoundError as e:
            return 127, str(e)

    def dexec(self, args, timeout=300, input_text=None):
        cmd = ["docker", "exec"]
        if input_text is not None:
            cmd.append("-i")
        if self.display:
            cmd += ["-e", f"DISPLAY={self.display}"]
        return self._run(cmd + [self.container] + args, timeout, input_text)

    def csh(self, script, timeout=30) -> str:
        return self.dexec(["sh", "-c", script], timeout)[1]

    def node_run(self, node, script, timeout=300):
        if node == "@host":
            return self._run(["bash", "-c", script], timeout)
        if node == "@container":
            return self.dexec(["bash", "-c", script], timeout)
        return self.dexec(["vcmd", "-c", f"{self.session}/{node}", "--", "bash", "-c", script], timeout)

    def preamble(self, node) -> str:
        if node == "@host":
            return ""
        return self.expand(self.preamble_tpl) + "\n"

    # ------------------------------------------------- setup (CORE/Docker)
    def find_container(self) -> str:
        want = self.args.container or self.cfg("Container")
        rc, out = self._run(["docker", "ps", "--format", "{{.Names}}"], 20)
        if rc:
            raise RunnerError(f"docker ps falhou: {out.strip()}")
        names = [n for n in out.split() if n]
        if want:
            if want not in names:
                raise RunnerError(f"contentor '{want}' não está a correr (ativos: {names})")
            return want
        cand = [n for n in names if "core" in n.lower()] or (names if len(names) == 1 else [])
        if len(cand) != 1:
            raise RunnerError(f"não consegui escolher o contentor ({names}); use --container")
        return cand[0]

    def topology_spec(self):
        spec = self.root.find("Topology")
        names, links, ifaces = set(), [], {}
        if spec is not None:
            for n in spec.findall("Node"):
                names.add(n.get("name"))
            for l in spec.findall("Link"):
                links.append((l.get("a"), l.get("b")))
            for i in spec.findall("Iface"):
                ifaces[(i.get("node"), i.get("to"))] = i.get("name")
        return names, links, ifaces

    def find_session(self):
        names, links, _ = self.topology_spec()
        out = self.csh('for d in /tmp/pycore.*; do [ -d "$d" ] && echo "$(stat -c %Y "$d") $d"; done')
        cands = sorted((l.split(None, 1) for l in out.splitlines() if l.strip()), key=lambda x: -int(x[0]))
        if not cands:
            raise RunnerError("nenhuma sessão /tmp/pycore.* no contentor — carregue Run no CORE")
        fallback = None
        for _, d in cands:
            socks = all(self.csh(f'[ -S "{d}/{n}" ] && echo y').strip() == "y" for n in names) if names else True
            if not socks:
                continue
            xml = self.csh(f'cat "{d}/session-deployed.xml" 2>/dev/null', 30)
            try:
                topo = Topology.parse(xml)
            except ET.ParseError:
                fallback = fallback or (d, None)
                continue
            if names <= topo.names and all(topo.has_link(a, b) for a, b in links):
                return d, topo
            log(f"{d}: XML da sessão não corresponde à topologia pedida", YELLOW)
        if fallback:
            log("sem session-deployed.xml utilizável: a usar a sessão pelos sockets", YELLOW)
            return fallback
        raise RunnerError("nenhuma sessão CORE corresponde à topologia do assignment")

    def find_tp1_root(self) -> str:
        forced = self.cfg("TP1Root")
        if forced:
            return forced
        out = self.csh("find /root /home -maxdepth 6 -type f -path '*/esr/TP1/scripts/tp1-env.sh' -print -quit 2>/dev/null")
        p = out.strip().splitlines()
        if not p:
            raise RunnerError("tp1-env.sh não encontrado no contentor (defina <TP1Root> em Settings)")
        return str(Path(p[0]).parent.parent)

    def setup(self, forced_session=None):
        self.container = self.find_container()
        self.display = self.args.display or self.cfg("Display") or os.environ.get("DISPLAY", ":0")
        if forced_session:
            self.session = forced_session
            xml = self.csh(f'cat "{forced_session}/session-deployed.xml" 2>/dev/null', 30)
            try:
                self.topo = Topology.parse(xml)
            except ET.ParseError:
                self.topo = None
        elif self.args.session:
            self.session = self.args.session
            try:
                self.topo = Topology.parse(self.csh(f'cat "{self.session}/session-deployed.xml"', 30))
            except ET.ParseError:
                self.topo = None
        else:
            self.session, self.topo = self.find_session()
        self.tp1_root = self.find_tp1_root()
        self.vars.update({"SESSION": self.session, "TP1_ROOT": self.tp1_root, "DISPLAY": self.display,
                          "RESULTS": str(self.results)})
        log(f"contentor={self.container}  sessão={self.session}  TP1_ROOT={self.tp1_root}  grupo={self.group}  perfil={self.profile}", GREEN)

    # ------------------------------------------------------------ interfaces
    def resolve_iface(self, node, spec) -> str:
        if not spec.startswith("to:"):
            return spec
        peer = spec[3:]
        key = (node, peer)
        if key in self.iface_cache:
            return self.iface_cache[key]
        _, _, over = self.topology_spec()
        i = over.get(key) or (self.topo.iface(node, peer) if self.topo else None) or self.by_subnet(node, peer)
        if not i:
            raise RunnerError(f"não consegui determinar a interface de {node} para {peer}; "
                              f"adicione <Iface node=\"{node}\" to=\"{peer}\" name=\"ethX\"/> em <Topology>")
        self.iface_cache[key] = i
        return i

    def by_subnet(self, a, b):
        def nets(n):
            _, out = self.node_run(n, "ip -o -4 addr show", 20)
            res = {}
            for l in out.splitlines():
                m = re.match(r"\d+:\s+(\S+)\s+inet\s+(\S+)", l)
                if m:
                    try:
                        res[ipaddress.ip_interface(m.group(2)).network] = m.group(1).split("@")[0]
                    except ValueError:
                        pass
            return res
        na, nb = nets(a), nets(b)
        for net, ifa in na.items():
            if net in nb:
                return ifa
        return None

    # -------------------------------------------------- processos de fundo
    def bg_start(self, node, bid, cmd, wait=1.0, ready=None, ready_timeout=15):
        if node == "@host":
            raise RunnerError("background não suportado em @host")
        if bid in self.bg:
            raise RunnerError(f"processo de fundo '{bid}' já existe")
        script = self.preamble(node) + cmd + "\n"
        rc, out = self.dexec(["sh", "-c", f"mkdir -p /tmp/runner && cat > /tmp/runner/{bid}.sh"], 20, script)
        if rc:
            raise RunnerError(f"não consegui escrever script de fundo: {out}")
        launch = (f"mkdir -p /tmp/runner; ( setsid nohup bash -c 'echo $$ > /tmp/runner/{bid}.pid; "
                  f"exec bash /tmp/runner/{bid}.sh' > /tmp/runner/{bid}.log 2>&1 < /dev/null & ); "
                  f"sleep 0.4; cat /tmp/runner/{bid}.pid")
        rc, out = self.node_run(node, launch, 30)
        pid = (out.strip().splitlines() or [""])[-1]
        if not pid.isdigit():
            raise RunnerError(f"falha a lançar '{bid}' em {node}: {out}")
        self.bg[bid] = {"node": node, "pid": pid, "keep": False}
        if ready:
            end = time.time() + ready_timeout
            while time.time() < end:
                _, o = self.node_run(node, f"grep -Eq {shlex.quote(ready)} /tmp/runner/{bid}.log && echo OK", 20)
                if "OK" in o:
                    break
                time.sleep(0.5)
            else:
                log(f"'{bid}': padrão ready '{ready}' não apareceu em {ready_timeout}s (a continuar)", YELLOW)
        time.sleep(wait)
        return pid

    def bg_log(self, bid, n=12) -> str:
        info = self.bg.get(bid)
        if not info:
            return ""
        return self.node_run(info["node"], f"tail -n {n} /tmp/runner/{bid}.log", 20)[1]

    def bg_stop(self, bid, sig="TERM"):
        info = self.bg.pop(bid, None)
        if not info:
            return
        pid = info["pid"]
        script = (f"kill -{sig} -- -{pid} 2>/dev/null; for i in $(seq 1 40); do kill -0 {pid} 2>/dev/null || exit 0; "
                  f"sleep 0.25; done; kill -KILL -- -{pid} 2>/dev/null; exit 0")
        self.node_run(info["node"], script, 30)

    def cleanup_bg(self, force=False):
        for bid in list(self.bg):
            if force or not self.bg[bid]["keep"]:
                self.bg_stop(bid)

    # ------------------------------------------------------------ terminal
    def prompt(self, node) -> str:
        if node == "@host":
            return "user@host:~$ "
        if node == "@container":
            return "root@core:~# "
        return self.prompt_tpl.replace("{node}", node)

    def banner(self, al: Al, what: str) -> list[str]:
        t = f" {self.group} · Perfil {self.profile} · Alínea {al.id} · {what} "
        bar = "=" * max(60, len(t))
        return [f"{CYAN}{BOLD}{bar}{RESET}", f"{CYAN}{BOLD}{t}{RESET}", f"{CYAN}{BOLD}{bar}{RESET}", ""]

    def render_cmd(self, node, text, out_lines, rc, hls, head=None, tail=None) -> list[str]:
        cl = text.split("\n")
        lines = [f"{BOLD}{GREEN}{self.prompt(node)}{RESET}{BOLD}{cl[0]}{RESET}"]
        lines += [f"{BOLD}> {x}{RESET}" for x in cl[1:]]
        shown = list(out_lines)
        if head and len(shown) > head:
            shown = shown[:head] + [f"{DIM}[... {len(out_lines) - head} linhas omitidas ...]{RESET}"]
        elif tail and len(shown) > tail:
            shown = [f"{DIM}[... {len(out_lines) - tail} linhas omitidas ...]{RESET}"] + shown[-tail:]
        for l in shown:
            lines.append(l if l.startswith(DIM) else hl_line(l, hls))
        if rc not in (0, None):
            lines.append(f"{DIM}{RED}[exit {rc}]{RESET}")
        lines.append("")
        return lines

    def spectacle(self, png: Path) -> bool:
        png.parent.mkdir(parents=True, exist_ok=True)
        if png.exists():
            png.unlink()
        time.sleep(self.shot_delay)
        for _ in range(3):
            try:
                subprocess.run(["spectacle", "--activewindow", "--background", "--nonotify", "--output", str(png)],
                               stdout=DEVNULL, stderr=DEVNULL, timeout=40)
            except Exception as e:
                log(f"spectacle falhou: {e}", RED)
                return False
            for _ in range(24):
                if png.exists() and png.stat().st_size > 0:
                    return True
                time.sleep(0.25)
        log(f"screenshot não criada: {png}", RED)
        return False

    @staticmethod
    def _kill(proc):
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                pass

    def screenshot_terminal(self, lines: list[str], png: Path) -> bool:
        tmp = self.results / ".tmp"
        tmp.mkdir(parents=True, exist_ok=True)
        tf = tmp / f"transcript_{os.getpid()}.ansi"
        tf.write_text("\033[?25l" + "\n".join(lines) + "\n", encoding="utf-8")
        cols = self.term_cols
        rows = sum(max(1, math.ceil(len(strip_ansi(l)) / cols)) for l in lines) + 2
        rows = max(8, min(rows, self.term_maxrows))
        title = f"RUNNER-{os.getpid()}-{next(self.counter)}"
        prog = f"cat {shlex.quote(str(tf))}; sleep 600"
        if self.term == "kitty":
            cmd = ["kitty", "--title", title, "-o", f"initial_window_width={cols}c",
                   "-o", f"initial_window_height={rows}c", "-o", "remember_window_size=no",
                   "-o", "confirm_os_window_close=0", "-o", f"font_size={self.font}", "sh", "-c", prog]
        else:
            cmd = ["konsole", "--separate", "--hide-menubar", "--hide-tabbar", "-p", f"tabtitle={title}",
                   "-p", f"TerminalColumns={cols}", "-p", f"TerminalRows={rows}", "-e", "sh", "-c", prog]
        proc = subprocess.Popen(cmd, stdout=DEVNULL, stderr=DEVNULL, start_new_session=True)
        try:
            wid = self.wm.wait(re.escape(title), 20)
            if wid is None and self.wm.tool:
                log("janela do terminal não encontrada (screenshot da janela ativa)", YELLOW)
            time.sleep(1.0)
            self.wm.activate(wid)
            ok = self.spectacle(png)
        finally:
            self._kill(proc)
            tf.unlink(missing_ok=True)
        return ok

    def shoot_gui(self, args, pattern, png: Path, size=None, load=3.0) -> bool:
        proc = subprocess.Popen(args, stdout=DEVNULL, stderr=DEVNULL, start_new_session=True)
        try:
            wid = self.wm.wait(pattern, 40)
            if wid is None and self.wm.tool:
                log(f"janela '{pattern}' não encontrada", YELLOW)
            time.sleep(load)
            if size:
                self.wm.resize(wid, *size)
            time.sleep(1.0)
            self.wm.activate(wid)
            return self.spectacle(png)
        finally:
            self._kill(proc)

    # ------------------------------------------------------------- passos
    def run_steps(self, parent, al: Al):
        for el in parent:
            if el.tag in DOC_TAGS or el.tag == "Highlight":
                continue
            fn = getattr(self, "step_" + el.tag.lower(), None)
            if fn is None:
                raise RunnerError(f"elemento <{el.tag}> não suportado aqui")
            fn(el, al)

    # ---- Node ------------------------------------------------------------
    def flatten(self, parent, loc):
        for ch in parent:
            if ch.tag == "Command":
                yield ("cmd", ch, loc)
            elif ch.tag == "Sleep":
                yield ("sleep", ch, loc)
            elif ch.tag == "Repeat":
                var, n = ch.get("var", "i"), int(self.expand(ch.get("times", "1"), loc))
                for i in range(1, n + 1):
                    yield from self.flatten(ch, {**loc, var: i})

    def step_node(self, el, al: Al):
        node = el.get("name")
        hls = [Hl(h, self.expand) for h in el.findall("Highlight")]
        items = list(self.flatten(el, {}))
        shot = el.get("screenshot", "true") != "false"
        base = al.unique(sanitize(node.lstrip("@")) + (f"_{sanitize(el.get('shot'))}" if el.get("shot") else ""))
        lines = self.banner(al, node)
        raw = []
        log(f"[{al.id}] {node}: {len(items)} comando(s)")
        for kind, cel, loc in items:
            if kind == "sleep":
                self.sleep(float(self.expand(cel.get("seconds") or cel.text, loc)))
                continue
            text = self.expand(clean_text(cel.text), loc)
            head = int(cel.get("head")) if cel.get("head") else None
            tail = int(cel.get("tail")) if cel.get("tail") else None
            if cel.get("background") == "true":
                bid = sanitize(self.expand(cel.get("id", f"bg{next(self.counter)}"), loc))
                self.bg_start(node, bid, text, float(cel.get("wait", "1")), cel.get("ready"),
                              float(cel.get("ready_timeout", "15")))
                self.bg[bid]["keep"] = cel.get("keep") == "true"
                out_l = clean_output(self.bg_log(bid)) + [f"[1] {self.bg[bid]['pid']}"]
                rc = 0
                text_disp = text + " &"
            else:
                rc, out = self.node_run(node, self.preamble(node) + text, float(cel.get("timeout", "300")))
                out_l = clean_output(out)
                text_disp = text
                if cel.get("var"):
                    rx = self.expand(cel.get("regex", r"(.+)"), loc)
                    m = re.search(rx, "\n".join(out_l), re.M)
                    if m:
                        v = to_num((m.group(1) if m.groups() else m.group(0)).strip())
                        self.vars[self.expand(cel.get("var"), loc)] = v
                        log(f"   {self.expand(cel.get('var'), loc)} = {v}")
                    else:
                        log(f"   var '{cel.get('var')}': regex '{rx}' sem correspondência", YELLOW)
                if rc not in (0, None) and cel.get("allow_fail") != "true":
                    log(f"   comando terminou com exit {rc}: {text.splitlines()[0]}", YELLOW)
            lines += self.render_cmd(node, text_disp, out_l, rc, hls, head, tail)
            raw.append(f"{self.prompt(node)}{text_disp}\n" + "\n".join(out_l) + "\n")
        txt = al.dir / f"{base}.txt"
        txt.parent.mkdir(parents=True, exist_ok=True)
        txt.write_text("\n".join(raw), encoding="utf-8")
        al.files.append(txt)
        if shot:
            png = al.dir / f"{base}.png"
            if self.screenshot_terminal(lines, png):
                al.files.append(png)
                log(f"   ✓ {png.relative_to(self.results)}", GREEN)

    # ---- Link (largura de banda / atraso / perda) -----------------------
    @staticmethod
    def norm(v, unit):
        v = (v or "").strip().lower().replace("/s", "").replace(" ", "")
        return f"{v}{unit}" if re.fullmatch(r"[\d.]+", v) else v

    def step_link(self, el, al: Al):
        a, b = el.get("a", "routerA"), el.get("b", "routerB")
        prof = el.get("profile")
        if prof:
            p = self.profiles.get(self.profile if prof == "auto" else prof)
            if not p:
                raise RunnerError(f"perfil '{prof}' inexistente")
            bw, delay, loss = p["bw"], p["delay"], p["loss"]
        else:
            bw, delay, loss = el.get("bw"), el.get("delay"), el.get("loss")
        bw, delay, loss = self.norm(bw, "mbit"), self.norm(delay, "ms"), self.norm(loss, "%")
        lines = self.banner(al, f"ligação {a} <-> {b}")
        lines.append(f"{DIM}# parâmetros aplicados: largura de banda={bw}  atraso/sentido={delay}  perda={loss}{RESET}\n")
        hls = [Hl(ET.fromstring("<H>netem|rate|delay|loss</H>"), self.expand)]
        ifs = {}
        for n, peer in ((a, b), (b, a)):
            i = self.resolve_iface(n, f"to:{peer}")
            ifs[n] = i
            rc, out = self.node_run(n, f"tc qdisc replace dev {i} root netem delay {delay} loss {loss} rate {bw}", 30)
            if rc:
                raise RunnerError(f"tc falhou em {n}/{i}: {out.strip()}")
        self.sleep(float(el.get("settle", "1")))
        for n in (a, b):
            cmd = f"tc qdisc show dev {ifs[n]}"
            rc, out = self.node_run(n, cmd, 30)
            lines += self.render_cmd(n, cmd, clean_output(out), rc, hls)
        log(f"[{al.id}] link {a}<->{b}: bw={bw} delay={delay} loss={loss}  ({a}:{ifs[a]} {b}:{ifs[b]})")
        if el.get("var"):
            v = el.get("var")
            self.vars.update({f"{v}_bw": bw, f"{v}_delay": delay, f"{v}_loss": loss})
        self.results.mkdir(parents=True, exist_ok=True)
        new = not (self.results / "link_log.csv").exists()
        with open(self.results / "link_log.csv", "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["timestamp", "alinea", "a", "if_a", "b", "if_b", "bw", "delay", "loss"])
            w.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), al.id, a, ifs[a], b, ifs[b], bw, delay, loss])
        if el.get("screenshot", "false") == "true":
            png = al.dir / f"{al.unique('Link_' + sanitize(el.get('var', 'cfg')))}.png"
            if self.screenshot_terminal(lines, png):
                al.files.append(png)

    # ---- tempo -----------------------------------------------------------
    @staticmethod
    def sleep(s):
        if s > 0:
            log(f"   a aguardar {s:g}s")
            time.sleep(s)

    def step_sleep(self, el, al):
        self.sleep(float(self.expand(el.get("seconds") or el.text)))

    def step_repeat(self, el, al):
        var = el.get("var", "i")
        for i in range(1, int(self.expand(el.get("times", "1"))) + 1):
            self.vars[var] = i
            self.run_steps(el, al)

    def step_timeline(self, el, al):
        name = el.get("name", "t")
        t0 = time.time()
        marks = []
        for a in sorted(el.findall("At"), key=lambda x: float(x.get("t"))):
            t = float(a.get("t"))
            self.sleep(t0 + t - time.time())
            label = self.expand(a.get("label", f"t={t:g}s"))
            marks.append((time.time(), label))
            log(f"[{al.id}] timeline '{name}' t={t:g}s: {label}")
            self.run_steps(a, al)
        if el.get("duration"):
            self.sleep(t0 + float(el.get("duration")) - time.time())
        self.marks[name] = marks
        al.dir.mkdir(parents=True, exist_ok=True)
        f = al.dir / f"marks_{sanitize(name)}.csv"
        with open(f, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["epoch", "t_rel_s", "label"])
            for ts, lb in marks:
                w.writerow([f"{ts:.3f}", f"{ts - t0:.1f}", lb])
        al.files.append(f)

    def step_stop(self, el, al):
        if el.get("all") == "true":
            self.cleanup_bg(force=True)
            return
        if el.get("ref"):
            self.bg_stop(sanitize(el.get("ref")), el.get("signal", "TERM"))
        if el.get("pattern"):
            self.node_run(el.get("node", "@container"), f"pkill -{el.get('signal', 'TERM')} -f {shlex.quote(el.get('pattern'))}; true", 20)

    # ---- capturas ----------------------------------------------------------
    def pull(self, cpath: str, al: Al, sub="captures") -> Path:
        dest = al.dir / sub
        dest.mkdir(parents=True, exist_ok=True)
        rc, out = self._run(["docker", "cp", f"{self.container}:{cpath}", str(dest) + "/"], 180)
        if rc:
            raise RunnerError(f"docker cp falhou ({cpath}): {out.strip()}")
        return dest / Path(cpath).name

    def step_pull(self, el, al):
        p = self.pull(self.expand(el.get("from")), al)
        if el.get("var"):
            self.vars[el.get("var")] = str(p)
        al.files.append(p)

    def step_tcpdump(self, el, al: Al):
        node = el.get("node")
        iface = self.resolve_iface(node, self.expand(el.get("iface")))
        fname = self.expand(el.get("file"))
        flt = self.expand(el.get("filter", ""))
        tmp = f"/tmp/runner_{sanitize(fname)}"
        bid = "tcpdump_" + sanitize(fname)
        cmd = f"tcpdump -i {iface} -s 0 -U -Z root -w {tmp}" + (f' "{flt}"' if flt else "")
        log(f"[{al.id}] tcpdump em {node}/{iface}: {flt or '(sem filtro)'} -> {fname}")
        self.bg_start(node, bid, cmd, float(el.get("settle", "1")), "listening on", 15)
        try:
            self.run_steps(el, al)
        finally:
            self.sleep(float(el.get("grace", "1.5")))
            tail = self.bg_log(bid, 4)
            self.bg_stop(bid, "TERM")
        dest = f"{self.tp1_root}/results/{fname}"
        rc, out = self.node_run(node, f"mkdir -p {self.tp1_root}/results && mv {tmp} {dest} && ls -l {dest}", 30)
        if rc:
            raise RunnerError(f"captura não foi guardada: {out.strip()}")
        host = self.pull(dest, al)
        al.files.append(host)
        (al.dir / "logs").mkdir(parents=True, exist_ok=True)
        (al.dir / "logs" / f"{fname}.tcpdump.log").write_text(tail, encoding="utf-8")
        if el.get("var"):
            self.vars[el.get("var")] = str(host)
        log(f"   ✓ captura {host.relative_to(self.results)} ({host.stat().st_size} bytes)", GREEN)

    # ---- screenshots de janelas GUI -------------------------------------
    def step_screenshot(self, el, al: Al):
        pat = self.expand(el.get("window"))
        name = al.unique(sanitize(self.expand(el.get("name", "janela"))))
        wid = self.wm.wait(pat, float(el.get("timeout", "20")))
        if wid is None and self.wm.tool:
            log(f"[{al.id}] janela '{pat}' não encontrada: screenshot ignorada", YELLOW)
            return
        if el.get("size") and wid:
            w, h = el.get("size").lower().split("x")
            self.wm.resize(wid, int(w), int(h))
        self.wm.activate(wid)
        time.sleep(float(el.get("delay", "0.5")))
        png = al.dir / f"{name}.png"
        if self.spectacle(png):
            al.files.append(png)
            log(f"   ✓ {png.relative_to(self.results)}", GREEN)

    def step_wireshark(self, el, al: Al):
        name = sanitize(el.get("name", "capture"))
        fe = el.find("File")
        if fe is None:
            raise RunnerError("<Wireshark> sem <File>")
        fpath = self.expand(clean_text(fe.text))
        if fe.get("container") == "true":
            host = self.pull(fpath, al)
        else:
            host = Path(fpath)
            if not host.is_absolute():
                host = self.results / host
        if not host.exists():
            raise RunnerError(f"captura não existe: {host}")
        filters = [(f.get("name"), self.expand(clean_text(f.text))) for f in el.findall("Filter")] or [(None, "")]
        colors = el.findall("Color")
        decode = [self.expand(clean_text(d.text)) for d in el.findall("DecodeAs")]
        cols = [(c.get("title", clean_text(c.text)), clean_text(c.text)) for c in el.findall("Column")]
        goto = el.find("Goto")
        prof = self.make_ws_profile(colors) if colors else None
        try:
            for k, (fname, flt) in enumerate(filters):
                args = ["wireshark"]
                if prof:
                    args += ["-C", prof[0]]
                args += ["-r", str(host), "-o", "gui.update.enabled:FALSE"]
                if flt:
                    args += ["-Y", flt]
                for d in decode:
                    args += ["-d", d]
                if cols:
                    base_cols = [("No.", "%m"), ("Time", "%t"), ("Source", "%s"), ("Destination", "%d"),
                                 ("Protocol", "%p"), ("Length", "%L")]
                    base_cols += [(t, f"%Cus:{f}:0:R") for t, f in cols] + [("Info", "%i")]
                    args += ["-o", "gui.column.format:" + ",".join(f'"{t}","{f}"' for t, f in base_cols)]
                if goto is not None:
                    args += ["-g", clean_text(goto.text)]
                suffix = f"_{sanitize(fname)}" if fname else (f"_{k + 1}" if len(filters) > 1 else "")
                png = al.dir / f"Wireshark_{name}{suffix}.png"
                log(f"[{al.id}] wireshark {host.name}  filtro='{flt}'")
                if self.shoot_gui(args, re.escape(host.name) + "|Wireshark", png, self.ws_size, 3.0):
                    al.files.append(png)
                    log(f"   ✓ {png.relative_to(self.results)}", GREEN)
        finally:
            if prof:
                shutil.rmtree(prof[1], ignore_errors=True)

    @staticmethod
    def make_ws_profile(colors):
        name = f"runner-{os.getpid()}"
        d = Path.home() / ".config/wireshark/profiles" / name
        d.mkdir(parents=True, exist_ok=True)

        def h16(h):
            h = h.lstrip("#")
            return ",".join(str(int(h[i:i + 2], 16) * 257) for i in (0, 2, 4))
        lines = ["# gerado por runner.py"]
        for i, c in enumerate(colors):
            flt = " ".join(clean_text(c.text).split())
            lines.append(f"@{c.get('name', f'runner{i}')}@{flt}@[{h16(c.get('bg', 'ffd400'))}][{h16(c.get('fg', '000000'))}]")
        (d / "colorfilters").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return name, d

    # ---- medidas, contas, tabelas, gráficos -----------------------------
    def step_measure(self, el, al: Al):
        pcap = Path(self.expand(el.get("pcap")))
        var = el.get("var")
        pk = read_pcap(pcap)
        t0, tend = pk[0][0], pk[-1][0]
        lo = float(el.get("from", "0"))
        hi = float(el.get("to", str(tend - t0)))
        hi = min(hi, tend - t0)
        sel = [l for t, l in pk if lo <= t - t0 <= hi]
        win = max(hi - lo, 1e-9)
        nbytes = sum(sel)
        bps = 8 * nbytes / win
        self.vars.update({f"{var}_packets": len(sel), f"{var}_bytes": nbytes, f"{var}_duration": win,
                          f"{var}_bps": bps, f"{var}_kbps": bps / 1e3, f"{var}_mbps": bps / 1e6})
        msg = (f"{var}: {len(sel)} pacotes, {nbytes} bytes em [{lo:g}s,{hi:g}s] -> "
               f"{bps / 1e3:.1f} kbit/s ({bps / 1e6:.3f} Mbit/s)")
        log(f"[{al.id}] {msg}")
        al.dir.mkdir(parents=True, exist_ok=True)
        with open(al.dir / "measures.txt", "a", encoding="utf-8") as f:
            f.write(msg + "\n")
        if (al.dir / "measures.txt") not in al.files:
            al.files.append(al.dir / "measures.txt")

    def step_compute(self, el, al):
        expr = self.expand(el.get("expr") or clean_text(el.text))
        v = safe_eval(expr, self.vars)
        self.vars[el.get("var")] = v
        log(f"[{al.id}] {el.get('var')} = {expr} = {v:.6g}")

    def step_set(self, el, al):
        self.vars[el.get("var")] = to_num(self.expand(el.get("value") if el.get("value") is not None else clean_text(el.text)))

    def dialog(self, kind, text, default=""):
        if self.args.no_ask:
            return default
        if kind == "ask":
            if shutil.which("kdialog"):
                r = subprocess.run(["kdialog", "--title", "runner", "--inputbox", text, default], capture_output=True, text=True)
                return r.stdout.strip() if r.returncode == 0 else default
            if shutil.which("zenity"):
                r = subprocess.run(["zenity", "--entry", "--text", text, "--entry-text", default], capture_output=True, text=True)
                return r.stdout.strip() if r.returncode == 0 else default
            return input(f"{text} [{default}]: ").strip() or default if sys.stdin.isatty() else default
        if shutil.which("kdialog"):
            subprocess.run(["kdialog", "--title", "runner", "--msgbox", text])
        elif shutil.which("zenity"):
            subprocess.run(["zenity", "--info", "--text", text])
        elif sys.stdin.isatty():
            input(f"{text}\n[ENTER para continuar] ")

    def step_ask(self, el, al):
        v = self.dialog("ask", self.expand(el.get("prompt", el.get("var"))), self.expand(el.get("default", "")))
        self.vars[el.get("var")] = to_num(v)

    def step_manual(self, el, al):
        self.dialog("msg", self.expand(clean_text(el.text)))

    def step_table(self, el, al: Al):
        name = al.unique(sanitize(el.get("name", "tabela")))
        title = self.expand(el.get("title", name))
        cols = [c.strip() for c in self.expand(clean_text(el.find("Columns").text)).split("|")]
        rows = [[c.strip() for c in self.expand(clean_text(r.text)).split("|")] for r in el.findall("Row")]
        al.dir.mkdir(parents=True, exist_ok=True)
        with open(al.dir / f"{name}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            w.writerows(rows)
        md = [f"**{title}**", "", "| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
        md += ["| " + " | ".join(r) + " |" for r in rows]
        (al.dir / f"{name}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
        al.files += [al.dir / f"{name}.csv", al.dir / f"{name}.md"]
        log(f"[{al.id}] tabela '{name}' ({len(rows)} linhas)")
        if el.get("screenshot", "true") == "true":
            widths = [max(len(str(x)) for x in col) for col in zip(cols, *rows)]
            fmt = lambda r: "│ " + " │ ".join(str(c).ljust(w) for c, w in zip(r, widths)) + " │"
            sep = "├" + "┼".join("─" * (w + 2) for w in widths) + "┤"
            lines = self.banner(al, title)
            lines += [f"{BOLD}{fmt(cols)}{RESET}", sep] + [fmt(r) for r in rows] + [""]
            png = al.dir / f"{name}.png"
            if self.screenshot_terminal(lines, png):
                al.files.append(png)

    def step_iograph(self, el, al: Al):
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError:
            raise RunnerError("IOGraph requer matplotlib (pip install matplotlib)")
        interval = float(el.get("interval", "1"))
        unit = el.get("unit", "kbit")
        div = {"bit": 1, "kbit": 1e3, "mbit": 1e6}[unit]
        ylab = {"bit": "bit/s", "kbit": "kbit/s", "mbit": "Mbit/s"}[unit]
        fig, ax = plt.subplots(figsize=(11, 5.5))
        first_t0 = None
        n = 0
        for s in el.findall("Series"):
            try:
                path = Path(self.expand(s.get("pcap")))
            except RunnerError:
                if s.get("optional") == "true":
                    continue
                raise
            if not path.exists():
                if s.get("optional") == "true":
                    continue
                raise RunnerError(f"IOGraph: captura inexistente {path}")
            pk = read_pcap(path)
            t0 = pk[0][0]
            first_t0 = t0 if first_t0 is None else first_t0
            nb = int((pk[-1][0] - t0) / interval) + 1
            arr = [0.0] * nb
            for t, l in pk:
                arr[int((t - t0) / interval)] += 8 * l
            xs = [i * interval for i in range(nb)]
            ax.step(xs, [a / interval / div for a in arr], where="post", label=self.expand(s.get("label", path.stem)))
            n += 1
        if n == 0:
            raise RunnerError("IOGraph sem séries válidas")
        for r in el.findall("Ref"):
            ax.axhline(float(r.get("y")), ls=":", color="gray", lw=1)
            ax.text(0.2, float(r.get("y")), self.expand(r.get("label", "")), fontsize=8, color="gray", va="bottom")
        mk = el.get("marks")
        if mk and mk in self.marks and first_t0 is not None:
            for ts, lb in self.marks[mk]:
                ax.axvline(ts - first_t0, ls="--", color="red", lw=1)
                ax.text(ts - first_t0 + 0.5, ax.get_ylim()[1] * 0.95, lb, rotation=90, fontsize=8, va="top", color="red")
        elif mk:
            log(f"IOGraph: marcas '{mk}' indisponíveis (correu a timeline?)", YELLOW)
        ax.set_xlabel("Tempo (s)")
        ax.set_ylabel(f"Débito ({ylab})")
        ax.set_title(self.expand(el.get("title", "Débito ao longo do tempo")) + f"  —  {self.group}, perfil {self.profile}")
        ax.grid(alpha=0.3)
        ax.legend()
        name = al.unique(sanitize(el.get("name", "iograph")))
        al.dir.mkdir(parents=True, exist_ok=True)
        png = al.dir / f"{name}.png"
        fig.tight_layout()
        fig.savefig(png, dpi=130)
        plt.close(fig)
        al.files.append(png)
        log(f"   ✓ {png.relative_to(self.results)}", GREEN)

    # ------------------------------------------------------ checklist
    def write_checklist(self, al: Al):
        el = al.el
        L = [f"## Alínea {al.id} — {al.title}", ""]
        evs = el.findall("Evidence")
        if evs:
            L += ["### Evidências mínimas", ""]
            for e in evs:
                need = e.get("need")
                ok = bool(list(self.results.glob(need))) if need else False
                L.append(f"- [{'x' if ok else ' '}] {' '.join(clean_text(e.text).split())}" + (f"  — `{need}`" if need else ""))
            L.append("")
        qs = el.findall("Question")
        if qs:
            L += ["### Questões (responder no relatório)", ""]
            for q in qs:
                L += [f"**Questão {q.get('n', '?')}.** {' '.join(clean_text(q.text).split())}", ""]
            L.append("Ficheiros desta alínea que suportam as respostas: " +
                     (", ".join(f"`{f.relative_to(self.results)}`" for f in al.files if f.suffix in ('.png', '.csv', '.md', '.txt', '.pcap')) or "—"))
            L.append("")
        al.dir.mkdir(parents=True, exist_ok=True)
        (al.dir / "CHECKLIST.md").write_text("\n".join(L), encoding="utf-8")

    def assemble_checklist(self):
        head = [f"# Checklist do relatório — grupo {self.group}, perfil {self.profile}", "",
                f"Perfil {self.profile}: largura de banda {self.vars.get('PROFILE_BW')}, atraso {self.vars.get('PROFILE_DELAY')}/sentido, "
                f"perda {self.vars.get('PROFILE_LOSS')}.", "",
                "Primeira página do relatório: turno PL, identificador do grupo, nome e número dos 3 estudantes, perfil.", ""]
        body = []
        for a in self.root.findall("Alinea"):
            f = self.results / sanitize(a.get("id")) / "CHECKLIST.md"
            if f.exists():
                body.append(f.read_text(encoding="utf-8"))
        (self.results / "CHECKLIST.md").write_text("\n".join(head + body), encoding="utf-8")

    # ---------------------------------------------------------- execução
    def selected(self):
        only = {x.strip() for x in (self.args.only or "").split(",") if x.strip()}
        skip = {x.strip() for x in (self.args.skip or "").split(",") if x.strip()}
        for a in self.root.findall("Alinea"):
            i = a.get("id")
            if a.get("enabled", "true") == "false" and not only:
                continue
            if only and i not in only:
                continue
            if i in skip:
                continue
            yield a

    def run_alinea(self, el):
        al = Al(el, self.results)
        shutil.rmtree(al.dir, ignore_errors=True)
        al.dir.mkdir(parents=True, exist_ok=True)
        log(f"━━━ Alínea {al.id}: {al.title} ━━━", BOLD + CYAN)
        try:
            self.run_steps(el, al)
        except Exception as e:  # noqa
            al.failed = True
            log(f"Alínea {al.id} falhou: {e}", RED)
            if self.args.fail_fast:
                raise
        finally:
            try:
                self.cleanup_bg()
            except Exception as e:  # noqa
                log(f"limpeza de processos de fundo: {e}", YELLOW)
            self.save_vars()
            self.write_checklist(al)
        return al

    def run_once(self, forced_session=None):
        self.results.mkdir(parents=True, exist_ok=True)
        global LOGF
        LOGF = open(self.results / "runner.log", "a", encoding="utf-8")
        self.setup(forced_session)
        self.load_vars()
        done = []
        try:
            for a in self.selected():
                done.append(self.run_alinea(a))
        finally:
            self.cleanup_bg(force=True)
            self.save_vars()
            self.assemble_checklist()
        log("━━━ RESUMO ━━━", BOLD + CYAN)
        for al in done:
            shots = len([f for f in al.files if f.suffix == ".png"])
            log(f"  {'✗' if al.failed else '✓'} {al.id:<10} {shots:>2} imagens  {al.title}", RED if al.failed else GREEN)
        log(f"resultados em {self.results}  (checklist: CHECKLIST.md)", GREEN)

    # ----------------------------------------------------------- watch
    def watch(self):
        trig = self.cfg("Trigger", default="/tmp/tp1-runner-trigger")
        self.container = self.find_container()
        self.display = self.args.display or self.cfg("Display") or os.environ.get("DISPLAY", ":0")
        log(f"à espera do hook de Runtime ({trig} no contentor {self.container})"
            + (" + deteção automática" if self.args.auto else "") + " — Ctrl+C para sair")
        seen = set()
        while True:
            try:
                t = self.csh(f"cat {trig} 2>/dev/null && rm -f {trig}", 10).strip()
                sess = t.splitlines()[0] if t else None
                if not sess and self.args.auto:
                    try:
                        d, _ = self.find_session()
                        key = (d, self.csh(f'stat -c %Y "{d}/session-deployed.xml" 2>/dev/null', 10).strip())
                        if key not in seen:
                            seen.add(key)
                            sess = d
                    except RunnerError:
                        pass
                if sess:
                    log(f"sessão em Runtime: {sess} — a aguardar {self.args.settle}s para a rede estabilizar")
                    time.sleep(self.args.settle)
                    try:
                        self.run_once(sess)
                    except Exception as e:  # noqa
                        log(f"execução falhou: {e}", RED)
                    log("de novo à espera de Run no CORE…")
                time.sleep(2)
            except KeyboardInterrupt:
                break

    # ------------------------------------------------------------- plano
    def plan(self):
        print(f"Assignment: {self.root.get('name')}  grupo={self.group}  perfil={self.profile} {self.profiles.get(self.profile)}")
        names, links, _ = self.topology_spec()
        print(f"Topologia exigida: nodes={sorted(names)} links={links}")

        def brief(el, ind):
            for ch in el:
                if ch.tag in DOC_TAGS or ch.tag in ("Highlight", "Command", "File", "Filter", "Color", "Column", "DecodeAs",
                                                    "Goto", "Series", "Ref", "Columns", "Row"):
                    continue
                extra = " ".join(f"{k}={v}" for k, v in ch.attrib.items() if k in ("name", "node", "file", "ref", "t", "var", "window", "times", "a", "bw", "profile"))
                nc = len(ch.findall("Command")) + sum(len(r.findall("Command")) for r in ch.findall("Repeat"))
                print(f"{ind}<{ch.tag}> {extra}" + (f"  [{nc} cmd]" if nc else ""))
                brief(ch, ind + "    ")
        for a in self.selected():
            print(f"\n■ Alínea {a.get('id')} — {a.get('title', '')}")
            brief(a, "    ")


def main():
    ap = argparse.ArgumentParser(description="Automatiza assignments CORE (XML -> comandos -> screenshots)")
    ap.add_argument("xml")
    ap.add_argument("--only", help="ids de alíneas separados por vírgula")
    ap.add_argument("--skip", help="ids de alíneas a saltar")
    ap.add_argument("--plan", action="store_true", help="valida o XML e mostra o plano (não executa)")
    ap.add_argument("--watch", action="store_true", help="espera pelo hook de Runtime do CORE")
    ap.add_argument("--auto", action="store_true", help="com --watch: deteta também sessões novas sem hook")
    ap.add_argument("--settle", type=float, default=3.0, help="segundos de espera após o hook (default 3)")
    ap.add_argument("--container")
    ap.add_argument("--session", help="forçar /tmp/pycore.N (dentro do contentor)")
    ap.add_argument("--group")
    ap.add_argument("--profile")
    ap.add_argument("--results")
    ap.add_argument("--display")
    ap.add_argument("--terminal", choices=["kitty", "konsole"])
    ap.add_argument("--no-ask", action="store_true", help="não abrir diálogos (<Ask>/<Manual>): usa defaults")
    ap.add_argument("--fail-fast", action="store_true")
    args = ap.parse_args()
    try:
        r = Runner(args)
        if args.plan:
            r.plan()
        elif args.watch:
            r.watch()
        else:
            r.run_once()
    except RunnerError as e:
        log(str(e), RED)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()