#!/usr/bin/env python3
"""
NKZ CodeGuardian — Static security analyzer for Python and JavaScript.
Detects risky patterns, suggests safer alternatives, outputs structured JSON.
"""

import ast
import re
import os
import json
import sys
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional


SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"


# ─── PYTHON RULES ────────────────────────────────────────────────────────────

class PythonASTAnalyzer(ast.NodeVisitor):
    def __init__(self, source_lines: list[str]):
        self.source_lines = source_lines
        self.issues: list[dict] = []

    def _issue(self, node, severity, rule_id, title, description, suggestion, snippet=""):
        line = getattr(node, "lineno", None)
        if not snippet and line:
            snippet = self.source_lines[line - 1].rstrip() if line <= len(self.source_lines) else ""
        self.issues.append({
            "rule_id":     rule_id,
            "severity":    severity,
            "title":       title,
            "description": description,
            "suggestion":  suggestion,
            "line":        line,
            "snippet":     snippet,
        })

    # eval() / exec()
    def visit_Call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name == "eval":
            self._issue(node, SEVERITY_CRITICAL, "PY001",
                "eval() detectado",
                "eval() executa código arbitrário a partir de strings. Vetor direto para RCE se a entrada não for sanitizada.",
                "Substitua por ast.literal_eval() para dados, ou reescreva a lógica sem eval."
            )

        if func_name == "exec":
            self._issue(node, SEVERITY_CRITICAL, "PY002",
                "exec() detectado",
                "exec() executa código dinâmico. Extremamente perigoso com entrada do usuário.",
                "Elimine o uso de exec(). Considere dicionários de funções ou importação controlada."
            )

        if func_name in ("compile",):
            self._issue(node, SEVERITY_HIGH, "PY003",
                "compile() com possível entrada dinâmica",
                "compile() pode ser usado para preparar código malicioso antes de exec().",
                "Evite compile() com strings dinâmicas. Prefira lógica estática."
            )

        # subprocess com shell=True
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("call", "run", "Popen", "check_output", "check_call"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._issue(node, SEVERITY_HIGH, "PY004",
                        "subprocess com shell=True",
                        "shell=True expõe a execução a injeção de comandos se qualquer parte da string vier do usuário.",
                        "Use shell=False e passe argumentos como lista: subprocess.run(['ls', '-la'])."
                    )

        # pickle.loads / pickle.load
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("loads", "load"):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                self._issue(node, SEVERITY_CRITICAL, "PY005",
                    "Deserialização com pickle",
                    "pickle.load/loads executa código arbitrário ao desserializar dados não confiáveis. CVE clássico.",
                    "Use json, msgpack ou protobuf para dados externos. Nunca deserialize pickle de fontes não verificadas."
                )

        # yaml.load sem Loader
        if isinstance(node.func, ast.Attribute) and node.func.attr == "load":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml":
                has_loader = any(kw.arg == "Loader" for kw in node.keywords)
                if not has_loader:
                    self._issue(node, SEVERITY_HIGH, "PY006",
                        "yaml.load() sem Loader explícito",
                        "yaml.load() sem Loader=yaml.SafeLoader permite execução de código Python arbitrário.",
                        "Use yaml.safe_load() ou yaml.load(data, Loader=yaml.SafeLoader)."
                    )

        # hashlib com md5/sha1
        if func_name in ("md5", "sha1") or (
            isinstance(node.func, ast.Attribute) and node.func.attr in ("md5", "sha1")
        ):
            self._issue(node, SEVERITY_MEDIUM, "PY007",
                f"Hash criptograficamente fraco ({func_name})",
                "MD5 e SHA-1 estão quebrados para uso criptográfico (colisões conhecidas).",
                "Use hashlib.sha256() ou hashlib.sha3_256() para integridade. Para senhas, use bcrypt/argon2."
            )

        # random em contexto de segurança (heurística: variável com 'token', 'secret', 'key')
        if func_name in ("random", "randint", "choice", "shuffle") or (
            isinstance(node.func, ast.Attribute) and node.func.attr in ("random", "randint", "choice")
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "random"
        ):
            self._issue(node, SEVERITY_MEDIUM, "PY008",
                "Módulo random (não criptográfico)",
                "random não é seguro para tokens, senhas ou chaves. Previsível com seed conhecida.",
                "Use secrets.token_hex(), secrets.token_urlsafe() ou os.urandom() para valores de segurança."
            )

        self.generic_visit(node)

    # assert em código de produção
    def visit_Assert(self, node):
        self._issue(node, SEVERITY_LOW, "PY009",
            "assert em código de produção",
            "assert é removido quando Python roda com -O (optimized). Nunca use para validação de segurança.",
            "Substitua por if not condition: raise ValueError(...) ou use bibliotecas de validação."
        )
        self.generic_visit(node)

    # hardcoded secrets (assign)
    def visit_Assign(self, node):
        secret_names = re.compile(r"(password|passwd|secret|api_key|token|private_key|access_key|auth)", re.I)
        for target in node.targets:
            if isinstance(target, ast.Name) and secret_names.search(target.id):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) > 3:
                    self._issue(node, SEVERITY_CRITICAL, "PY010",
                        f"Credencial hardcoded: {target.id}",
                        f"O valor de '{target.id}' está em texto claro no código-fonte. Vazamento em VCS.",
                        "Use variáveis de ambiente (os.getenv) ou gerenciadores de segredos (Vault, AWS Secrets Manager)."
                    )
        self.generic_visit(node)

    # SQL com f-string ou concatenação
    def visit_JoinedStr(self, node):
        # f-strings próximas de SQL são detectadas no analisador regex também
        self.generic_visit(node)


def analyze_python_file(filepath: str, source: str) -> list[dict]:
    issues = []
    lines = source.splitlines()

    # AST pass
    try:
        tree = ast.parse(source, filename=filepath)
        visitor = PythonASTAnalyzer(lines)
        visitor.visit(tree)
        issues.extend(visitor.issues)
    except SyntaxError as e:
        issues.append({
            "rule_id": "PY000",
            "severity": SEVERITY_HIGH,
            "title": "Erro de sintaxe Python",
            "description": str(e),
            "suggestion": "Corrija o erro de sintaxe antes da análise.",
            "line": e.lineno,
            "snippet": lines[e.lineno - 1].rstrip() if e.lineno and e.lineno <= len(lines) else "",
        })

    # Regex pass (padrões que AST não captura facilmente)
    regex_rules = [
        (re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*\+.*\b(req|request|input|user|param)\b", re.I),
         SEVERITY_CRITICAL, "PY011",
         "Possível SQL Injection via concatenação",
         "Concatenar input do usuário em queries SQL é vulnerabilidade clássica de injeção.",
         "Use queries parametrizadas: cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))"),

        (re.compile(r"os\.system\s*\("),
         SEVERITY_HIGH, "PY012",
         "os.system() detectado",
         "os.system() passa string para shell. Vulnerável a injeção de comandos.",
         "Use subprocess.run(['cmd', 'arg'], shell=False) para controle seguro."),

        (re.compile(r"open\s*\(.*\+.*\b(req|request|input|user|param|filename)\b", re.I),
         SEVERITY_HIGH, "PY013",
         "Path traversal em open()",
         "Construir caminhos com input do usuário permite path traversal (../../etc/passwd).",
         "Use pathlib.Path e valide com .resolve().is_relative_to(base_dir)."),

        (re.compile(r"DEBUG\s*=\s*True", re.I),
         SEVERITY_MEDIUM, "PY014",
         "DEBUG=True em código",
         "Modo debug expõe tracebacks, variáveis e configurações em produção.",
         "Use variáveis de ambiente: DEBUG = os.getenv('DEBUG', 'False') == 'True'"),

        (re.compile(r"verify\s*=\s*False"),
         SEVERITY_HIGH, "PY015",
         "SSL verify=False em requests",
         "Desabilitar verificação SSL permite ataques man-in-the-middle.",
         "Nunca use verify=False em produção. Corrija o certificado ou use verify='/path/to/cert.pem'."),
    ]

    for i, line in enumerate(lines, 1):
        for pattern, severity, rule_id, title, desc, suggestion in regex_rules:
            if pattern.search(line):
                issues.append({
                    "rule_id":     rule_id,
                    "severity":    severity,
                    "title":       title,
                    "description": desc,
                    "suggestion":  suggestion,
                    "line":        i,
                    "snippet":     line.rstrip(),
                })

    return issues


# ─── JAVASCRIPT RULES ────────────────────────────────────────────────────────

def analyze_javascript_file(filepath: str, source: str) -> list[dict]:
    issues = []
    lines = source.splitlines()

    js_rules = [
        (re.compile(r"\beval\s*\("),
         SEVERITY_CRITICAL, "JS001",
         "eval() detectado",
         "eval() executa código JavaScript arbitrário. RCE no contexto do browser ou Node.js.",
         "Remova eval(). Use JSON.parse() para dados, ou reescreva a lógica sem eval."),

        (re.compile(r"innerHTML\s*=(?!=)"),
         SEVERITY_HIGH, "JS002",
         "innerHTML assignment",
         "Atribuir a innerHTML sem sanitização é vetor direto para XSS.",
         "Use textContent para texto puro, ou DOMPurify.sanitize() antes de innerHTML."),

        (re.compile(r"document\.write\s*\("),
         SEVERITY_HIGH, "JS003",
         "document.write() detectado",
         "document.write() pode ser usado para injetar HTML/script malicioso.",
         "Use métodos DOM seguros: createElement, appendChild, textContent."),

        (re.compile(r"\.outerHTML\s*=(?!=)"),
         SEVERITY_HIGH, "JS004",
         "outerHTML assignment",
         "Equivalente a innerHTML — XSS se o conteúdo vier de fonte externa.",
         "Sanitize com DOMPurify ou use métodos DOM seguros."),

        (re.compile(r"setTimeout\s*\(\s*['\"`]|setInterval\s*\(\s*['\"`]"),
         SEVERITY_MEDIUM, "JS005",
         "setTimeout/setInterval com string",
         "Passar string para setTimeout/setInterval é equivalente a eval().",
         "Passe sempre uma função: setTimeout(() => { myFunc(); }, delay)"),

        (re.compile(r"new\s+Function\s*\("),
         SEVERITY_CRITICAL, "JS006",
         "new Function() detectado",
         "new Function() constrói e executa código a partir de strings. Equivalente a eval().",
         "Elimine new Function(). Prefira closures ou padrões estáticos."),

        (re.compile(r"localStorage\.setItem|sessionStorage\.setItem"),
         SEVERITY_MEDIUM, "JS007",
         "Dados sensíveis em localStorage/sessionStorage",
         "Storage do browser é acessível a qualquer script na página (XSS). Não armazene tokens JWT ou senhas.",
         "Use cookies HttpOnly+Secure para tokens de sessão. Evite dados sensíveis em Web Storage."),

        (re.compile(r"Math\.random\s*\(\s*\)"),
         SEVERITY_MEDIUM, "JS008",
         "Math.random() em contexto de segurança",
         "Math.random() não é criptograficamente seguro. Previsível.",
         "Use crypto.getRandomValues() ou crypto.randomUUID() para valores de segurança."),

        (re.compile(r"['\"]http://(?!localhost|127\.0\.0\.1)"),
         SEVERITY_MEDIUM, "JS009",
         "URL HTTP (não HTTPS)",
         "Requisições HTTP são transmitidas em texto claro. Suscetíveis a MITM.",
         "Use sempre HTTPS. Considere Content-Security-Policy com upgrade-insecure-requests."),

        (re.compile(r"\.exec\s*\(\s*req\.|\.exec\s*\(\s*request\.|\.exec\s*\(\s*params\.", re.I),
         SEVERITY_CRITICAL, "JS010",
         "Possível NoSQL Injection",
         "Passar input do usuário diretamente para .exec() ou queries Mongo sem sanitização.",
         "Sanitize e valide inputs. Use mongoose com schemas tipados ou mongodb-sanitize."),

        (re.compile(r"require\s*\(\s*[`'\"]\.\."),
         SEVERITY_LOW, "JS011",
         "require() com caminho relativo dinâmico",
         "Carregar módulos com caminhos construídos dinamicamente pode levar a path traversal.",
         "Use caminhos absolutos com __dirname ou path.resolve()."),

        (re.compile(r"(password|secret|api_key|token|private_key)\s*[:=]\s*['\"][^'\"]{4,}['\"]", re.I),
         SEVERITY_CRITICAL, "JS012",
         "Credencial hardcoded",
         "Segredos em texto claro no código-fonte são expostos em repositórios e logs.",
         "Use variáveis de ambiente: process.env.API_KEY, e .env com dotenv (nunca commite .env)."),

        (re.compile(r"Access-Control-Allow-Origin['\"\s:]+\*"),
         SEVERITY_MEDIUM, "JS013",
         "CORS wildcard (*)",
         "Access-Control-Allow-Origin: * permite requisições de qualquer origem.",
         "Especifique origens permitidas explicitamente: 'https://meudominio.com'."),

        (re.compile(r"\bconsole\.(log|info|debug)\s*\(.*?(password|token|secret|key)", re.I),
         SEVERITY_HIGH, "JS014",
         "Logging de dado sensível",
         "console.log com dados sensíveis expõe credenciais em logs de produção.",
         "Remova logs de dados sensíveis. Use níveis de log controlados por ambiente."),
    ]

    for i, line in enumerate(lines, 1):
        for pattern, severity, rule_id, title, desc, suggestion in js_rules:
            if pattern.search(line):
                issues.append({
                    "rule_id":     rule_id,
                    "severity":    severity,
                    "title":       title,
                    "description": desc,
                    "suggestion":  suggestion,
                    "line":        i,
                    "snippet":     line.rstrip(),
                })

    return issues


# ─── FILE DISPATCHER ─────────────────────────────────────────────────────────

SUPPORTED_EXTENSIONS = {
    ".py":   analyze_python_file,
    ".js":   analyze_javascript_file,
    ".mjs":  analyze_javascript_file,
    ".cjs":  analyze_javascript_file,
    ".ts":   analyze_javascript_file,  # subset of JS rules applies
    ".jsx":  analyze_javascript_file,
    ".tsx":  analyze_javascript_file,
}

IGNORE_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", "coverage", ".cache",
}


def scan_path(target: str) -> dict:
    target_path = Path(target).resolve()
    files_scanned = []
    all_results   = []

    if target_path.is_file():
        paths = [target_path]
    elif target_path.is_dir():
        paths = [
            p for p in target_path.rglob("*")
            if p.is_file()
            and not any(part in IGNORE_DIRS for part in p.parts)
        ]
    else:
        print(f"[NKZ] Caminho não encontrado: {target}", file=sys.stderr)
        sys.exit(1)

    for path in paths:
        ext = path.suffix.lower()
        analyzer = SUPPORTED_EXTENSIONS.get(ext)
        if not analyzer:
            continue

        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            continue

        issues = analyzer(str(path), source)
        rel    = str(path.relative_to(target_path.parent if target_path.is_file() else target_path))

        files_scanned.append(rel)
        for issue in issues:
            issue["file"] = rel
            all_results.append(issue)

    severity_order = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 1, SEVERITY_MEDIUM: 2, SEVERITY_LOW: 3}
    all_results.sort(key=lambda x: (severity_order.get(x["severity"], 4), x["file"], x.get("line") or 0))

    counts = {s: 0 for s in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]}
    for r in all_results:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1

    score = max(0, 100 - (counts[SEVERITY_CRITICAL] * 25) - (counts[SEVERITY_HIGH] * 10)
                       - (counts[SEVERITY_MEDIUM] * 4)  - (counts[SEVERITY_LOW] * 1))

    return {
        "meta": {
            "project":       str(target_path.name),
            "target":        str(target_path),
            "scanned_at":    datetime.now().isoformat(),
            "files_scanned": len(files_scanned),
            "total_issues":  len(all_results),
            "security_score": score,
            "counts":        counts,
        },
        "files":  files_scanned,
        "issues": all_results,
    }


# ─── CLI ─────────────────────────────────────────────────────────────────────

def print_report(report: dict):
    meta = report["meta"]
    sep  = "─" * 60

    print(f"\n{'═' * 60}")
    print(f"  NKZ CODEGUARDIAN  —  {meta['project']}")
    print(f"{'═' * 60}")
    print(f"  Arquivos analisados : {meta['files_scanned']}")
    print(f"  Total de issues     : {meta['total_issues']}")
    print(f"  Security Score      : {meta['security_score']}/100")
    print(f"  {sep}")
    print(f"  CRITICAL : {meta['counts'][SEVERITY_CRITICAL]}")
    print(f"  HIGH     : {meta['counts'][SEVERITY_HIGH]}")
    print(f"  MEDIUM   : {meta['counts'][SEVERITY_MEDIUM]}")
    print(f"  LOW      : {meta['counts'][SEVERITY_LOW]}")
    print(f"{'═' * 60}\n")

    for issue in report["issues"]:
        sev_icons = {
            SEVERITY_CRITICAL: "🔴",
            SEVERITY_HIGH:     "🟠",
            SEVERITY_MEDIUM:   "🟡",
            SEVERITY_LOW:      "🔵",
        }
        icon = sev_icons.get(issue["severity"], "⚪")
        print(f"{icon} [{issue['severity']}] {issue['rule_id']} — {issue['title']}")
        print(f"   Arquivo  : {issue['file']}:{issue.get('line', '?')}")
        if issue.get("snippet"):
            print(f"   Código   : {issue['snippet'].strip()}")
        print(f"   Problema : {issue['description']}")
        print(f"   Fix      : {issue['suggestion']}")
        print(f"   {sep}")

    print()


def main():
    if len(sys.argv) < 2:
        print("Uso: python analyzer.py <caminho_do_projeto_ou_arquivo> [--json]")
        sys.exit(1)

    target      = sys.argv[1]
    output_json = "--json" in sys.argv
    report      = scan_path(target)

    if output_json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_report(report)

        # Salva JSON automaticamente
        out_path = Path(target).resolve()
        report_name = f"codeguardian_report_{out_path.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_file = Path(report_name)
        report_file.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  Relatório salvo em: {report_file}\n")


if __name__ == "__main__":
    main()
