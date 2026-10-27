<div align="center">

# 🛡️ NKZ CodeGuardian

**Analisador local de segurança para Python e JavaScript**  
Detecta padrões perigosos, mostra arquivo, linha, snippet e sugere o fix.  
Zero dependências. Roda offline. Dashboard visual incluído.

![Python](https://img.shields.io/badge/Python-3.8%2B-3B82F6?style=flat-square&logo=python&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-ES6%2B-F59E0B?style=flat-square&logo=javascript&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-10B981?style=flat-square)
![Zero deps](https://img.shields.io/badge/dependências-zero-7C3AED?style=flat-square)

</div>

---

## Como usar

**1. Clone o repositório**
```bash
git clone https://github.com/seu-usuario/nkz-codeguardian.git
cd nkz-codeguardian
```

**2. Rode o analyzer no seu projeto**
```bash
# Gera o relatório JSON
python analyzer.py C:\caminho\para\seu\projeto --json > report.json

# Ou se estiver dentro da pasta do projeto
python analyzer.py . --json > report.json
```

**3. Abra o dashboard**  
Abra o arquivo `index.html` no browser e arraste o `report.json` para visualizar.

---

## O que detecta

### Python — 15 rules

| ID | Severidade | Descrição |
|---|---|---|
| PY001 | 🔴 CRITICAL | `eval()` detectado |
| PY002 | 🔴 CRITICAL | `exec()` detectado |
| PY003 | 🟠 HIGH | `compile()` com string dinâmica |
| PY004 | 🟠 HIGH | `subprocess` com `shell=True` |
| PY005 | 🔴 CRITICAL | Deserialização com `pickle` |
| PY006 | 🟠 HIGH | `yaml.load()` sem Loader seguro |
| PY007 | 🟡 MEDIUM | Hash fraco (MD5/SHA1) |
| PY008 | 🟡 MEDIUM | `random` em contexto de segurança |
| PY009 | 🔵 LOW | `assert` em produção |
| PY010 | 🔴 CRITICAL | Credencial hardcoded |
| PY011 | 🔴 CRITICAL | SQL Injection via concatenação |
| PY012 | 🟠 HIGH | `os.system()` detectado |
| PY013 | 🟠 HIGH | Path traversal em `open()` |
| PY014 | 🟡 MEDIUM | `DEBUG=True` em código |
| PY015 | 🟠 HIGH | SSL `verify=False` |

### JavaScript / TypeScript — 14 rules

| ID | Severidade | Descrição |
|---|---|---|
| JS001 | 🔴 CRITICAL | `eval()` detectado |
| JS002 | 🟠 HIGH | `innerHTML` assignment sem sanitização |
| JS003 | 🟠 HIGH | `document.write()` |
| JS004 | 🟠 HIGH | `outerHTML` assignment |
| JS005 | 🟡 MEDIUM | `setTimeout`/`setInterval` com string |
| JS006 | 🔴 CRITICAL | `new Function()` |
| JS007 | 🟡 MEDIUM | Dados sensíveis em `localStorage` |
| JS008 | 🟡 MEDIUM | `Math.random()` em contexto de segurança |
| JS009 | 🟡 MEDIUM | URL HTTP (não HTTPS) |
| JS010 | 🔴 CRITICAL | Possível NoSQL Injection |
| JS011 | 🔵 LOW | `require()` com path relativo dinâmico |
| JS012 | 🔴 CRITICAL | Credencial hardcoded |
| JS013 | 🟡 MEDIUM | CORS wildcard (`*`) |
| JS014 | 🟠 HIGH | Logging de dado sensível |

---

## Security Score

```
score = max(0, 100 - (CRITICAL×25) - (HIGH×10) - (MEDIUM×4) - (LOW×1))
```

| Score | Status |
|---|---|
| 80–100 | 🟢 Boa postura |
| 50–79 | 🟡 Atenção necessária |
| 0–49 | 🔴 Ação urgente |

---

## Estrutura

```
nkz-codeguardian/
├── analyzer.py   # engine — AST + regex, CLI, gerador de JSON
├── index.html    # dashboard visual — drag & drop do report.json
└── README.md
```

## Extensões suportadas

`.py` `.js` `.mjs` `.cjs` `.ts` `.jsx` `.tsx`

## Pastas ignoradas automaticamente

`node_modules` `.git` `__pycache__` `.venv` `venv` `dist` `build` `.next` `coverage` `.cache`

---

## Requisitos

- Python 3.8+
- Zero dependências externas (stdlib pura)
- Browser moderno para o dashboard

---

<div align="center">
  <sub>Feito por NkzAyanoX</sub>
</div>
