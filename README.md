# OBAI — Reverse Engineering Platform

OBAI is a Flask + React application that drives **Ghidra** and **angr** for binary
analysis and layers a **multi-agent LLM system** on top to assist with reverse
engineering, vulnerability discovery, and (optionally) remote Windows/AD
investigation via a companion C# agent.

It gives you a web UI to upload a binary, run automated decompilation and
control-flow analysis, browse functions/imports/exports/strings/pseudocode, and
chat with an orchestrated team of LLM agents that read the analysis on your behalf.

---

## ⚠️ Authorized use only

This project includes **dual-use offensive security tooling** — automated
vulnerability discovery, exploit-generation prompts, and an optional remote agent
that executes PowerShell / C# and enumerates Active Directory on connected hosts.

Use it **only** against binaries and systems you own or are explicitly authorized
to test. You are responsible for complying with all applicable laws and for
operating within the scope of an authorized engagement. The software is provided
"as is", without warranty of any kind (see [LICENSE](LICENSE)).

---

## Features

- **Automated analysis pipeline** — symbol download (PDB), Ghidra auto-analysis and
  decompilation, and an angr `CFGFast` for control-flow visualization and symbolic
  execution.
- **Interactive UI** — function list, imports/exports, strings, pseudocode,
  disassembly, cross-references, and an interactive CFG graph (Cytoscape).
- **Multi-agent assistant** — an orchestrator delegates to Recon, Code-Analysis, and
  Security teams that share findings through per-binary briefings and a scratch memory.
- **Pluggable LLM providers** — Anthropic, OpenAI, or local Ollama, selected at runtime.
- **Persisted analyses** — each analysis is stored as a JSON document and can be
  reloaded later.
- **Optional remote investigation agent** — a self-contained .NET console app for
  authorized Windows/AD investigation.

## Architecture (overview)

| Layer | Location |
|---|---|
| Flask app + REST/SSE API | [app/](app/) |
| Analysis engines (Ghidra, angr, PE utils) | [app/core/](app/core/) |
| Multi-agent system (orchestrator → team leaders → workers) | [app/agents/](app/agents/) |
| Remote-agent server endpoints | [app/remote/](app/remote/) |
| React + Vite frontend | [frontend/](frontend/) |
| .NET remote investigation agent | [agent/](agent/) |

## Prerequisites

- **Python 3.10+** (64-bit)
- **A JDK compatible with your Ghidra version** — Ghidra 12 requires **JDK 21**
- **Ghidra 12.0** — *not bundled in this repository* (see [Ghidra setup](#3-install-ghidra) below)
- **Node.js 18+** and npm (for the frontend)
- **.NET 8 SDK** — only if you build the optional remote agent

## Installation

### 1. Clone and install Python dependencies

```powershell
git clone <your-repo-url> obai
cd obai
python setup.py
```

`setup.py` installs the packages in [requirements.txt](requirements.txt) and writes
the `ghidra_bridge_server.py` helper into `ghidra_scripts/`.

### 2. Configure your LLM provider

API keys are **not** committed. Copy the example config and set your key, or leave it
blank and enter the key later in the in-app **Settings** modal:

```powershell
Copy-Item re_config.example.json re_config.json
# then edit re_config.json and set the api_key for your active provider
```

`re_config.json` is gitignored — never commit real keys. Ollama needs no key.

### 3. Install Ghidra

Ghidra is large and is **not** part of this repository. Download it, then either:

- **Option A** — set an environment variable pointing at your install:

  ```powershell
  $env:GHIDRA_HOME = "C:\path\to\ghidra_12.0_PUBLIC"
  ```

- **Option B** — unzip it into the repo root as `ghidra_12.0_PUBLIC/` (the default
  location [app/config.py](app/config.py) looks for when `GHIDRA_HOME` is unset).

### 4. Build the frontend

```powershell
cd frontend
npm install
npm run build   # outputs to ../static/dist, which Flask then serves
```

## Running

```powershell
python run.py
```

Then open <http://localhost:5000>.

> **Security note:** `run.py` starts Flask's development server with `debug=True` and
> binds `0.0.0.0`. Do not expose it directly to untrusted networks. Put it behind a
> proper WSGI server / reverse proxy (and disable debug) for any non-local use.

### Frontend development

For hot-reload during development, run the Vite dev server alongside Flask. It proxies
`/api` to `localhost:5000`, so both must be running:

```powershell
cd frontend
npm run dev      # http://localhost:5173
```

## Optional: remote investigation agent

The [agent/](agent/) directory is a .NET 8 `win-x64` console app for **authorized**
Windows/AD investigation. It registers with the backend and long-polls for tasks
(PowerShell, C#, AD enumeration, system info).

```powershell
cd agent
dotnet publish -c Release
# Run against your backend (authorized hosts only):
OBAIAgent.exe <backend-host:port>
```

Only run this in environments where you are explicitly authorized to do so.

## Configuration reference

Environment variables (all optional; `setup.py` reports which are set):

| Variable | Purpose | Default |
|---|---|---|
| `GHIDRA_HOME` | Ghidra install root | bundled `./ghidra_12.0_PUBLIC` if present |
| `GHIDRA_SCRIPTS` | Ghidra scripts directory used by `ghidra_bridge` | `./ghidra_scripts` |
| `GHIDRA_PROJECT_ROOT` | Where Ghidra projects are stored | `./ghidra_projects` |
| `RB_UPLOAD_DIR` | Override the uploads directory | `./uploads` |
| `PORT` | Backend port | `5000` |

LLM provider settings (active provider, models, API keys) live in `re_config.json`
and are also editable from the in-app Settings modal.

User-generated data (`uploads/`, `analysis_db/`, `ghidra_projects/`, `symbols/`,
`symbol_cache/`, `libraries/`) is gitignored and stays local.

## License

Licensed under the Apache License 2.0 — see [LICENSE](LICENSE).

This repository does not redistribute Ghidra; download it separately from the
official source. Ghidra is licensed under its own Apache License 2.0.
