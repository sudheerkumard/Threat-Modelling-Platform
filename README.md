# AI Threat Modelling Platform

A self-hosted, browser-based platform that runs from **PowerShell 7**. Anyone on your team opens it in a browser, uploads an
architecture **diagram (PNG/JPG/GIF/WEBP)** and/or an **architecture summary**, and receives a complete threat model:

| Output | What it contains |
|---|---|
| **Threat mapping diagram** | Data-flow diagram rebuilt from the input; trust boundaries as zones, components coloured by highest risk, threat IDs on every node and flow, unencrypted flows flagged. Downloadable as SVG. |
| **Threat register** | STRIDE threats with attack scenario, likelihood × impact score, existing controls, mitigations. Filterable. |
| **Gap analysis** | Missing/weak controls with severity, P1/P2/P3 roadmap, effort, recommendation. |
| **Framework mapping** | Every threat and gap mapped to OWASP Top 10 2025, CIS Controls v8.1, NIST CSF 2.0, NIST SP 800-53 Rev 5, Microsoft Cloud Security Benchmark (and optionally OWASP Top 10 for LLM 2025), plus a per-framework coverage table. |
| **Heatmap & risk matrix** | STRIDE × component heatmap and 5×5 likelihood/impact matrix. |
| **Exports** | Standalone HTML report (print to PDF), `threats.csv`, `gaps.csv` (with Owner/Target date/Status columns for tracking), `model.json`, `diagram.mmd`, and `.xlsx` if ImportExcel is installed. |

---

## 1. Requirements

* **PowerShell 7.2+** (`winget install Microsoft.PowerShell`) — Windows PowerShell 5.1 is not supported
* One AI provider. **Two of them need no API key:**

| Provider | API key? | Data location | Quality | Notes |
|---|---|---|---|---|
| **Azure OpenAI + Entra ID** *(recommended)* | **No** — uses your Azure sign-in or managed identity | Your Azure tenant | High | Billed per use to your Azure subscription |
| **Ollama** (local model) | **No** | Never leaves the machine | Moderate | Free; 16 GB+ RAM, GPU strongly recommended |
| Anthropic Claude | Yes | Anthropic | Highest | Default model `claude-opus-5-5` |
| Mock | No | — | Demo data only | For trying the UI |

### Option A — Azure OpenAI with Entra ID (no key)
1. **Azure portal → Create a resource → Azure OpenAI** in your subscription (choose a region that offers the model you want).
2. Open it in **Azure AI Foundry → Deployments → Deploy model** and pick a **vision-capable** GPT model (e.g. `gpt-4.1` or `gpt-4o`). Note the **deployment name** and the **endpoint** (`https://<name>.openai.azure.com`).
3. **Access control (IAM) → Add role assignment → `Cognitive Services OpenAI User`** → assign to yourself (and to the managed identity of the server, if you host the platform on an Azure VM).
4. Sign in on the machine that runs the platform — any one of:
   ```powershell
   Install-Module Az.Accounts -Scope CurrentUser; Connect-AzAccount     # Az PowerShell
   az login                                                              # or Azure CLI
   # or nothing at all on an Azure VM / App Service with a managed identity
   ```
5. Run setup and choose option **1**, or non-interactively:
   ```powershell
   .\Setup-ThreatModelPlatform.ps1 -Provider AzureOpenAI -AzureEndpoint https://<name>.openai.azure.com -AzureDeployment <deployment>
   ```
   Setup confirms it can obtain a token. You can additionally set **Keys and Endpoint → Disable local authentication** on the
   resource so API keys can't be used at all.

### Option B — Ollama (local, free, offline)
```powershell
winget install Ollama.Ollama              # or download from https://ollama.com/download
ollama pull qwen2.5vl:7b                  # vision model that reads diagrams well (~6 GB); setup can pull it for you
.\Setup-ThreatModelPlatform.ps1 -Provider Ollama
```
Alternatives: `llama3.2-vision:11b`, `gemma3:12b` (`-Model <name>`). Local models are slower (several minutes per assessment
without a GPU) and less thorough than cloud models — use depth **Quick/Standard**, and supply a text summary alongside the
diagram for best results.

## 2. Install

```powershell
# 1. Extract the folder, e.g. C:\Tools\ThreatModelPlatform, then:
cd C:\Tools\ThreatModelPlatform
Get-ChildItem -Recurse | Unblock-File          # files downloaded from the internet

# 2. Configure (interactive: choose Azure OpenAI + Entra ID, Ollama, Claude or Mock)
pwsh -File .\Setup-ThreatModelPlatform.ps1

# 3. Open a NEW PowerShell window (so the API key env var is loaded) and start
pwsh -File .\Start-ThreatModelPlatform.ps1
```
Browse to **http://localhost:8080/**.

The package ships configured with the **Mock** provider, so step 3 works immediately as a demo before you connect a real AI provider.

### Share with your team (Windows server / jump host)
Run once in an **Administrator** PowerShell:
```powershell
.\Setup-ThreatModelPlatform.ps1 -Provider AzureOpenAI -AzureEndpoint https://<name>.openai.azure.com -AzureDeployment <deployment> -EnableNetworkAccess -UseWindowsAuth -Port 8080
```
* `-EnableNetworkAccess` adds the HTTP URL ACL and a Domain/Private firewall rule and listens on all interfaces.
* `-UseWindowsAuth` turns on Integrated Windows Authentication — users sign in with their domain account and every
  assessment records who requested it.
* Users then browse to `http://<server-name>:8080/`.

To keep it running after reboot, register it as a scheduled task:
```powershell
$a = New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument '-NoProfile -File "C:\Tools\ThreatModelPlatform\Start-ThreatModelPlatform.ps1"' -WorkingDirectory 'C:\Tools\ThreatModelPlatform'
$t = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName 'AI Threat Modelling Platform' -Action $a -Trigger $t -User 'DOMAIN\svc-threatmodel' -Password '<pwd>' -RunLevel Limited
```
(With Azure OpenAI + Entra ID, give that service account — or the VM's managed identity — the `Cognitive Services OpenAI User` role; with an API key provider, set the key environment variable for the service account.) For HTTPS, put the platform behind IIS ARR,
Azure Application Gateway or nginx with a certificate — HttpListener itself serves plain HTTP.

## 3. Using the platform

1. **New assessment** → enter the system name, environment, criticality, data classification.
2. Drop up to 5 diagrams (Visio/draw.io/Lucid exports as PNG work best; huge images are optimised in the browser),
   paste a screenshot with Ctrl+V, and/or write a summary (**Insert template** gives a structure; **Load .txt/.md** imports one).
   A diagram **plus** a summary gives the most accurate results — the summary supplies what a picture can't (auth methods,
   protocols, existing controls).
3. Choose frameworks (STRIDE always applies; OWASP LLM is auto-ticked when the summary mentions LLM/RAG/OpenAI) and depth.
4. **Generate threat model** — typically 1–4 minutes. Progress is shown live; you can leave and find it under **Assessments**.
5. Open the report in the built-in viewer, open it in a new tab, print to PDF, or download CSV/JSON/Mermaid.

Command line / pipeline use (same engine; results also show in the web history):
```powershell
.\Invoke-ThreatModel.ps1 -Name 'Customer Portal' -ImagePath .\portal.png -SummaryPath .\samples\sample-architecture-summary.md -Open
```

## 4. Configuration — `config/platform.config.json`

| Setting | Default | Notes |
|---|---|---|
| `Provider` | `Mock` | `AzureOpenAI`, `Ollama`, `Anthropic` or `Mock` |
| `Port` / `ListenAddress` | `8080` / `Localhost` | `Any` to serve the network (run setup with `-EnableNetworkAccess`) |
| `Authentication` | `None` | `Windows` = Integrated Windows Authentication |
| `MaxConcurrentJobs` | `3` | Parallel AI analyses; extra requests queue |
| `MaxUploadMB` | `40` | Max request size |
| `AllowDelete` | `true` | Whether users can delete assessments |
| `DataPath` | `./data` | Where assessments and reports are stored |
| `Anthropic.Model` | `claude-opus-5-5` | Any Claude vision model |
| `Anthropic.MaxTokens` | `16000` | Increase for very large architectures with depth *Deep* |
| `AzureOpenAI.Endpoint/Deployment/ApiVersion` | | `MaxTokensParam` = `max_tokens` for older API versions |
| `AzureOpenAI.AuthMode` | `EntraId` | `EntraId` (keyless: Az PowerShell → Azure CLI → managed identity) or `ApiKey` |
| `Ollama.Endpoint` / `Ollama.Model` | `http://localhost:11434` / `qwen2.5vl:7b` | Any Ollama vision model |
| `Ollama.NumCtx` / `MaxTokens` / `TimeoutSec` | `32768` / `12000` / `3600` | Raise `NumCtx` if responses are cut off (uses more RAM) |
| `*.ApiKeyEnvVar` | `ANTHROPIC_API_KEY` / `AZURE_OPENAI_API_KEY` | Keys are read from env vars, never stored in config |
| `*.ApiKeySecretName` | | Optional: name of a secret in a `Microsoft.PowerShell.SecretManagement` vault (checked first) |

Framework catalogues live in `config/frameworks.json` — edit to add controls or another framework (e.g. ISO 27001 Annex A);
new top-level entries automatically appear as checkboxes in the UI and in the AI prompt.

## 5. How it works

```
Browser ──JSON upload──▶ Start-ThreatModelPlatform.ps1 (HttpListener)
                              │ saves data/assessments/<id>/input + request.json
                              └─▶ background ThreadJob ─▶ ThreatModel.Engine.psm1
                                      1. builds prompt: STRIDE method + selected framework catalogues
                                      2. sends image(s) + summary to Azure OpenAI / Ollama / Claude, requests strict JSON
                                      3. validates & normalises; risk = likelihood × impact (scored by the platform, not the AI)
                                      4. generates Mermaid threat map, HTML report, CSV/JSON/XLSX
Browser ◀── polls status ── report served from /reports/<id>/report.html
```

## 6. Security notes

* Uploaded diagrams and summaries are sent to the configured AI provider. Use **Azure OpenAI** to keep data in your
  tenant, or **Ollama** to keep it on the machine, and tell users not to upload credentials or secrets.
* Azure OpenAI with `AuthMode = EntraId` means no secret exists to leak; access is governed by Azure RBAC.
* Platform hardening included: image type validated by magic bytes, ID/filename allow-lists (no path traversal), JSON-only
  POSTs with Origin check (CSRF), all AI output HTML-encoded in reports (prompt-injected text in a diagram cannot inject script),
  Mermaid in strict security mode, CSV formula-injection protection, CSP and nosniff headers, the prompt instructs the model to
  treat diagram/summary text as data only.
* Reports are AI-generated from the inputs supplied — have a security architect validate them before using them as audit evidence.

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `API key not found` | Set the env var in a new window: `$env:ANTHROPIC_API_KEY = '…'` or re-run setup |
| `Could not obtain an Entra ID token` | Run `Connect-AzAccount` or `az login` as the account that runs the platform |
| HTTP 401/403 with Entra ID | Assign `Cognitive Services OpenAI User` on the Azure OpenAI resource; role assignments can take a few minutes |
| `Ollama is not reachable` / model not installed | Start Ollama (tray app or `ollama serve`) and run `ollama pull <model>` |
| Ollama results are thin or JSON fails | Use a larger model, depth *Quick*, add a text summary, or raise `Ollama.NumCtx` |
| `Access is denied` when starting with `ListenAddress Any` | Run `Setup-ThreatModelPlatform.ps1 -EnableNetworkAccess` once as Administrator |
| Assessment *Failed – output token limit reached* | Raise `MaxTokens` or use depth *Quick* |
| Diagram area shows "could not be rendered" | `wwwroot/vendor/mermaid.min.js` missing — re-run setup (downloads it) |
| HTTP 401/403 from provider | Check key, model/deployment name, and that the deployment supports images |
| Inspect a failure | `data/assessments/<id>/error.log` and `raw-response.txt` |

Third-party: Mermaid (MIT licence, `wwwroot/vendor/mermaid.LICENSE`).
