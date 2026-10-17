#Requires -Version 7.2
<#
.SYNOPSIS
    One-time setup for the AI Threat Modelling Platform.

.DESCRIPTION
    * Verifies PowerShell 7.2+ and required modules
    * Configures the AI provider: Azure OpenAI with Entra ID (no API key), Ollama (local, no key),
      Anthropic Claude (API key) or Mock (demo)
    * Stores any API key as a user environment variable (never in the config file)
    * Optionally opens the platform to your network (URL ACL + firewall rule, Windows, run as Administrator)
    * Optionally enables Windows Integrated Authentication so every report records who requested it

.EXAMPLE
    ./Setup-ThreatModelPlatform.ps1
    Interactive setup.

.EXAMPLE
    ./Setup-ThreatModelPlatform.ps1 -Provider Anthropic -Model claude-opus-5-5 -Port 8080
.EXAMPLE
    # As Administrator - share the platform with your team on the corporate network, with Windows sign-in
    ./Setup-ThreatModelPlatform.ps1 -EnableNetworkAccess -UseWindowsAuth -Port 8080
#>
[CmdletBinding()]
param(
    [ValidateSet('AzureOpenAI', 'Ollama', 'Anthropic', 'Mock')][string]$Provider,
    [string]$Model,
    [ValidateSet('EntraId', 'ApiKey')][string]$AzureAuth = 'EntraId',
    [string]$AzureEndpoint,
    [string]$AzureDeployment,
    [int]$Port,
    [switch]$EnableNetworkAccess,
    [switch]$UseWindowsAuth,
    [switch]$SkipApiKey,
    [switch]$InstallExcelExport
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$ConfigPath = Join-Path $Root 'config/platform.config.json'

function Write-Step($t) { Write-Host "`n▶ $t" -ForegroundColor Cyan }
function Write-Ok($t)   { Write-Host "  ✔ $t" -ForegroundColor Green }
function Write-Note($t) { Write-Host "  • $t" -ForegroundColor Gray }

Write-Host "`n  AI Threat Modelling Platform — setup" -ForegroundColor White

# ---------------------------------------------------------------- prerequisites
Write-Step 'Checking prerequisites'
Write-Ok "PowerShell $($PSVersionTable.PSVersion) on $([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)"
if (-not (Get-Module -ListAvailable ThreadJob)) {
    Write-Note 'Installing ThreadJob module (CurrentUser)…'
    Install-Module ThreadJob -Scope CurrentUser -Force -AllowClobber
}
Write-Ok 'ThreadJob module available'

if ($InstallExcelExport -or ((-not (Get-Module -ListAvailable ImportExcel)) -and -not $PSBoundParameters.ContainsKey('Provider') -and
    (Read-Host '  Install ImportExcel to also produce .xlsx workbooks? (y/N)') -match '^[yY]')) {
    Install-Module ImportExcel -Scope CurrentUser -Force
}
if (Get-Module -ListAvailable ImportExcel) { Write-Ok 'ImportExcel available (Excel export enabled)' } else { Write-Note 'ImportExcel not installed - CSV exports only' }

$vendor = Join-Path $Root 'wwwroot/vendor/mermaid.min.js'
if (-not (Test-Path $vendor)) {
    Write-Note 'Downloading Mermaid diagram library…'
    New-Item -ItemType Directory -Path (Split-Path $vendor) -Force | Out-Null
    try { Invoke-WebRequest 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js' -OutFile $vendor -UseBasicParsing; Write-Ok 'Mermaid library downloaded' }
    catch { Write-Warning 'Could not download Mermaid; reports will try the public CDN at view time.' }
} else { Write-Ok 'Mermaid diagram library bundled' }

# ---------------------------------------------------------------- config
$cfg = if (Test-Path $ConfigPath) { Get-Content $ConfigPath -Raw | ConvertFrom-Json -AsHashtable } else { [ordered]@{} }
$defaults = [ordered]@{
    Provider = 'Mock'; Port = 8080; ListenAddress = 'Localhost'; Authentication = 'None'
    DataPath = './data'; MaxUploadMB = 40; MaxConcurrentJobs = 3; AllowDelete = $true
    Anthropic = [ordered]@{ Model = 'claude-opus-5-5'; MaxTokens = 16000; ApiKeyEnvVar = 'ANTHROPIC_API_KEY'; ApiKeySecretName = '' }
    AzureOpenAI = [ordered]@{ Endpoint = ''; Deployment = ''; ApiVersion = '2024-10-21'; AuthMode = 'EntraId'; ApiKeyEnvVar = 'AZURE_OPENAI_API_KEY'; MaxTokens = 16000; MaxTokensParam = 'max_completion_tokens'; ApiKeySecretName = '' }
    Ollama = [ordered]@{ Endpoint = 'http://localhost:11434'; Model = 'qwen2.5vl:7b'; NumCtx = 32768; MaxTokens = 12000; Temperature = 0.2; TimeoutSec = 3600 }
}
foreach ($k in $defaults.Keys) {
    if (-not $cfg.Contains($k)) { $cfg[$k] = $defaults[$k] }
    elseif ($defaults[$k] -is [System.Collections.IDictionary]) {
        foreach ($sk in $defaults[$k].Keys) { if (-not $cfg[$k].Contains($sk)) { $cfg[$k][$sk] = $defaults[$k][$sk] } }
    }
}

Write-Step 'AI provider'
if (-not $Provider) {
    Write-Host '   1) Azure OpenAI + Entra ID   - NO API KEY: uses your Azure sign-in / managed identity; data stays in your tenant'
    Write-Host '   2) Ollama (local model)      - NO API KEY, free, fully offline; needs 16 GB+ RAM (GPU recommended)'
    Write-Host '   3) Anthropic Claude          - needs an Anthropic API key'
    Write-Host '   4) Mock                      - demo data only, for trying the UI'
    $choice = Read-Host "  Choose 1-4 [current: $($cfg.Provider)]"
    $Provider = switch ($choice) { '1' { 'AzureOpenAI' } '2' { 'Ollama' } '3' { 'Anthropic' } '4' { 'Mock' } default { $cfg.Provider } }
}
$cfg.Provider = $Provider
Write-Ok "Provider: $Provider"

function Save-UserSecretEnv([string]$Name, [string]$Prompt) {
    $sec = Read-Host "  $Prompt (input hidden, Enter to keep existing)" -AsSecureString
    $plain = [System.Net.NetworkCredential]::new('', $sec).Password
    if (-not $plain) { Write-Note "Keeping existing $Name"; return }
    [Environment]::SetEnvironmentVariable($Name, $plain, 'Process')
    if ($IsWindows) {
        [Environment]::SetEnvironmentVariable($Name, $plain, 'User')
        Write-Ok "Stored in user environment variable $Name (open a new PowerShell window before starting the platform)"
    } else {
        Write-Warning "On Linux/macOS add this to your PowerShell profile or service definition:  `$env:$Name = '<key>'"
    }
}

switch ($Provider) {
    'Anthropic' {
        if ($Model) { $cfg.Anthropic.Model = $Model }
        elseif (-not $PSBoundParameters.ContainsKey('Provider')) {
            $m = Read-Host "  Claude model [$($cfg.Anthropic.Model)]"; if ($m) { $cfg.Anthropic.Model = $m }
        }
        if (-not $SkipApiKey) { Save-UserSecretEnv $cfg.Anthropic.ApiKeyEnvVar 'Anthropic API key (sk-ant-…)' }
        Write-Ok "Model: $($cfg.Anthropic.Model)"
    }
    'AzureOpenAI' {
        if ($AzureEndpoint)   { $cfg.AzureOpenAI.Endpoint = $AzureEndpoint }   elseif (-not $cfg.AzureOpenAI.Endpoint)   { $cfg.AzureOpenAI.Endpoint = Read-Host '  Azure OpenAI endpoint (https://<name>.openai.azure.com)' }
        if ($AzureDeployment) { $cfg.AzureOpenAI.Deployment = $AzureDeployment } elseif (-not $cfg.AzureOpenAI.Deployment) { $cfg.AzureOpenAI.Deployment = Read-Host '  Deployment name of a vision-capable model (e.g. gpt-4o / gpt-4.1)' }
        $cfg.AzureOpenAI.AuthMode = $AzureAuth
        Write-Ok "Endpoint: $($cfg.AzureOpenAI.Endpoint)  Deployment: $($cfg.AzureOpenAI.Deployment)  Auth: $AzureAuth"
        if ($AzureAuth -eq 'ApiKey') {
            if (-not $SkipApiKey) { Save-UserSecretEnv $cfg.AzureOpenAI.ApiKeyEnvVar 'Azure OpenAI API key' }
        } else {
            Write-Note 'Keyless: the platform signs in with Az PowerShell (Connect-AzAccount), Azure CLI (az login) or the machine''s managed identity.'
            Write-Note "That identity needs the 'Cognitive Services OpenAI User' role on the Azure OpenAI resource."
            try {
                Import-Module (Join-Path $Root 'modules/ThreatModel.Engine.psm1') -Force
                [void](Get-EntraAccessToken)
                Write-Ok 'Entra ID token acquired successfully'
            } catch {
                Write-Warning 'No Azure sign-in found yet. Before starting the platform run ONE of:'
                Write-Host  '      Connect-AzAccount            (Install-Module Az.Accounts -Scope CurrentUser)' -ForegroundColor Yellow
                Write-Host  '      az login                     (Azure CLI)' -ForegroundColor Yellow
            }
        }
    }
    'Ollama' {
        if ($Model) { $cfg.Ollama.Model = $Model }
        elseif (-not $PSBoundParameters.ContainsKey('Provider')) {
            Write-Note 'Suggested vision models: qwen2.5vl:7b (best for diagrams, ~6 GB), llama3.2-vision:11b (~8 GB), gemma3:12b (~8 GB)'
            $m = Read-Host "  Ollama model [$($cfg.Ollama.Model)]"; if ($m) { $cfg.Ollama.Model = $m }
        }
        $ollama = Get-Command ollama -ErrorAction SilentlyContinue
        if (-not $ollama) {
            Write-Warning 'Ollama is not installed. Install it, then re-run this setup:'
            if ($IsWindows) { Write-Host '      winget install Ollama.Ollama      (or download from https://ollama.com/download)' -ForegroundColor Yellow }
            else { Write-Host '      https://ollama.com/download' -ForegroundColor Yellow }
        } else {
            Write-Ok "Ollama found: $($ollama.Source)"
            $have = (& ollama list 2>$null) -match [regex]::Escape(($cfg.Ollama.Model -replace ':latest$', ''))
            if (-not $have) {
                $ans = if ($PSBoundParameters.ContainsKey('Provider')) { 'y' } else { Read-Host "  Download model $($cfg.Ollama.Model) now? (Y/n)" }
                if ($ans -notmatch '^[nN]') { & ollama pull $cfg.Ollama.Model }
            } else { Write-Ok "Model $($cfg.Ollama.Model) is installed" }
        }
        Write-Note 'Local models are slower than cloud AI: expect 3-15 minutes per assessment on a typical laptop (GPU much faster).'
    }
    'Mock' { Write-Note 'Mock provider returns a fixed demo threat model regardless of the upload.' }
}

# ---------------------------------------------------------------- network / auth
Write-Step 'Web access'
if ($Port) { $cfg.Port = $Port }
if ($UseWindowsAuth) { $cfg.Authentication = 'Windows'; Write-Ok 'Windows Integrated Authentication enabled (users sign in with their domain account)' }

if ($EnableNetworkAccess) {
    $cfg.ListenAddress = 'Any'
    if ($IsWindows) {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) { throw 'Run PowerShell as Administrator to use -EnableNetworkAccess (needed once for the URL ACL and firewall rule).' }
        $url = "http://+:$($cfg.Port)/"
        $runAs = "$env:USERDOMAIN\$env:USERNAME"
        & netsh http delete urlacl url=$url 2>$null | Out-Null
        & netsh http add urlacl url=$url user="$runAs" | Out-Null
        Write-Ok "URL ACL $url granted to $runAs"
        $ruleName = "AI Threat Modelling Platform (TCP $($cfg.Port))"
        Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $cfg.Port -Action Allow -Profile Domain, Private | Out-Null
        Write-Ok "Firewall rule '$ruleName' (Domain/Private profiles)"
    }
    Write-Ok "Platform will listen on all interfaces, port $($cfg.Port)"
} else {
    Write-Note "Listening on localhost:$($cfg.Port) only (use -EnableNetworkAccess to share with your team)"
}

$cfg | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigPath -Encoding utf8
Write-Ok "Configuration saved: $ConfigPath"

Write-Host "`n  Setup complete. Start the platform with:" -ForegroundColor White
Write-Host "    pwsh -File `"$(Join-Path $Root 'Start-ThreatModelPlatform.ps1')`"" -ForegroundColor Yellow
$hostName = if ($cfg.ListenAddress -eq 'Any') { [System.Net.Dns]::GetHostName() } else { 'localhost' }
Write-Host "  then browse to  http://${hostName}:$($cfg.Port)/`n" -ForegroundColor Yellow
