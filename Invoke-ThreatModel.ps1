#Requires -Version 7.2
<#
.SYNOPSIS
    Headless / command-line threat model (same engine as the web platform).
    Results also appear in the web platform's Assessments list.

.EXAMPLE
    ./Invoke-ThreatModel.ps1 -Name 'Payments API' -ImagePath .\arch.png -SummaryPath .\arch.md
.EXAMPLE
    ./Invoke-ThreatModel.ps1 -Name 'RAG Chatbot' -SummaryPath .\rag.md -Frameworks OWASP,OWASP_LLM,MCSB -Depth Deep -Open
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Name,
    [string[]]$ImagePath = @(),
    [string]$SummaryPath,
    [ValidateSet('OWASP', 'OWASP_LLM', 'CIS', 'NIST_CSF', 'NIST_80053', 'MCSB')]
    [string[]]$Frameworks = @('OWASP', 'CIS', 'NIST_CSF', 'NIST_80053', 'MCSB'),
    [ValidateSet('Quick', 'Standard', 'Deep')][string]$Depth = 'Standard',
    [string]$Owner = $env:USERNAME,
    [string]$Environment = 'Production',
    [string]$Criticality = 'High',
    [string]$DataClassification = 'Confidential',
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config/platform.config.json'),
    [switch]$Open
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'modules/ThreatModel.Engine.psm1') -Force
$config = Get-PlatformConfig -Path $ConfigPath

if (-not $ImagePath -and -not $SummaryPath) { throw 'Provide -ImagePath and/or -SummaryPath.' }
$dataPath = if ($config.PSObject.Properties['DataPath'] -and $config.DataPath) { $config.DataPath } else { './data' }
if (-not [IO.Path]::IsPathRooted($dataPath)) { $dataPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $dataPath)) }

$id  = 'TM-{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 6))
$dir = Join-Path $dataPath "assessments/$id"
$in  = Join-Path $dir 'input'
New-Item -ItemType Directory -Path $in -Force | Out-Null

$mediaMap = @{ '.png' = 'image/png'; '.jpg' = 'image/jpeg'; '.jpeg' = 'image/jpeg'; '.gif' = 'image/gif'; '.webp' = 'image/webp' }
$images = @(); $i = 0
foreach ($p in $ImagePath) {
    $i++; $ext = [IO.Path]::GetExtension($p).ToLower()
    if (-not $mediaMap[$ext]) { throw "Unsupported image type: $p (use PNG/JPG/GIF/WEBP)" }
    if ((Get-Item $p).Length -gt 7MB) { throw "$p is larger than 7 MB - export a smaller image." }
    $file = "diagram-$i$($ext -replace '\.jpeg', '.jpg')"
    Copy-Item -LiteralPath $p -Destination (Join-Path $in $file)
    $images += [ordered]@{ file = $file; mediaType = $mediaMap[$ext]; originalName = (Split-Path $p -Leaf) }
}
if ($SummaryPath) { Copy-Item -LiteralPath $SummaryPath -Destination (Join-Path $in 'summary.md') }

[ordered]@{
    id = $id; name = $Name; owner = $Owner; environment = $Environment; criticality = $Criticality
    dataClassification = $DataClassification; depth = $Depth; frameworks = $Frameworks; images = $images
    hasSummary = [bool]$SummaryPath; requestedBy = "cli:$env:USERNAME"; createdAt = (Get-Date).ToUniversalTime().ToString('o')
} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $dir 'request.json') -Encoding utf8

Write-Host "Running threat model $id with $($config.Provider)…" -ForegroundColor Cyan
Invoke-ThreatAssessment -AssessmentPath $dir -Config $config -ErrorAction SilentlyContinue
$status = Get-Content (Join-Path $dir 'status.json') -Raw | ConvertFrom-Json
if ($status.state -ne 'Completed') { throw "Assessment failed: $($status.message)" }

Write-Host ("Done in {0}s - exposure {1}/100 ({2}), {3} threats, {4} gaps" -f $status.durationSec, $status.exposureScore, $status.exposureRating, $status.threats, $status.gaps) -ForegroundColor Green
Write-Host "Report: $(Join-Path $dir 'report.html')"
if ($Open) { Invoke-Item (Join-Path $dir 'report.html') }
Get-Item (Join-Path $dir 'report.html')
