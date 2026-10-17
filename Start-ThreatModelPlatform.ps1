#Requires -Version 7.2
<#
.SYNOPSIS
    Starts the AI Threat Modelling Platform web GUI.

.DESCRIPTION
    Hosts a browser-based platform (HttpListener) where any user can upload architecture
    diagrams (PNG/JPG/GIF/WEBP) and/or an architecture summary, select frameworks
    (STRIDE, OWASP Top 10 2025, CIS v8.1, NIST CSF 2.0, NIST SP 800-53, MCSB, OWASP LLM Top 10)
    and receive a threat-mapping diagram, threat register and gap analysis report.
    Assessments run as background jobs so multiple users can work at the same time.

.EXAMPLE
    ./Start-ThreatModelPlatform.ps1                       # uses config/platform.config.json
.EXAMPLE
    ./Start-ThreatModelPlatform.ps1 -Port 9090 -ListenAddress Any   # share on the network (run setup first)
#>
[CmdletBinding()]
param(
    [int]$Port,
    [ValidateSet('Localhost', 'Any')][string]$ListenAddress,
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config/platform.config.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root       = $PSScriptRoot
$EnginePath = Join-Path $Root 'modules/ThreatModel.Engine.psm1'
Import-Module $EnginePath -Force
Import-Module ThreadJob -ErrorAction SilentlyContinue

$Config  = Get-PlatformConfig -Path $ConfigPath
$Catalog = Get-FrameworkCatalog

function CfgVal([string]$Name, $Default) { $p = $Config.PSObject.Properties[$Name]; if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne '') { $p.Value } else { $Default } }

if (-not $Port)          { $Port = [int](CfgVal 'Port' 8080) }
if (-not $ListenAddress) { $ListenAddress = [string](CfgVal 'ListenAddress' 'Localhost') }
$DataPath   = CfgVal 'DataPath' (Join-Path $Root 'data')
if (-not [IO.Path]::IsPathRooted($DataPath)) { $DataPath = [IO.Path]::GetFullPath((Join-Path $Root $DataPath)) }
$AssessRoot = Join-Path $DataPath 'assessments'
New-Item -ItemType Directory -Path $AssessRoot -Force | Out-Null

$MaxUploadMB  = [int](CfgVal 'MaxUploadMB' 40)
$MaxJobs      = [int](CfgVal 'MaxConcurrentJobs' 3)
$AuthMode     = [string](CfgVal 'Authentication' 'None')
$AllowDelete  = [bool](CfgVal 'AllowDelete' $true)
$Provider     = [string](CfgVal 'Provider' 'Anthropic')
$ProviderModel = switch ($Provider) {
    'Anthropic'   { $Config.Anthropic.Model }
    'AzureOpenAI' { "$($Config.AzureOpenAI.Deployment)$(if ($Config.AzureOpenAI.PSObject.Properties['AuthMode'] -and $Config.AzureOpenAI.AuthMode -eq 'EntraId') { ' · Entra ID' })" }
    'Ollama'      { "$(if ($Config.PSObject.Properties['Ollama']) { $Config.Ollama.Model } else { 'qwen2.5vl:7b' }) · local" }
    default       { 'mock (demo data)' }
}
$FrameworkKeys = @($Catalog.PSObject.Properties.Name | Where-Object { $_ -ne 'STRIDE' })
$IdPattern     = '^TM-\d{8}-\d{6}-[a-f0-9]{6}$'
$AllowedMedia  = @{ 'image/png' = 'png'; 'image/jpeg' = 'jpg'; 'image/gif' = 'gif'; 'image/webp' = 'webp' }
$ReportFiles   = @{
    'report.html'       = 'text/html; charset=utf-8'
    'threats.csv'       = 'text/csv; charset=utf-8'
    'gaps.csv'          = 'text/csv; charset=utf-8'
    'model.json'        = 'application/json; charset=utf-8'
    'diagram.mmd'       = 'text/plain; charset=utf-8'
    'threat-model.xlsx' = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
}
$StaticFiles = @{
    '/'                = @('wwwroot/index.html', 'text/html; charset=utf-8')
    '/index.html'      = @('wwwroot/index.html', 'text/html; charset=utf-8')
    '/assets/app.js'   = @('wwwroot/app.js',     'application/javascript; charset=utf-8')
    '/assets/app.css'  = @('wwwroot/app.css',    'text/css; charset=utf-8')
    '/favicon.svg'     = @('wwwroot/favicon.svg','image/svg+xml')
    '/vendor/mermaid.min.js' = @('wwwroot/vendor/mermaid.min.js', 'application/javascript; charset=utf-8')
}

#region ---------- HTTP helpers ----------

function Send-Bytes {
    param($Ctx, [int]$Status, [string]$ContentType, [byte[]]$Bytes, [hashtable]$Headers = @{})
    $r = $Ctx.Response
    $r.StatusCode = $Status
    $r.ContentType = $ContentType
    $r.Headers['X-Content-Type-Options'] = 'nosniff'
    $r.Headers['Referrer-Policy'] = 'no-referrer'
    $r.Headers['X-Frame-Options'] = 'SAMEORIGIN'
    $r.Headers['Cache-Control'] = 'no-store'
    $r.Headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'none'"
    foreach ($k in $Headers.Keys) { $r.Headers[$k] = $Headers[$k] }
    $r.ContentLength64 = $Bytes.Length
    $r.OutputStream.Write($Bytes, 0, $Bytes.Length)
}

function Send-Json {
    param($Ctx, [int]$Status, $Object)
    $json = $Object | ConvertTo-Json -Depth 10 -Compress
    if ($null -eq $Object) { $json = 'null' }
    Send-Bytes $Ctx $Status 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes($json))
}

function Send-Error { param($Ctx, [int]$Status, [string]$Message) Send-Json $Ctx $Status @{ error = $Message } }

function Read-JsonBody {
    param($Ctx)
    $req = $Ctx.Request
    if (-not ($req.ContentType -like 'application/json*')) { throw [System.ArgumentException]'Content-Type must be application/json.' }
    if ($req.ContentLength64 -gt ($MaxUploadMB * 1MB)) { throw [System.ArgumentException]"Request exceeds $MaxUploadMB MB." }
    $reader = [IO.StreamReader]::new($req.InputStream, [Text.Encoding]::UTF8)
    try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
    return $text | ConvertFrom-Json -Depth 10
}

function Test-SameOrigin {
    # CSRF defence for state-changing requests: Origin (if sent) must match Host
    param($Ctx)
    $origin = $Ctx.Request.Headers['Origin']
    if (-not $origin) { return $true }
    try { return ([Uri]$origin).Authority -eq $Ctx.Request.Headers['Host'] } catch { return $false }
}

function Get-RequestUser {
    param($Ctx)
    if ($Ctx.User -and $Ctx.User.Identity -and $Ctx.User.Identity.IsAuthenticated) { return $Ctx.User.Identity.Name }
    $ip = try { $Ctx.Request.RemoteEndPoint.Address.ToString() } catch { 'unknown' }
    return "anonymous@$ip"
}

function Test-ImageMagic {
    param([byte[]]$B, [string]$Media)
    if ($B.Length -lt 12) { return $false }
    switch ($Media) {
        'image/png'  { return ($B[0] -eq 0x89 -and $B[1] -eq 0x50 -and $B[2] -eq 0x4E -and $B[3] -eq 0x47) }
        'image/jpeg' { return ($B[0] -eq 0xFF -and $B[1] -eq 0xD8 -and $B[2] -eq 0xFF) }
        'image/gif'  { return ($B[0] -eq 0x47 -and $B[1] -eq 0x49 -and $B[2] -eq 0x46) }
        'image/webp' { return ([Text.Encoding]::ASCII.GetString($B, 0, 4) -eq 'RIFF' -and [Text.Encoding]::ASCII.GetString($B, 8, 4) -eq 'WEBP') }
    }
    return $false
}

function Read-JsonFile { param([string]$Path) if (Test-Path -LiteralPath $Path) { Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 20 } }

function Get-Str { param($Obj, [string]$Name, [int]$Max = 200, [string]$Default = '')
    $p = $Obj.PSObject.Properties[$Name]
    if (-not $p -or $null -eq $p.Value) { return $Default }
    $s = ([string]$p.Value).Trim()
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) }
    if ($s) { return $s } else { return $Default }
}

#endregion

#region ---------- API handlers ----------

function New-Assessment {
    param($Ctx)
    $body = Read-JsonBody $Ctx
    $name = Get-Str $body 'name' 120
    if (-not $name) { throw [System.ArgumentException]'Assessment name is required.' }
    $summary = Get-Str $body 'summary' 150000
    $images  = @(if ($body.PSObject.Properties['images'] -and $body.images) { $body.images })
    if (-not $summary -and $images.Count -eq 0) { throw [System.ArgumentException]'Provide at least one architecture image or an architecture summary.' }
    if ($images.Count -gt 5) { throw [System.ArgumentException]'A maximum of 5 images is allowed per assessment.' }

    $frameworks = @(@(if ($body.PSObject.Properties['frameworks']) { $body.frameworks }) | ForEach-Object { [string]$_ } | Where-Object { $FrameworkKeys -contains $_ } | Select-Object -Unique)
    if ($frameworks.Count -eq 0) { $frameworks = @('OWASP', 'CIS', 'NIST_CSF', 'NIST_80053', 'MCSB') }
    $depth = Get-Str $body 'depth' 10 'Standard'; if ($depth -notin 'Quick', 'Standard', 'Deep') { $depth = 'Standard' }

    $id  = 'TM-{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 6))
    $dir = Join-Path $AssessRoot $id
    $in  = Join-Path $dir 'input'
    New-Item -ItemType Directory -Path $in -Force | Out-Null

    $saved = [System.Collections.Generic.List[object]]::new()
    $i = 0
    try {
        foreach ($img in $images) {
            $i++
            $media = [string]$img.mediaType
            if (-not $AllowedMedia.ContainsKey($media)) { throw [System.ArgumentException]"Image $i has unsupported type '$media'. Use PNG, JPEG, GIF or WEBP." }
            $bytes = [Convert]::FromBase64String([string]$img.data)
            if (-not (Test-ImageMagic $bytes $media)) { throw [System.ArgumentException]"Image $i is not a valid $media file." }
            if ($bytes.Length -gt 7MB) { throw [System.ArgumentException]"Image $i is larger than 7 MB after processing. Please export a smaller image." }
            $file = "diagram-$i.$($AllowedMedia[$media])"
            [IO.File]::WriteAllBytes((Join-Path $in $file), $bytes)
            $orig = (Get-Str $img 'fileName' 150) -replace '[^\w\.\- ]', '_'
            $saved.Add([ordered]@{ file = $file; mediaType = $media; originalName = $orig; bytes = $bytes.Length })
        }
    } catch { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; throw }
    if ($summary) { Set-Content -LiteralPath (Join-Path $in 'summary.md') -Value $summary -Encoding utf8 }

    $request = [ordered]@{
        id = $id; name = $name
        owner = Get-Str $body 'owner' 120; environment = Get-Str $body 'environment' 40 'Not specified'
        criticality = Get-Str $body 'criticality' 40 'Not specified'; dataClassification = Get-Str $body 'dataClassification' 40 'Not specified'
        depth = $depth; frameworks = $frameworks; images = $saved; hasSummary = [bool]$summary
        requestedBy = Get-RequestUser $Ctx; createdAt = (Get-Date).ToUniversalTime().ToString('o')
    }
    $request | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $dir 'request.json') -Encoding utf8
    Set-AssessmentStatus -AssessmentPath $dir -State Queued -Message 'Waiting for an analysis slot…'

    Start-ThreadJob -Name $id -ThrottleLimit $MaxJobs -ArgumentList $EnginePath, $dir, $ConfigPath -ScriptBlock {
        param($enginePath, $dir, $cfgPath)
        Import-Module $enginePath -Force
        Invoke-ThreatAssessment -AssessmentPath $dir -Config (Get-PlatformConfig -Path $cfgPath) -ErrorAction SilentlyContinue
    } | Out-Null

    Write-Host ("  ▶ queued {0}  '{1}'  images={2} summary={3} frameworks={4}" -f $id, $name, $saved.Count, [bool]$summary, ($frameworks -join ',')) -ForegroundColor Cyan
    Send-Json $Ctx 202 @{ id = $id; state = 'Queued' }
}

function Get-AssessmentSummary {
    param([string]$Dir)
    $req = Read-JsonFile (Join-Path $Dir 'request.json')
    $st  = Read-JsonFile (Join-Path $Dir 'status.json')
    if (-not $req) { return $null }
    $o = [ordered]@{
        id = $req.id; name = $req.name; owner = $req.owner; environment = $req.environment; criticality = $req.criticality
        dataClassification = $req.dataClassification; depth = $req.depth; frameworks = $req.frameworks
        requestedBy = $req.requestedBy; createdAt = $req.createdAt
        imageCount = @($req.images).Count; hasSummary = $req.hasSummary
        state = 'Unknown'; message = ''; updatedAt = $null
    }
    if ($st) { foreach ($p in $st.PSObject.Properties) { $o[$p.Name] = $p.Value } }
    $o['files'] = @($ReportFiles.Keys | Where-Object { Test-Path -LiteralPath (Join-Path $Dir $_) })
    return $o
}

function Get-AssessmentList {
    param($Ctx)
    $items = Get-ChildItem -LiteralPath $AssessRoot -Directory | Where-Object { $_.Name -match $IdPattern } |
             Sort-Object Name -Descending | Select-Object -First 500 | ForEach-Object { Get-AssessmentSummary $_.FullName } | Where-Object { $_ }
    Send-Json $Ctx 200 @{ items = @($items) }
}

#endregion

#region ---------- Startup ----------

# Any assessment left mid-flight by a previous run can never finish - mark it failed.
Get-ChildItem -LiteralPath $AssessRoot -Directory | ForEach-Object {
    $st = Read-JsonFile (Join-Path $_.FullName 'status.json')
    if ($st -and $st.state -in 'Queued', 'Analyzing', 'Rendering') {
        Set-AssessmentStatus -AssessmentPath $_.FullName -State Failed -Message 'Interrupted because the platform was restarted. Please submit again.'
    }
}

$problem = Test-ProviderReady -Config $Config
if ($problem) {
    Write-Warning "AI provider '$Provider' is not ready: $problem"
    Write-Warning 'The web UI will start, but assessments will fail until this is fixed (re-run Setup-ThreatModelPlatform.ps1).'
}

$listener = [System.Net.HttpListener]::new()
$hostPart = if ($ListenAddress -eq 'Any') { if ($IsWindows) { '+' } else { '*' } } else { 'localhost' }
$listener.Prefixes.Add("http://${hostPart}:$Port/")
if ($AuthMode -eq 'Windows') {
    $listener.AuthenticationSchemes = [System.Net.AuthenticationSchemes]::IntegratedWindowsAuthentication
}
try { $listener.Start() }
catch {
    Write-Host "Could not listen on http://${hostPart}:$Port/ - $($_.Exception.Message)" -ForegroundColor Red
    if ($IsWindows -and $ListenAddress -eq 'Any') {
        Write-Host "For network access run Setup-ThreatModelPlatform.ps1 -EnableNetworkAccess as Administrator once (adds the URL ACL and firewall rule)." -ForegroundColor Yellow
    }
    exit 1
}

$displayHost = if ($ListenAddress -eq 'Any') { [System.Net.Dns]::GetHostName() } else { 'localhost' }
Write-Host ''
Write-Host '  ╔══════════════════════════════════════════════════════════╗' -ForegroundColor DarkCyan
Write-Host '  ║          AI Threat Modelling Platform  — running          ║' -ForegroundColor DarkCyan
Write-Host '  ╚══════════════════════════════════════════════════════════╝' -ForegroundColor DarkCyan
Write-Host "   URL        : http://${displayHost}:$Port/" -ForegroundColor Green
Write-Host "   AI provider: $Provider ($ProviderModel)"
Write-Host "   Auth       : $AuthMode    Data: $AssessRoot"
Write-Host "   Press Ctrl+C to stop."
Write-Host ''

#endregion

#region ---------- Request loop ----------

try {
    while ($listener.IsListening) {
        $task = $listener.GetContextAsync()
        while (-not $task.Wait(500)) {
            Get-Job -State Completed, Failed, Stopped -ErrorAction SilentlyContinue | Where-Object Name -match $IdPattern | Remove-Job -Force
        }
        $ctx = $task.Result
        $req = $ctx.Request
        $path = $req.Url.AbsolutePath
        $method = $req.HttpMethod
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $who = Get-RequestUser $ctx
        try {
            if ($method -eq 'GET' -and $StaticFiles.ContainsKey($path)) {
                $f = $StaticFiles[$path]
                $fp = Join-Path $Root $f[0]
                if (-not (Test-Path -LiteralPath $fp)) { Send-Error $ctx 404 'Not found.' }
                else { Send-Bytes $ctx 200 $f[1] ([IO.File]::ReadAllBytes($fp)) @{ 'Cache-Control' = $(if ($path -like '/vendor/*') { 'public, max-age=86400' } else { 'no-cache' }) } }
            }
            elseif ($method -eq 'GET' -and $path -eq '/api/config') {
                $fws = foreach ($k in $Catalog.PSObject.Properties.Name) {
                    $fw = $Catalog.$k
                    [ordered]@{ key = $k; name = $fw.name; version = $fw.version
                        alwaysOn = [bool]($fw.PSObject.Properties['alwaysOn'] -and $fw.alwaysOn)
                        optional = [bool]($fw.PSObject.Properties['optional'] -and $fw.optional) }
                }
                Send-Json $ctx 200 @{ provider = $Provider; model = $ProviderModel; frameworks = @($fws); maxImages = 5; allowDelete = $AllowDelete; user = (Get-RequestUser $ctx) }
            }
            elseif ($path -eq '/api/assessments' -and $method -eq 'GET') { Get-AssessmentList $ctx }
            elseif ($path -eq '/api/assessments' -and $method -eq 'POST') {
                if (-not (Test-SameOrigin $ctx)) { Send-Error $ctx 403 'Cross-origin request rejected.' } else { New-Assessment $ctx }
            }
            elseif ($path -match '^/api/assessments/([^/]+)$') {
                $id = $Matches[1]
                $dir = Join-Path $AssessRoot $id
                if ($id -notmatch $IdPattern -or -not (Test-Path -LiteralPath $dir)) { Send-Error $ctx 404 'Assessment not found.' }
                elseif ($method -eq 'GET') { Send-Json $ctx 200 (Get-AssessmentSummary $dir) }
                elseif ($method -eq 'DELETE') {
                    $st = Read-JsonFile (Join-Path $dir 'status.json')
                    if (-not $AllowDelete) { Send-Error $ctx 403 'Deletion is disabled on this platform.' }
                    elseif (-not (Test-SameOrigin $ctx)) { Send-Error $ctx 403 'Cross-origin request rejected.' }
                    elseif ($st -and $st.state -in 'Queued', 'Analyzing', 'Rendering') { Send-Error $ctx 409 'Assessment is still running.' }
                    else { Remove-Item -LiteralPath $dir -Recurse -Force; Send-Json $ctx 200 @{ deleted = $id } }
                }
                else { Send-Error $ctx 405 'Method not allowed.' }
            }
            elseif ($method -eq 'GET' -and $path -match '^/reports/([^/]+)/([^/]+)$') {
                $id = $Matches[1]; $file = $Matches[2]
                $full = Join-Path (Join-Path $AssessRoot $id) $file
                if ($id -notmatch $IdPattern -or -not $ReportFiles.ContainsKey($file) -or -not (Test-Path -LiteralPath $full)) { Send-Error $ctx 404 'File not found.' }
                else {
                    $hdr = @{}
                    if ($req.QueryString['download'] -eq '1' -or $file -ne 'report.html') { $hdr['Content-Disposition'] = "attachment; filename=`"$id-$file`"" }
                    Send-Bytes $ctx 200 $ReportFiles[$file] ([IO.File]::ReadAllBytes($full)) $hdr
                }
            }
            elseif ($method -eq 'GET' -and $path -eq '/healthz') { Send-Json $ctx 200 @{ status = 'ok' } }
            else { Send-Error $ctx 404 'Not found.' }
        }
        catch [System.ArgumentException] { try { Send-Error $ctx 400 $_.Exception.Message } catch { } }
        catch {
            Write-Host "  ✖ $method $path : $($_.Exception.Message)" -ForegroundColor Red
            try { Send-Error $ctx 500 'Internal server error. See the platform console for details.' } catch { }
        }
        finally {
            $code = try { $ctx.Response.StatusCode } catch { 0 }
            try { $ctx.Response.Close() } catch { }
            if ($path -notmatch '^/(assets|favicon|vendor)' -and -not ($method -eq 'GET' -and $path -match '^/api/assessments')) {
                try { Write-Host ("  {0:HH:mm:ss}  {1,-6} {2,-45} {3}  {4}ms  {5}" -f (Get-Date), $method, $path, $code, $sw.ElapsedMilliseconds, $who) -ForegroundColor DarkGray } catch { }
            }
        }
    }
}
finally {
    $listener.Stop(); $listener.Close()
    Write-Host 'Platform stopped.' -ForegroundColor Yellow
}

#endregion
