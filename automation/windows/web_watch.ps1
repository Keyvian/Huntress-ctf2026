# Huntress CTF 2026 - deterministic WEB-lane watchdog (0 LLM tokens on the happy path).
# Scheduled in a bounded morning window (08:50-12:50 ET, every 5 min). Clears any unsolved web
# mode via webrun.backlog(). On ALERT (a web mode it could NOT auto-solve = likely a NEW vuln
# type webrun.py doesn't handle yet) it AUTO-LAUNCHES a headless Claude triage agent
# (web_triage.ps1), with anti-runaway guardrails. Known types cost nothing (no agent).
$ErrorActionPreference = "Continue"
$Auto      = "C:\\Users\\<user>\Documents\Huntress CTF\auto"
$LogDir    = Join-Path $Auto "logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$Log       = Join-Path $LogDir "webwatch.log"
$StateFile = Join-Path $Auto ".webwatch_state.json"
function Note($m) { Add-Content -Path $Log -Value ("{0}  {1}" -f (Get-Date).ToString("s"), $m) -Encoding utf8 }

# --- run the deterministic monitor in WSL ---
$out = ""
try { $out = (wsl.exe -e bash -lc '~/ctf-venv/bin/python ~/ctf/webwatch.py' 2>$null | Out-String) }
catch { Note ("wsl invoke error: " + $_.Exception.Message) }
$code = $LASTEXITCODE
$line = ($out -split "`r?`n" | Where-Object { $_ -match '^WEBWATCH ' } | Select-Object -Last 1)
if (-not $line) { $line = "WEBWATCH (no state line; wsl exit $code)"; if (-not $code) { $code = 2 } }
Note ("exit=$code  $line")

# --- load toast/triage state (dedup so a 5-min cadence never spams or over-launches) ---
$prev = @{ alertSig = ""; alertAt = "2000-01-01T00:00:00"; warnAt = "2000-01-01T00:00:00";
           triageAt = "2000-01-01T00:00:00"; triageDay = ""; triageCount = 0; triageResultAt = "" }
if (Test-Path $StateFile) {
  try {
    $j = Get-Content $StateFile -Raw | ConvertFrom-Json
    if ($j.alertSig)  { $prev.alertSig  = [string]$j.alertSig }
    if ($j.alertAt)   { $prev.alertAt   = [string]$j.alertAt }
    if ($j.warnAt)    { $prev.warnAt    = [string]$j.warnAt }
    if ($j.triageAt)  { $prev.triageAt  = [string]$j.triageAt }
    if ($j.triageDay) { $prev.triageDay = [string]$j.triageDay }
    if ($null -ne $j.triageCount)   { $prev.triageCount    = [int]$j.triageCount }
    if ($j.triageResultAt) { $prev.triageResultAt = [string]$j.triageResultAt }
  } catch {}
}
$now = Get-Date
$toast = $null

if ($code -eq 2) {
  # ALERT: a web mode could NOT be auto-solved -> likely a NEW vuln type. Auto-launch a
  # headless Claude triage agent, guarded against runaway (user opted in 2026-10-20).
  $sig = $line -replace '.*(FAILED:.*)$', '$1'
  $lastAlert = try { [datetime]$prev.alertAt } catch { [datetime]::MinValue }

  $today = $now.ToString("yyyy-MM-dd")
  if ($prev.triageDay -ne $today) { $prev.triageDay = $today; $prev.triageCount = 0 }
  $triageLast = try { [datetime]$prev.triageAt } catch { [datetime]::MinValue }

  # is a triage agent already running? (lock file w/ a live PID, younger than 75 min)
  $running = $false
  $lock = Join-Path $Auto ".web_triage.lock"
  if (Test-Path $lock) {
    try {
      $lk = Get-Content $lock -Raw | ConvertFrom-Json
      if ($lk.pid -and (Get-Process -Id ([int]$lk.pid) -ErrorAction SilentlyContinue)) { $running = $true }
      if ($running -and $lk.startedAt -and (($now - [datetime]$lk.startedAt).TotalMinutes -gt 75)) { $running = $false }
    } catch { $running = $true }  # unreadable lock -> assume running; don't double-launch
  }

  $MAX_PER_DAY = 4
  $MIN_SPACING_MIN = 20
  $canLaunch = (-not $running) -and ([int]$prev.triageCount -lt $MAX_PER_DAY) -and `
               (($now - $triageLast).TotalMinutes -ge $MIN_SPACING_MIN)

  if ($canLaunch) {
    $triageScript = Join-Path $Auto "web_triage.ps1"
    try {
      $p = Start-Process -FilePath "powershell.exe" -WindowStyle Hidden -PassThru `
             -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File',"`"$triageScript`""
      $prev.triageAt = $now.ToString("s"); $prev.triageCount = [int]$prev.triageCount + 1
      Note ("TRIAGE LAUNCHED #$($prev.triageCount) pid=$($p.Id): $line")
      $toast = "Huntress WebWatch - NEW web type? auto-triage LANCE ($($prev.triageCount)/$MAX_PER_DAY): " + $line
    } catch {
      Note ("triage launch FAILED: " + $_.Exception.Message)
      $toast = "Huntress WebWatch - ATTENTION (new web type?) triage launch FAILED: " + $line
    }
  } else {
    $reason = if ($running) { "triage deja en cours" } elseif ([int]$prev.triageCount -ge $MAX_PER_DAY) { "cap $MAX_PER_DAY/jour atteint" } else { "espacement<$MIN_SPACING_MIN min" }
    Note ("triage skipped ($reason)")
    if ($sig -ne $prev.alertSig -or ($now - $lastAlert).TotalMinutes -ge 20) {
      $toast = "Huntress WebWatch - ATTENTION (new web type?, $reason): " + $line
    }
  }
  $prev.alertSig = $sig; $prev.alertAt = $now.ToString("s")
}
elseif ($line -match 'SOLVED:\s*([^|]+)') {
  # a web mode was just auto-solved by the deterministic solver -> surface (only on this run)
  $toast = "Huntress WebWatch - AUTO-SOLVED: " + ($Matches[1].Trim())
  $prev.alertSig = ""
}
elseif ($code -eq 1) {
  # WARN: a non-web lane reads unsolved (maybe status lag) -> at most one toast / 2h
  $lastWarn = try { [datetime]$prev.warnAt } catch { [datetime]::MinValue }
  if (($now - $lastWarn).TotalHours -ge 2) {
    $toast = "Huntress WebWatch - check lanes: " + $line
    $prev.warnAt = $now.ToString("s")
  }
}
else {
  # OK: clear the alert signature so the next real alert toasts/launches immediately
  $prev.alertSig = ""
}

# --- relay a finished triage agent's RESULT from the reliable task session ---
$resFile = Join-Path $Auto ".web_triage_result.json"
if (Test-Path $resFile) {
  try {
    $res = Get-Content $resFile -Raw | ConvertFrom-Json
    if ($res.at -and ($res.at -ne $prev.triageResultAt)) {
      $prev.triageResultAt = [string]$res.at
      try { & msg.exe * "/TIME:180" ("Huntress WebWatch triage - " + $res.result); Note ("triage-result toast: " + $res.result) } catch {}
    }
  } catch {}
}

try { ($prev | ConvertTo-Json) | Set-Content -Path $StateFile -Encoding utf8 } catch {}
if ($toast) {
  try { & msg.exe * "/TIME:150" $toast; Note ("toast: " + $toast) }
  catch { Note ("toast failed: " + $_.Exception.Message) }
}
