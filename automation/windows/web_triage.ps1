# Huntress CTF 2026 - WEB novel-type auto-triage launcher.
# Launched DETACHED by web_watch.ps1 on ALERT (a web mode the deterministic solver could NOT
# handle = likely a NEW vuln type). Runs a headless Claude agent that solves the new type AND
# extends webrun.py so it becomes deterministic next time. Writes a lock so the watchdog never
# runs two triage agents at once. User opted in 2026-10-20 ("un agent Claude soit lance ... au
# lieu d'attendre le ok de ma part"). -DryRun does everything EXCEPT spend tokens on Claude.
param([switch]$DryRun)
$ErrorActionPreference = "Continue"
$Proj   = "C:\\Users\\<user>\Documents\Huntress CTF"
$Auto   = Join-Path $Proj "auto"
$Claude = "C:\\Users\\<user>\.local\bin\claude.exe"
$Allow  = 'Bash(wsl.exe:*) Bash(wsl:*) Read Write Edit Glob Grep'
$AddDir = 'C:\\Users\\<user>\.claude'
$LogDir = Join-Path $Auto "logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$stamp  = Get-Date -Format "yyyy-MM-dd_HHmmss"
$Log    = Join-Path $LogDir "web_triage_$stamp.log"
$Lock   = Join-Path $Auto ".web_triage.lock"
function Note($m) { Add-Content -Path $Log -Value ("{0}  {1}" -f (Get-Date).ToString("s"), $m) -Encoding utf8 }

# --- lock (pid + start); removed in finally so the watchdog can relaunch later ---
try { @{ pid = $PID; startedAt = (Get-Date).ToString("s"); dryrun = [bool]$DryRun } | ConvertTo-Json | Set-Content -Path $Lock -Encoding utf8 } catch {}
Note "=== web triage start (pid $PID, dryrun=$DryRun) ==="

try {
  # failing ids for context (the agent re-audits live anyway)
  $failed = ""
  try {
    $h = Get-Content (Join-Path $Auto "health.json") -Raw | ConvertFrom-Json
    if ($h.web.failed) { $failed = ($h.web.failed -join ", ") }
  } catch { Note ("health.json read error: " + $_.Exception.Message) }
  if (-not $failed) { $failed = "(none listed in health.json -> audit ?op=list&all=true live)" }
  Note ("failed: " + $failed)

  $tmpl = Get-Content (Join-Path $Auto "web_triage_prompt.txt") -Raw -Encoding utf8
  $sys  = Get-Content (Join-Path $Auto "system_prompt.txt") -Raw -Encoding utf8
  if (-not $tmpl -or -not $sys) { Note "prompt/system file empty; abort"; return }
  $prompt = $tmpl.Replace("__FAILED__", $failed)
  Note ("prompt assembled (" + $prompt.Length + " chars)")

  Set-Location $Proj
  if ($DryRun) {
    Note ("DRYRUN: would launch claude -p <prompt> --allowedTools '$Allow' --add-dir '$AddDir' --append-system-prompt <sys>")
    $rl = "RESULT: web-triage DRYRUN (claude not invoked)"
  } else {
    Note "launching headless Claude triage agent..."
    & $Claude -p $prompt --allowedTools $Allow --add-dir $AddDir --append-system-prompt $sys *>> $Log
    $rl = $null
    if (Test-Path $Log) { $rl = (Select-String -Path $Log -Pattern "RESULT:" | Select-Object -Last 1).Line }
    if (-not $rl) { $rl = "RESULT: web-triage (no RESULT line - check log)" }
  }
  Note ("agent done: " + $rl)

  # publish result so web_watch.ps1 can toast it from the (reliable) task session too
  try { @{ at = (Get-Date).ToString("s"); result = $rl.Trim() } | ConvertTo-Json | Set-Content -Path (Join-Path $Auto ".web_triage_result.json") -Encoding utf8 } catch {}
  if (-not $DryRun) { try { & msg.exe * "/TIME:180" ("Huntress WebWatch triage - " + $rl.Trim()) } catch { Note ("toast failed: " + $_.Exception.Message) } }
}
catch { Note ("triage ERROR: " + $_.Exception.Message + " @ line " + $_.InvocationInfo.ScriptLineNumber) }
finally {
  Remove-Item -Path $Lock -Force -ErrorAction SilentlyContinue
  Note "=== web triage end ==="
}
