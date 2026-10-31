# Huntress CTF 2026 - daily autonomous solve wrapper (scheduled ~09:00 ET)
# PARALLEL: 3 grouped headless Claude agents (quick / binary / script) solve the day's lanes concurrently.
# Resilient: native wsl.exe stderr (systemd warning) or a transient GM hiccup must NOT abort the run.
$ErrorActionPreference = "Continue"
$Proj   = "C:\\Users\\<user>\Documents\Huntress CTF"
$Auto   = Join-Path $Proj "auto"
$Claude = "C:\\Users\\<user>\.local\bin\claude.exe"
$MemDir = "C:\\Users\\<user>\.claude\projects\C--Users-<user>-Documents-Huntress-CTF\memory"
$Allow  = 'Bash(wsl.exe:*) Bash(wsl:*) Read Write Edit Glob Grep'
$AddDir = 'C:\\Users\\<user>\.claude'
$VenvPy = '~/ctf-venv/bin/python'
$LogDir = Join-Path $Auto "logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$stamp  = Get-Date -Format "yyyy-MM-dd_HHmmss"
$Log    = Join-Path $LogDir "solve_$stamp.log"
function Note($m) { Add-Content -Path $Log -Value ("{0}  {1}" -f (Get-Date).ToString("s"), $m) -Encoding utf8 }
Note "=== parallel daily solve start ==="

# --- WEB lane FIRST (deterministic, 0 LLM): clear it before anything else so web
#     points land within seconds of the 09:00 drop, independent of the new-day gate
#     below (web has its own cadence and is NOT part of the quick/binary/script groups). ---
$webResult = "web (not run)"
try {
  $wl = (wsl.exe -e bash -lc "$VenvPy ~/ctf/webwatch.py" 2>$null | Out-String)
  $wline = ($wl -split "`r?`n" | Where-Object { $_ -match '^WEBWATCH ' } | Select-Object -Last 1)
  if ($wline) { $webResult = $wline.Trim() }
  Note ("web: " + $webResult)
} catch { Note ("web step error: " + $_.Exception.Message) }

# --- EXTRA "standard" challenge (2026-10-29): a traditional CTF task that may be portal-only
#     (CourseStack lesson, not the GM). One Chrome-enabled agent (`--chrome`, the user's logged-in
#     Chrome) finds it in the GM or the portal, solves it from WSL, submits. On a date listed in
#     extra_days.txt ("yyyy-MM-dd <day>") it starts right away, independent of the GM new-day gate
#     below; on any other day an unknown-lane id from dayids.py ("extra" group) gets the same agent. ---
$RunStart  = Get-Date
$ChromeExe = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$ExtraAllow = "$Allow mcp__claude-in-chrome"
$ExtraSys  = "`n- EXTRA agent only: you MAY use the Claude in Chrome tools (mcp__claude-in-chrome__*) in the user's logged-in Chrome, strictly on ctf.huntress.com, for the steps in your task prompt (read the challenge lesson, download its attachment, submit its flag in that lesson's answer box). This overrides the WSL-only wording above for the browser only; shell work stays in wsl.exe."
function Start-ExtraAgent($day, $idsText) {
  if (-not (Get-Process chrome -ErrorAction SilentlyContinue)) {
    try { Start-Process $ChromeExe; Note "chrome was not running; started it"; Start-Sleep -Seconds 30 } catch { Note ("chrome start failed: " + $_.Exception.Message) }
  }
  $et = Get-Content (Join-Path $Auto "extra_prompt.txt") -Raw -Encoding utf8
  $es = (Get-Content (Join-Path $Auto "system_prompt.txt") -Raw -Encoding utf8) + $ExtraSys
  $noteRel = "auto/day{0:D2}/extra.md" -f [int]$day
  New-Item -ItemType Directory -Force -Path (Join-Path $Auto ("day{0:D2}" -f [int]$day)) | Out-Null
  $p = $et.Replace("__DAY__", "$day").Replace("__IDS__", $idsText).Replace("__NOTEFILE__", $noteRel)
  # PS 5.1 does not escape embedded double quotes when passing args to a native exe: they get
  # stripped, and a quoted span containing spaces can split the argument (seen in the 2026-10-29 dry run).
  $p = $p.Replace('"', "'"); $es = $es.Replace('"', "'")
  $elog = Join-Path $LogDir "solve_${stamp}_extra.log"
  Note "launching EXTRA agent (day $day, --chrome) -> $elog"
  return Start-Job -Name "ctf_extra" -ScriptBlock {
    param($claude, $prompt, $sys, $glog, $allow, $adddir, $proj)
    Set-Location $proj
    & $claude -p $prompt --chrome --allowedTools $allow --add-dir $adddir --append-system-prompt $sys *>> $glog
  } -ArgumentList $Claude, $p, $es, $elog, $ExtraAllow, $AddDir, $Proj
}
$extraJob = $null; $extraDay = 0
try {
  $today = (Get-Date).ToString("yyyy-MM-dd")
  $edf = Join-Path $Auto "extra_days.txt"
  if (Test-Path $edf) {
    foreach ($l in (Get-Content $edf -Encoding utf8)) {
      $f = ($l -split '\s+') | Where-Object { $_ }
      if ($f.Count -ge 2 -and $f[0] -eq $today) { $extraDay = [int]$f[1] }
    }
  }
  if ($extraDay -gt 0) { $extraJob = Start-ExtraAgent $extraDay "none - discover it yourself (GM first, then the portal)" }
} catch { Note ("extra launch error: " + $_.Exception.Message) }

# --- readiness: wait until a NEW day is released (all=true count grows) ---
$baseFile = Join-Path $Auto "last_count.txt"
$base = 0
if (Test-Path $baseFile) { try { $base = [int]((Get-Content $baseFile -Raw).Trim()) } catch { $base = 0 } }
Note "baseline = $base"
$ready = $false; $newcount = $base; $N = 0
for ($i = 0; $i -lt 120; $i++) {
  $count = 0; $line = ""
  try { $line = (wsl.exe -e bash -lc "$VenvPy ~/ctf/count.py" 2>$null | Out-String) } catch {}
  $mc = [regex]::Match($line, 'COUNT=(\d+)'); if ($mc.Success) { $count = [int]$mc.Groups[1].Value }
  $md = [regex]::Match($line, 'DAYS=([\d,]+)')
  if ($md.Success) { $N = ($md.Groups[1].Value.Split(',') | ForEach-Object { [int]$_ } | Measure-Object -Maximum).Maximum }
  Note ("poll {0}: count={1} day={2}" -f $i, $count, $N)
  if ($count -gt $base) { $ready = $true; $newcount = $count; break }
  Start-Sleep -Seconds 30
}
if (-not $ready -and -not $extraJob) { Note "No new day detected; exiting."; exit 0 }
$groups = @{}
$jobs = @{}
if ($ready) {
Note "new day detected: Day $N (count $base -> $newcount)"

# --- discover + group the day's challenge ids ---
$DayDir = Join-Path $Auto ("day{0:D2}" -f [int]$N)
New-Item -ItemType Directory -Force -Path $DayDir | Out-Null
for ($dtry = 0; $dtry -lt 15; $dtry++) {
  $groups = @{}
  $rowsTxt = (wsl.exe -e bash -lc "$VenvPy ~/ctf/dayids.py $N" 2>$null | Out-String)
  foreach ($r in ($rowsTxt -split "`r?`n")) {
    $r = $r.Trim(); if (-not $r) { continue }
    $parts = $r -split "`t"; if ($parts.Count -lt 2) { continue }
    $g = $parts[0].Trim(); $id = $parts[1].Trim()
    if (-not $groups.ContainsKey($g)) { $groups[$g] = @() }
    $groups[$g] += $id
  }
  $total = 0; foreach ($k in $groups.Keys) { $total += $groups[$k].Count }
  Note ("dayids try ${dtry}: $total ids")
  if ($total -ge 5) { break }
  Start-Sleep -Seconds 20
}
Note ("groups: " + (($groups.Keys | ForEach-Object { "$_=$($groups[$_].Count)" }) -join ", "))
if ($extraJob -and $groups.ContainsKey("extra")) {
  Note ("extra ids already owned by the early EXTRA agent: " + ($groups["extra"] -join ", ")); $groups.Remove("extra")
}
if ($groups.Count -eq 0 -and -not $extraJob) { Note "No ids discovered; exiting."; exit 1 }

# --- launch one headless agent per group, in parallel ---
$tmpl = Get-Content (Join-Path $Auto "group_prompt.txt") -Raw -Encoding utf8
$sys  = Get-Content (Join-Path $Auto "system_prompt.txt") -Raw -Encoding utf8
if (-not $tmpl -or -not $sys) { Note "prompt template/system file empty; abort"; exit 1 }
foreach ($g in @($groups.Keys)) {
  $ids = $groups[$g]
  if ($g -eq "extra") { $jobs[$g] = Start-ExtraAgent $N ($ids -join "`n"); continue }
  $noteRel = "auto/day{0:D2}/{1}.md" -f [int]$N, $g
  $prompt = $tmpl.Replace("__DAY__", "$N").Replace("__GROUP__", $g).Replace("__IDS__", ($ids -join "`n")).Replace("__NOTEFILE__", $noteRel)
  $glog = Join-Path $LogDir "solve_${stamp}_$g.log"
  Note "launching group '$g' ($($ids.Count) lanes) -> $glog"
  $jobs[$g] = Start-Job -Name "ctf_$g" -ScriptBlock {
    param($claude, $prompt, $sys, $glog, $allow, $adddir, $proj)
    Set-Location $proj
    & $claude -p $prompt --allowedTools $allow --add-dir $adddir --append-system-prompt $sys *>> $glog
  } -ArgumentList $Claude, $prompt, $sys, $glog, $Allow, $AddDir, $Proj
}
} else {
  # no new GM day (the standard challenge may be portal-only): only the EXTRA agent runs
  $N = $extraDay
  Note "No new GM day detected; EXTRA agent (day $N) is running on its own"
}
if ($extraJob) { $jobs["extra"] = $extraJob; $groups["extra"] = @("standard") }
$DayDir = Join-Path $Auto ("day{0:D2}" -f [int]$N)
New-Item -ItemType Directory -Force -Path $DayDir | Out-Null

# --- wait for all (max ~2.5h, capped so the whole run stays inside the 3h task limit) ---
$all = @($jobs.Values)
$waitS = [int][Math]::Max(600, [Math]::Min(9000, 10500 - ((Get-Date) - $RunStart).TotalSeconds))
Note "waiting up to $waitS s for: $(@($jobs.Keys) -join ', ')"
$done = Wait-Job -Job $all -Timeout $waitS
foreach ($g in $jobs.Keys) {
  $j = $jobs[$g]
  if ($j.State -eq "Running") { Note "group '$g' TIMED OUT; stopping"; Stop-Job $j }
  Remove-Job $j -Force -ErrorAction SilentlyContinue
}
Note "all groups finished"

# --- aggregate RESULT lines ---
$results = @()
foreach ($g in $groups.Keys) {
  $glog = Join-Path $LogDir "solve_${stamp}_$g.log"
  $rl = $null
  if (Test-Path $glog) { $rl = (Select-String -Path $glog -Pattern "RESULT:" | Select-Object -Last 1).Line }
  if (-not $rl) { $rl = "RESULT: $g (no RESULT line - check log)" }
  Note $rl; $results += $rl.Trim()
}
$summary = "Day $N | " + ($results -join " | ")

# --- consolidate memory (wrapper does it; agents did not touch memory/) ---
# Hardened 2026-10-11: each step is independently guarded so a transient on one never aborts the rest,
# and every catch logs the failing line (InvocationInfo) so a recurrence is diagnosable. Day-11 hit a
# non-reproducible null-Path throw in the old single-try block, which silently skipped ALL of consolidation.
$NN = ([int]$N).ToString("00")
if (-not $MemDir) {
  Note "consolidate SKIP: MemDir is null"
} else {
  $dayFile = Join-Path $MemDir "day$NN-results.md"
  $body = "---`nname: day$NN-results`ndescription: Day $NN parallel-solve results and per-lane notes`nmetadata:`n  type: project`n---`n`n# Day $NN (parallel 3-agent run $stamp)`n`n$summary`n`n"
  foreach ($g in $groups.Keys) {
    $body += "## group: $g`n"
    $nf = if ($DayDir) { Join-Path $DayDir "$g.md" } else { $null }
    if ($nf -and (Test-Path $nf)) {
      try { $body += ((Get-Content $nf -Raw -Encoding utf8) + "`n`n") }
      catch { $body += "(notes unreadable)`n`n"; Note ("notes read ERROR [$g]: " + $_.Exception.Message) }
    } else { $body += "(no notes file written)`n`n" }
  }
  try { Set-Content -Path $dayFile -Value $body -Encoding utf8; Note "memory day file -> $dayFile" }
  catch { Note ("day-file write ERROR: " + $_.Exception.Message + " @ " + $_.InvocationInfo.Line.Trim() + " (line " + $_.InvocationInfo.ScriptLineNumber + ")") }
  try {
    $mdx = Join-Path $MemDir "MEMORY.md"
    $idxLine = "- [Day-$NN results](day$NN-results.md) - $summary"
    if (-not (Select-String -Path $mdx -Pattern ("day{0}-results" -f $NN) -SimpleMatch -Quiet)) {
      Add-Content -Path $mdx -Value $idxLine -Encoding utf8; Note "memory index updated"
    } else { Note "memory index already has day$NN line; not duplicating" }
  } catch { Note ("index append ERROR: " + $_.Exception.Message + " @ " + $_.InvocationInfo.Line.Trim() + " (line " + $_.InvocationInfo.ScriptLineNumber + ")") }
  try { wsl.exe -e bash -lc "$VenvPy ~/ctf/kb.py reindex" 2>$null | Out-Null; Note "kb reindexed" }
  catch { Note ("kb reindex ERROR: " + $_.Exception.Message) }
}

# --- baseline ---
try { Set-Content -Path $baseFile -Value "$newcount" -Encoding ascii } catch {}

# --- disk hygiene: purge regenerable binary-lane scratch now the day's points are banked.
#     Each binary artifact is ~31 MB and is downloaded per mode/delivery (~200 MB/day); it is
#     re-downloadable from the GM any time, so we keep only the solvers + notes + memory.
#     Self-healing: clears today's AND any leftover binary_work dirs so auto/ stays lean. ---
try {
  $bw = Get-ChildItem $Auto -Recurse -Directory -Filter "binary_work" -ErrorAction SilentlyContinue
  $freed = 0
  foreach ($d in $bw) {
    $freed += ((Get-ChildItem $d.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum)
    Remove-Item $d.FullName -Recurse -Force -ErrorAction SilentlyContinue
  }
  Note ("scratch purge: removed {0} binary_work dir(s), ~{1:N0} MB reclaimed" -f $bw.Count, ($freed/1MB))
} catch { Note ("scratch purge ERROR: " + $_.Exception.Message) }

Note "DONE: $summary"
try { & msg.exe * "/TIME:180" "Huntress CTF  -  $summary  |  $webResult" } catch { Note ("toast failed: " + $_.Exception.Message) }
Note "=== wrapper end ==="
