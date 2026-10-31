# Huntress Script Triage -- inert composite-analysis fixture (windows_powershell_5_1)
function artifact_2f02607ddb {
  $encodedMaterial = [Convert]::FromBase64String('eyJhIjoiMzI5N2FmYzY0ZjA4IiwiYiI6Imh0dHBzOi8vYzc1MDIxMDgzNy5leGFtcGxlLmludmFsaWQvM2U4Nzc2OTg4YjY5LmRhdCIsImMiOiJ3YWxsZXRfOGZlNjg5MTk3NjFmNDI3NzM3Y2RiZDdjZjhhOTA3MmUiLCJkIjoidXBkYXRlLWM3NTAyMTA4MzcuZGF0IiwiZSI6IkhLQ1VcXFNvZnR3YXJlXFxIdW50cmVzc0xhYlxcUnVuXFxjNzUwMjEwODM3IiwiZiI6Ik1vemlsbGEvNS4wIEh1bnRyZXNzTGFiLzkuMCIsImciOjY0LCJoIjoiR2xvYmFsXFxIdW50cmVzc0xhYl8xZDllNTA0YTY2ODMifQ==')
  $reconstruct = {
    param([byte[]]$candidateBytes)
    return [byte[]]$candidateBytes
  }
  [byte[]]$plainMaterial = @(& $reconstruct $encodedMaterial)
  $decodedText = [Text.Encoding]::UTF8.GetString($plainMaterial)
  $descriptor = $decodedText | ConvertFrom-Json
  $record = $descriptor
  $nativeTypes = @([Diagnostics.Process],[Microsoft.Win32.Registry],[Net.WebClient])
  [pscustomobject]@{ A = $record.a; B = $record.b; C = $record.c; D = $record.d; Native = $nativeTypes }
}
