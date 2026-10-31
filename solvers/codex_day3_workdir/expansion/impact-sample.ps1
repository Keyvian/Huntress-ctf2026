# Huntress Script Triage -- inert composite-analysis fixture (windows_powershell_5_1)
function artifact_983c1025fd {
  $encodedMaterial = [Convert]::FromBase64String('eyJhIjoiNDQ2ZWM3ODFmY2EzIiwiYiI6Ii5sb2NrZWQtMzZlMGMiLCJjIjoiUkVDT1ZFUlktMzZlMGMwYjIxNi50eHQiLCJkIjoiaHR0cHM6Ly8zNmUwYzBiMjE2LmV4YW1wbGUuaW52YWxpZC9kZGY2N2IwM2Y1OTcuZGF0IiwiZSI6WyJ1cGRhdGUtMzZlMGMwYjIxNi5kYXQiLCJMb2dpbiBEYXRhIiwiQ29va2llcyJdLCJmIjoiR2xvYmFsXFxIdW50cmVzc0xhYl9iZmRlMjYzMGU5NGUifQ==')
  $reconstruct = {
    param([byte[]]$candidateBytes)
    return [byte[]]$candidateBytes
  }
  [byte[]]$plainMaterial = @(& $reconstruct $encodedMaterial)
  $decodedText = [Text.Encoding]::UTF8.GetString($plainMaterial)
  $descriptor = $decodedText | ConvertFrom-Json
  $record = $descriptor
  $nativeTypes = @([IO.File],[Security.Cryptography.Aes],[IO.DirectoryInfo])
  [pscustomobject]@{ A = $record.a; B = $record.b; C = $record.c; D = $record.d; Native = $nativeTypes }
}
