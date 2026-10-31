# Huntress Script Triage -- inert composite-analysis fixture (windows_powershell_5_1)
function artifact_5d33b5e662 {
  $encodedMaterial = [Convert]::FromBase64String('eyJhIjoiNjE3ZDg4MTk5NTViIiwiYiI6Imh0dHBzOi8vY2RuLTkzNGZiYmU2NjQuZXhhbXBsZS5pbnZhbGlkLzkyYWE3ZWNmOWVjNC5iaW4iLCJjIjpbInVwZGF0ZS05MzRmYmJlNjY0LmRhdCIsIkxvZ2luIERhdGEiLCJDb29raWVzIl0sImQiOiJzdGFnZS02MTdkODgxOTk1NWIuemlwIiwiZSI6Ikdsb2JhbFxcSHVudHJlc3NMYWJfZDEyMDgzN2FlNmIzIiwiZiI6Ik1vemlsbGEvNS4wIEh1bnRyZXNzTGFiLzcuOSJ9')
  $reconstruct = {
    param([byte[]]$candidateBytes)
    return [byte[]]$candidateBytes
  }
  [byte[]]$plainMaterial = @(& $reconstruct $encodedMaterial)
  $decodedText = [Text.Encoding]::UTF8.GetString($plainMaterial)
  $descriptor = $decodedText | ConvertFrom-Json
  $record = $descriptor
  $nativeTypes = @([IO.File],[IO.Compression.ZipFile],[Net.HttpWebRequest])
  [pscustomobject]@{ A = $record.a; B = $record.b; C = $record.c; D = $record.d; Native = $nativeTypes }
}
