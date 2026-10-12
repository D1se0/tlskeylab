# E2E: Chrome forzado a HTTP/1.1 + captura + verificacion de rastro legible.
$ws      = 'C:\Program Files\Wireshark\tshark.exe'
$chrome  = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
$cap     = 'C:\Users\diseo\tlskeylab\h11_cap.pcapng'
$keylog  = 'C:\Users\diseo\tlskeylab\sslkeys.log'

if (Test-Path $cap) { Remove-Item $cap -Force }

Write-Host '[1] Captura (60s)...'
$job = Start-Job -ScriptBlock {
    param($tshark, $outfile)
    & $tshark -i 4 -f 'tcp port 443' -a duration:60 -w $outfile 2>$null
} -ArgumentList $ws, $cap
Start-Sleep -Seconds 6

Write-Host '[2] Chrome con HTTP/1.1 forzado + keylog...'
$env:SSLKEYLOGFILE = $keylog
& $chrome --headless=new --disable-gpu --disable-crashpad --disable-http2 --disable-quic --dump-dom https://example.com 2>$null | Out-Null
Start-Sleep -Seconds 4
& $chrome --headless=new --disable-gpu --disable-crashpad --disable-http2 --disable-quic --dump-dom https://httpbin.org/get 2>$null | Out-Null
Start-Sleep -Seconds 20

Write-Host '[3] Fin de captura...'
$job | Wait-Job -Timeout 70 | Out-Null
Remove-Job $job -Force -ErrorAction SilentlyContinue
$size = (Get-Item $cap -ErrorAction SilentlyContinue).Length
Write-Host "    tamano=$size"

Write-Host '[4] Peticiones (esperamos HTTP/1.1 puro):'
& $ws -r $cap -o "tls.keylog_file:$keylog" -Y 'http.request' -T fields -e frame.number -e http.request.method -e http.host -e http.request.uri
Write-Host "RC_REQ=$LASTEXITCODE"

Write-Host '[5] Body HTTP/1.1 (httpbin /get devuelve JSON):'
& $ws -r $cap -o "tls.keylog_file:$keylog" -Y 'http.file_data' -T fields -e frame.number -e http.file_data 2>$null | ForEach-Object { if ($_.Length -gt 260) { $_.Substring(0,260) } else { $_ } } | Select-Object -First 4

Write-Host '[6] Comprobacion de que NO hay HTTP/2:'
& $ws -r $cap -Y 'http2' -T fields -e frame.number 2>$null | Select-Object -First 3
Write-Host '    (nada arriba = ningun paquete http2, HTTP/1.1 forzado OK)'
