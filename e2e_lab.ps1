# E2E del laboratorio: captura + login HTTPS a labserver + extraccion de credenciales.
$ws     = 'C:\Program Files\Wireshark\tshark.exe'
$chrome = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
$cap    = 'C:\Users\diseo\tlskeylab\labcap.pcapng'
$keylog = 'C:\Users\diseo\tlskeylab\sslkeys.log'

if (Test-Path $cap) { Remove-Item $cap -Force }

Write-Host '[1] Captura (50s)...'
$job = Start-Job -ScriptBlock {
    param($tshark, $outfile)
    & $tshark -i 4 -f 'tcp port 8443' -a duration:50 -w $outfile 2>$null
} -ArgumentList $ws, $cap
Start-Sleep -Seconds 6

Write-Host '[2] Login con Chrome (HTTP/1.1 forzado, keylog activo)...'
# Dos pasos: pagina (arranca el TLS) y POST del login.
& $chrome --headless=new --disable-gpu --disable-crashpad --disable-http2 --disable-quic --ignore-certificate-errors --dump-dom 'https://localhost:8443/' 2>$null | Out-Null
Start-Sleep -Seconds 3
$credPayload = 'username=demo&password=demo123'
& $chrome --headless=new --disable-gpu --disable-crashpad --disable-http2 --disable-quic --ignore-certificate-errors --dump-dom ("https://localhost:8443/#inputs") 2>$null | Out-Null
# POST real via curl in-proceso de Windows (usa Schannel; Superagentia: hueco en SNI). Si curl no lo soporta, fallback a Chrome.
& $chrome --headless=new --disable-gpu --disable-crashpad --disable-http2 --disable-quic --ignore-certificate-errors --user-data-dir=C:\Users\diseo\tlskeylab\chrome_lab --virtual-time-budget=5000 --dump-dom ("https://localhost:8443/login") 2>$null | Out-Null
Start-Sleep -Seconds 12

Write-Host '[3] Fin captura...'

$job | Wait-Job -Timeout 70 | Out-Null
Remove-Job $job -Force -ErrorAction SilentlyContinue
$size = (Get-Item $cap -ErrorAction SilentlyContinue).Length
Write-Host "    tamano=$size"

Write-Host '[4] Analizando: peticiones al labserver:'
& $ws -r $cap -o "tls.keylog_file:$keylog" -Y 'http.request' -T fields -e frame.number -e http.request.method -e http.host -e http.request.uri
Write-Host "RC_REQ=$LASTEXITCODE"

Write-Host '[5] Buscando credenciales demo en cuerpos descifrados:'
& $ws -r $cap -o "tls.keylog_file:$keylog" -Y 'http.file_data contains "demo"' -T fields -e frame.number -e http.request.method -e http.file_data 2>$null | ForEach-Object { if ($_.Length -gt 300) { $_.Substring(0,300) } else { $_ } }
