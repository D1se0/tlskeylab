# E2E del lab con el diseño correcto:
#   - captura en la interfaz LOOPBACK (el curl/Chrome van a localhost)
#   - el cliente es Chrome con SSLKEYLOGFILE (curl NUNCA escribe el keylog)
$ws     = 'C:\Program Files\Wireshark\tshark.exe'
$chrome = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
$cap    = 'C:\Users\diseo\tlskeylab\labcap_loop.pcapng'
$keylog = 'C:\Users\diseo\tlskeylab\sslkeys.log'

if (Test-Path $cap) { Remove-Item $cap -Force }

Write-Host '[1] Captura en loopback (iface 5) (45s)...'
$job = Start-Job -ScriptBlock {
    param($tshark, $outfile)
    & $tshark -i 5 -f 'tcp port 8443' -a duration:45 -w $outfile 2>$null
} -ArgumentList $ws, $cap
Start-Sleep -Seconds 6

Write-Host '[2] Chrome: POST del formulario con credenciales...'
$env:SSLKEYLOGFILE = $keylog
# HTML de submit automatico: el headless carga //, inyecta credenciales y envia el form.
$html = @"
<html><body onload="f.submit()">
<form id="f" method="POST" action="https://localhost:8443/login">
<input type="hidden" name="username" value="alumnoSPE">
<input type="hidden" name="password" value="mlg13579">
</form></body></html>
"@
Set-Content -Path 'C:\Users\diseo\tlskeylab\lab_submit.html' -Value $html -Encoding UTF8
& $chrome --headless=new --disable-gpu --disable-crashpad --disable-http2 --disable-quic --ignore-certificate-errors --user-data-dir=C:\Users\diseo\tlskeylab\chrome_lab --allow-file-access-from-files "file:///C:/Users/diseo/tlskeylab/lab_submit.html" 2>$null | Out-Null
Start-Sleep -Seconds 10

Write-Host '[3] Segundo login (usuario demo por si falla el primero):'
$html2 = @"
<html><body onload="f.submit()">
<form id="f" method="POST" action="https://localhost:8443/login">
<input type="hidden" name="username" value="demo">
<input type="hidden" name="password" value="demo123">
</form></body></html>
"@
Set-Content -Path 'C:\Users\diseo\tlskeylab\lab_submit2.html' -Value $html2 -Encoding UTF8
& $chrome --headless=new --disable-gpu --disable-crashpad --disable-http2 --disable-quic --ignore-certificate-errors --user-data-dir=C:\Users\diseo\tlskeylab\chrome_lab --allow-file-access-from-files "file:///C:/Users/diseo/tlskeylab/lab_submit2.html" 2>$null | Out-Null
Start-Sleep -Seconds 8

$job | Wait-Job -Timeout 60 | Out-Null
Remove-Job $job -Force -ErrorAction SilentlyContinue
$size = (Get-Item $cap -ErrorAction SilentlyContinue).Length
Write-Host "    captura=tamano:$size"

Write-Host '[4] Analisis (paquetes 8443 + POSTs descifrados):'
& $ws -r $cap 2>$null | Select-Object -First 1
& $ws -r $cap -o "tls.keylog_file:$keylog" -Y 'http.request.method == "POST"' -T fields -e frame.number -e http.host -e http.request.uri
Write-Host "RC_POSTS=$LASTEXITCODE"

Write-Host '[5] Credenciales en cuerpos (buscamos mlg13579 y demo123):'
& $ws -r $cap -o "tls.keylog_file:$keylog" -Y 'http.file_data contains "mlg13579" or http.file_data contains "demo123"' -T fields -e frame.number -e http.file_data 2>$null | ForEach-Object { if ($_.Length -gt 300) { $_.Substring(0,300) } }
