# Prueba end-to-end de tlskeylab: captura, trafico TLS y descifrado con tshark.
$ws     = 'C:\Program Files\Wireshark\tshark.exe'
$chrome = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
$cap    = 'C:\Users\diseo\tlskeylab\test_capture.pcapng'
$keylog = 'C:\Users\diseo\tlskeylab\sslkeys.log'

if (Test-Path $cap) { Remove-Item $cap -Force }

Write-Host '[1] Iniciando captura (30s) en Ethernet0 via Start-Job...'
$job = Start-Job -ScriptBlock {
    param($tshark, $outfile)
    & $tshark -i 4 -f 'tcp port 443' -a duration:30 -w $outfile 2>$null
    Write-Output "exitcode=$LASTEXITCODE"
} -ArgumentList $ws, $cap
Start-Sleep -Seconds 6

Write-Host '[2] Generando trafico TLS con Chrome + SSLKEYLOGFILE...'
$env:SSLKEYLOGFILE = $keylog
& $chrome --headless --disable-gpu --no-sandbox --dump-dom https://example.com 2>$null | Out-Null
Write-Host '    trafico generado.'

Write-Host '[3] Esperando a que termine la captura...'
$job | Wait-Job -Timeout 60 | Out-Null
Receive-Job $job | ForEach-Object { Write-Host "    captura: $_" }
Remove-Job $job -Force -ErrorAction SilentlyContinue

$capOK = Test-Path $cap
$capSize = 0
if ($capOK) { $capSize = (Get-Item $cap).Length }
Write-Host "    captura_pcreada=$capOK tamana=$capSize"

Write-Host '[4] Analizando con tshark usando el keylog (esperamos HTTP/2 descifrado):'
& $ws -r $cap -o "tls.keylog_file:$keylog" -Y 'http2 or http' -T fields -e frame.number -e http2.headers.method -e http2.headers.authority
Write-Host "RC_ANALISIS=$LASTEXITCODE"
