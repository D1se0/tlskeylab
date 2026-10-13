# tlskeylab v1.0.0 — «El flujo completo, verificado»

Primera versión estable de la suite de laboratorio **tlskeylab**: activar la convención
SSLKEYLOGFILE en TU máquina, capturar el tráfico y ver en Wireshark (o en el informe de
`tlsviewer.py`) tus propios logins HTTPS en texto plano.

## Assets y SHA-256

| Asset | Qué es | SHA-256 |
|---|---|---|
| `tlskeylab.exe` | Motor de la suite (Go, windows/amd64) | ver `SHA256SUMS.txt` del release |
| `labserver.exe` | Servidor de login HTTPS+SQLite (Go, windows/amd64) | ver `SHA256SUMS.txt` |
| `tlsviewer.py` | Visor sin GUI del rastro descifrado (Python 3 stdlib) | ver `SHA256SUMS.txt` |
| `tlskeylab-suite-fuentes-y-binarios.tar.gz` | Todo: binarios + fuentes Go + web + e2e + workflows | ver `SHA256SUMS.txt` |

El fichero `SHA256SUMS.txt` (incluido en el release) permite verificar cada asset antes de ejecutarlo.

## Cómo se compiló (100 % reproducible)

```bash
# tlskeylab.exe
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o tlskeylab.exe .

# labserver.exe (submódulo con SQLite puro-Go, sin CGO)
cd labserver_src && GOOS=windows GOARCH=amd64 go build -o labserver.exe .
```

Solo se necesita **Go ≥ 1.22**. `tlsviewer.py` no se compila: es un script.

## Qué incluye

### tlskeylab.exe (motor)
- `setup`: keylog + variable SSLKEYLOGFILE (broadcast WM_SETTINGCHANGE) + SMB solo-lectura + firewall.
- `status`: panel en vivo del estado y el número de claves.
- `launch chrome|edge|firefox`: navegador con keylog heredado; **HTTP/1.1 forzado por defecto**
  (`--disable-http2 --disable-quic --ignore-certificate-errors` en Chromium; perfil dedicado en Firefox).
  Con `--h2` se anula el forzado.
- `capture [seg] [-i N]`: graba el pcapng con dumpcap; **por defecto captura interfaz activa + loopback**
  (el tráfico a `https://localhost` no pasa por Ethernet).
- `uninstall [--purge]`: revierte todo con log completo.

### labserver.exe (objetivo del lab)
- Login HTTPS en el puerto 8443 con certificado autofirmado automático.
- SQLite embebido (`lab_users.db`): tablas `users` y `logins`; usuario demo `demo / demo123`.
- Firewall automático; `-port` y `-stop` para controlar el servicio.
- La instalación del certificado usa la API nativa de Windows (CertOpenStore) con fallback
  a instrucciones manuales cuando la build lo bloquea («Solicitud no compatible»).

### tlsviewer.py (análisis)
- `python3 tlsviewer.py capture_X.pcapng sslkeys.log` → `capture_X+decodificado.txt`
  con método, host, URI, User-Agent y cuerpos en claro de todas las peticiones HTTP.

## Verificación e2e incluida en el desarrollo

- Login real desde Chrome con keylog activo: el POST descifrado muestra
  `username=pruebaE2E&password=…` en el pcap (frame del POST, `Follow HTTP Stream` en claro).
- `capture` con loopback incluido: 11 paquetes TLS del 8443 en el pcap frente a 0 en la versión que
  solo captaba Ethernet.
- `go vet` limpio en ambos módulos.

## Correcciones notables incluidas

1. **Web del labserver en blanco** — la plantilla Go usaba campos no exportados (`brand`, `user`…)
   y `html/template` abortaba en la primera variable: respuesta truncada a 67 bytes. Ahora usa
   campos exportados y loguea el error de `Execute` si lo hubiera.
2. **`launch <nav>` sin flags → panic** — `hasFlag` hacía `args[1:]` sobre un slice vacío.
3. **Credenciales del login local invisibles en el pcap** — `capture` solo tomaba Ethernet; ahora
   también la loopback por defecto.

## Limitaciones conocidas (honestas)

- HTTP/3 (QUIC): sin descifrado clásico por keylog (TLS propio sobre UDP); el `launch` lo desactiva.
- OHTTP (Google Safe Browsing relays, etc.): doble cifrado de aplicación, ilegible incluso con el keylog.
- Sesiones TLS abiertas antes de `launch`: no hay secretos para ellas (regla: capturar antes de lanzar).
- Cert autofirmado: aviso esperado si se usa un navegador normal; `launch` lo salta.
 Binarios sin firma code-signing: SmartScreen avisará la primera vez; SHA-256 en las notas.
