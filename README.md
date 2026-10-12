# tlskeylab

Herramienta para Windows para practicar el descifrado de tráfico **HTTPS propio** en Wireshark mediante el mecanismo estándar **SSLKEYLOGFILE** (TLS keylog), en un laboratorio local de ciberseguridad.

- **Archivo:** `tlskeylab.exe` (binario Go autocontenido, ~2 MB, sin dependencias).
- **Alcance:** solo la máquina donde se ejecuta y la LAN privada del laboratorio.
- **Garantías:** idempotente, con log de todas las acciones, y 100 % reversible (`uninstall`).

---

## Qué hace

| Modo | Acción |
|---|---|
| `tlskeylab.exe setup` | Crea `%USERPROFILE%\tlskeylab\sslkeys.log`, fija la variable de usuario `SSLKEYLOGFILE`, comparte la carpeta por SMB de solo lectura (`\\HOST\tlskeys`) y permite SMB en el firewall solo hacia la red local. |
| `tlskeylab.exe status` | Muestra el estado: variable, fichero de claves (y cuántas hay), recurso SMB y regla de firewall. |
| `tlskeylab.exe launch chrome` | Arranca Chrome con `SSLKEYLOGFILE` inyectada en el proceso (independiente de la variable de sesión). |
| `tlskeylab.exe launch edge` | Ídem con Microsoft Edge. |
| `tlskeylab.exe capture [segundos] [-i N]` | Captura tráfico en un pcapng (en la carpeta del keylog) mientras navegas; termina con Ctrl+C o tras N segundos. Usa dumpcap (motor de Wireshark). |
| `tlskeylab.exe uninstall` | Revierte todo: variable del registro, recurso compartido, regla de firewall. Añade `--purge` para borrar también los ficheros (keylog y logs). |

Todo queda registrado en `%USERPROFILE%\tlskeylab\tool.log`.

---

## Guía rápida de uso

### 1. Máquina "víctima" (donde navegas, Windows 11)

1. Copia `tlskeylab.exe` a la máquina (p. ej. `C:\Users\<tu_usuario>\tlskeylab.exe`).
2. Abre un **cmd como Administrador** y ejecuta:

   ```
   tlskeylab.exe setup
   ```

   Debe terminar con todos los elementos en verde `[+]`. Los recursos SMB y el firewall requieren elevación; si alguno sale en `[!]`, revisa que la consola sea de Administrador y reejecuta.

3. Comprueba:

   ```
   tlskeylab.exe status
   ```

4. Arranca un navegador en modo trazable:

   ```
   tlskeylab.exe launch chrome
   ```

   (o `launch edge`). Navega por cualquier sitio HTTPS y verás en status cómo aumenta el contador de claves.

> **Nota importante:** si ya tenías Chrome abierto, ciérralo antes de `launch`.
> Los procesos ya arrancados **no** leen de nuevo la variable de entorno.

### 2. Máquina "atacante" (donde capturas con Wireshark)

Wireshark no descifra nada por arte de magia: necesita dos cosas, **la captura del tráfico** y **el fichero de claves** de las sesiones.

**Paso A — dónde están las claves:** en el recurso compartido de red de la víctima:

```
\\<IP-o-nombre-de-la-víctima>\tlskeys\sslkeys.log
```

En Linux puedes copiarlo a tu disco, por ejemplo con impacket:

```bash
python3 -c "
from impacket.smbconnection import SMBConnection
c = SMBConnection('<IP-victima>', '<IP-victima>', sess_port=445)
c.login('<usuario>', '<password>')
open('sslkeys.log','wb').write(b'')
c.getFile('tlskeys', 'sslkeys.log', lambda b: open('sslkeys.log','ab').write(b))
"
```

…o desde Windows con `copy \\IP-victima\tlskeys\sslkeys.log .`

**Paso B — Wireshark:**

1. `Editar → Preferencias → Protocols → TLS`.
2. En *(Pre)-Master-Secret log filename*, pon la **ruta local** donde hayas copiado el fichero.
3. Captura el tráfico de la víctima (en tu misma LAN puedes verlo desde el router o con un switch/port mirror; en el laboratorio lo habitual es capturar en la propia víctima o en el punto de enlace).
4. Los paquetes TLS aparecerán como `HTTP2`/`HTTP` descifrados. Filtra con `tls && !(tcp.analysis.retransmission)` o directamente `http2`.

### 3. Verificación

- `tlskeylab.exe status` en la víctima debe decir `N claves` con N > 0.
- En Wireshark, los paquetes que correspondan a esas sesiones deben aparecer descifrados (pestaña *Decrypted TLS* / *Follow → TLS Stream* muestra texto plano).
- Si alguien navega en la víctima con un navegador que **no** fue arrancado via `launch` ni heredó la variable, sus sesiones nuevas **no** tendrán claves (ver limitaciones).

### 3b. Captura integrada de pcap

Además, **si dumpcap.exe no está presente** (no hay Wireshark instalado), `capture` lo instala automáticamente vía `winget install --id WiresharkFoundation.Wireshark --silent` y sigue con la captura. La operación queda en el log; si winget no está disponible, lo indica y pide instalación manual.

Ya no necesitas capturar en la máquina atacante: la víctima puede autotrazarse. Ejecuta en la víctima:

```
tlskeylab.exe capture
```

- Captura tráfico en la **interfaz activa** y escribe `capture_<fecha>_<hora>.pcapng` en `C:\Users\diseo\tlskeylab\` (la misma carpeta que el keylog).
- Termina con **Ctrl+C** (cierre limpio de dumpcap) o tras N segundos: `tlskeylab.exe capture 30`.
- Puedes elegir interfaz: `tlskeylab.exe capture 30 -i 4` (la lista de interfaces se muestra al arrancar).

Después basta pasar ambos ficheros al atacante:

```
copy \\192.168.5.154\\tlskeys\\sslkeys.log C:\lab\\
copy \\192.168.5.154\\tlskeys\\capture_XXXXXX.pcapng C:\lab\\
```

### 3c. Abrirlo todo en un clic en el atacante: tlsviewer.py

En la máquina atacante (Linux, Windows o macOS) copia `sslkeys.log` y el `capture_*.pcapng` (o el `test_capture.pcapng`) a una misma carpeta y ejecuta:

```bash
python3 tlsviewer.py
```

El script:
1. Detecta el keylog (`sslkeys.log`) y el pcapng más reciente en la carpeta actual.
2. Detecta tu ejecutable de Wireshark (Linux/Windows/macOS o el PATH).
3. Crea/actualiza un perfil de Wireshark llamado **TLSKeyLab** con `tls.keylog_file` apuntando al keylog absoluto.
4. Lanza Wireshark con `-C TLSKeyLab -r <pcapng>`: se abre con el keylog ya cargado y el pcap descifrado.

Opciones útiles: `--keylog RUTA`, `--pcap RUTA`, `--wireshark RUTA`, `--dir DIR`, `--list` (muestra qué usaría sin abrir nada).

Y abre el pcapng en Wireshark con el keylog ya configurado en `Preferences → Protocols → TLS`.

### 4. Desinstalar

```
tlskeylab.exe uninstall            (deja el keylog y el log)
tlskeylab.exe uninstall --purge    (borra también los ficheros)
```

---

## Cómo funciona por dentro

Wireshark **nunca** "rompe" TLS: lo que hace es reutilizar las claves de sesión que el cliente (navegador) generó. El protocolo TLS en sí no expone esas claves; lo que permite esta técnica es una **convención**: si la variable de entorno `SSLKEYLOGFILE` está definida cuando arranca el navegador, este escribe en ese fichero, por cada handshake, una línea por cada secreto que necesita para descifrar lo que habla.

Formato de línea (ejemplo real generado en las pruebas):

```
CLIENT_HANDSHAKE_TRAFFIC_SECRET 3e5d3293ba6af... 5c82d8575aae33...
```

- El primer hex es el **Random de ClientHello** (identifica la sesión).
- El segundo hex es el **secreto** del que derivan las claves simétricas.
- Otras etiquetas posibles: `CLIENT_RANDOM` (TLS 1.2), `CLIENT_TRAFFIC_SECRET_0`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `EXPORTER_SECRET` (TLS 1.3).

Con esos secretos Wireshark deriva las claves de cifrado y puede mostrar en claro el contenido de la sesión (HTTP/2, headers, bodies), pero **solo de las sesiones del navegador que generó ese fichero**. No hay intercepción de red: es cooperación del cliente con su propio usuario.

### Qué hace exactamente `setup`

| Elemento | Mecanismo | Registro de evidencia |
|---|---|---|
| Fichero de claves | `os.OpenFile(..., O_CREATE)` en `%USERPROFILE%\tlskeylab\sslkeys.log` (nunca sobreescribe) | tool.log |
| Variable de entorno | `reg add HKCU\Environment /v SSLKEYLOGFILE /t REG_SZ /d <ruta> /f` | tool.log + visual |
| Difusión del cambio | `SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, "Environment")` para que Explorer y las shells nuevas recojan la variable sin cerrar sesión | — |
| Recurso SMB | `net share tlskeys=<ruta> /grant:Everyone,READ` (con reintento `Todos` por si el Windows está en español) | tool.log |
| Firewall | `netsh advfirewall firewall add rule name=tlskeylab SMB-in dir=in action=allow protocol=TCP localport=445 remoteip=LocalSubnet profile=domain,private` | tool.log |

`launch <navegador>` arranca el ejecutable con `cmd.Env` modificado; los navegadores Chromium leen `SSLKEYLOGFILE` **solo en el arranque del proceso**.

### Limitaciones honestas

- **Solo funciona con los procesos que la heredan.** Chrome/Edge/Firefox sí lo soportan de forma nativa y sin flags. Aplicaciones como curl, PowerShell, Python, juegos o apps que usan Schannel/WinHTTP/BoringSSL sin esa convención **no** escriben el keylog.
- **No retroactivo:** las sesiones TLS que empezaron antes de fijar la variable no tendrán claves.
- **TLS 1.3 vs 1.2:** ambos funcionan; verás etiquetas distintas en el keylog (`CLIENT_RANDOM` en 1.2, `*_TRAFFIC_SECRET` en 1.3).
- **Si el usuario de la víctima no es el mismo que ejecuta la herramienta**, la variable de usuario no se aplica a otro perfil; usa `launch` dentro de la sesión de dicho usuario.
- **El recurso SMB es de solo lectura** pero accesible desde toda la LAN local mientras esté activo. Desactívalo con `uninstall` cuando no lo uses.
- **Wireshark necesita el keylog en una ruta local** de la máquina atacante (no acepta rutas UNC en algunos builds); copia el fichero antes de abrirlo.

---

## Fuente y compilación (si quieres tocar código)

- `main.go` — modos, lógica de setup/status/launch/uninstall.
- `winenv.go` — notificación `WM_SETTINGCHANGE` (WinAPI).
- `go.mod` — módulo Go (compila con Go ≥ 1.22).

```bash
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o tlskeylab.exe .
```

## Ética y alcance

Esta herramienta **solo** habilita el mecanismo SSLKEYLOGFILE en la máquina donde se ejecuta, con cambios visibles, logueados y reversibles. No intercepta tráfico de terceros, no instala servicios ni persiste silenciosamente. Úsala solo sobre equipos que te pertenezcan o para los que tengas autorización expresa.
