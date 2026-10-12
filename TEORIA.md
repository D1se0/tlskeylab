# Teoría: por qué se puede descifrar HTTPS con el keylog y cómo funciona por dentro

Este documento explica con calma y rigor **por qué funciona** la técnica que automatiza `tlskeylab`. No hace falta ser experto en criptografía: cada concepto se presenta cuando se necesita.

---

## 1. ¿Por qué HTTPS no es legible en Wireshark "de serie"?

Cuando tu navegador habla con un servidor por HTTPS, lo que viaja por el cable no es texto, sino **cifrado simétrico**: ambos lados acordaron una clave secreta al principio de la conexión (el *handshake*) y todas las peticiones/respuestas (los verdaderos HTTP) van cifradas con ella.

Wireshark solo ve los **bytes cifrados**. Puede mostrar metadatos (quién habla con quién, cuánto se transfiere, certificados server→client en claro) porque TLS los deja visibles a propósito; pero el contenido de la sesión (URLs, headers, bodies) es indistinguible de ruido sin la clave de sesión.

Esto no es un defecto de Wireshark ni un "modo oculto": es el diseño mismo de TLS. El cifrado es de **extremo a extremo**, y las claves solo existen dentro del navegador (cliente) y del servidor. Ni el router, ni el antivirus, ni Wireshark las ven.

## 2. ¿Dónde están las claves, entonces?

En la memoria del proceso del navegador. Ahí surge la idea del **keylog**: una convención heredada de NSS (la librería criptográfica de Mozilla) y adoptada por Chrome/Edge/Firefox: **"si la variable de entorno `SSLKEYLOGFILE` está definida cuando arranco, escribe los secretos de cada handshake en ese fichero"**.

Es decir: el propio navegador, que es la única parte del mundo legitimate que sabe las claves, es quien las **regala a su usuario** a petición. No hay ataque: es instrumentation entre un software y su operador.

Formato de línea en el fichero (NSS Keylog Format):

```
CLIENT_HANDSHAKE_TRAFFIC_SECRET 3e5d3293ba6af989... 5c82d8575aae338c...
^ etiqueta                       ^ Random del ClientHello   ^ el secreto
```

- **Etiqueta**: qué secreto es (ver §4 para qué significa cada una en TLS 1.2 vs 1.3).
- **Random del ClientHello**: el navegador envía en el primer mensaje del handshake un número aleatorio de 32 bytes en **texto claro** (cualquiera que capture el tráfico lo ve). Wireshark lo lee del pcap y lo usa como "identificador de sesión" para buscar el secreto en el keylog.
- **El secreto**: el valor del que derivan las claves simétricas de esa sesión.

## 3. El handshake TLS a vista de pájaro (y por qué basta un solo secreto)

TLS 1.3 (lo que usan hoy casi todos los sitios):

1. **ClientHello** (en claro): propuestas de cifrados + `random` de 32 bytes + compartir ("key share") de clave pública efímera.
2. **ServerHello** (en claro): elige cifrado + su propio key share + su random.
3. **A partir de aquí, TODO va cifrado.** El navegador ya puede calcular el secreto de handshake con las efímeras (esta es la magia de Diffie-Hellman: ambos lados llegan al mismo secreto por caminos distintos, y un observador de la red no puede calcularlo ni "a medias").

El resto del handshake (certificado, Finished, etc.) va ya cifrado con ese secreto de handshake; luego se derivan los **traffic secrets** (los que cifran el HTTP real) con una KDF (HKDF). El keylog escribe precisamente estos valores derivados (`*_TRAFFIC_SECRET`), por lo que Wireshark salta directamente al final del cálculo: le das el secreto y él genera las claves simétricas aplicando la misma HKDF con los parámetros de la sesión (que aprende del propio pcap: cipher suite, etc.).

En TLS 1.2 (aún común en servicios internos) hay RSA key exchange o (EC)DHE; en el primer caso el secreto es el "pre-master secret" descifrado con la clave RSA del servidor, y el keylog registra `CLIENT_RANDOM <random> <master_secret>`: 48 bytes de material del que derivan las claves de la sesión. Wireshark tratará ambas etiquetas igual que en 1.3: empareja por el random de ClientHello.

**Moraleja importante y honesta:** como el secreto depende de Diffie-Hellman dado en el propio handshake, **no se puede** "retro-decodear" tráfico que no tenga claves registradas, ni descifrar sesiones *futuras* sin seguir escribiendo el keylog. Solo se descifra lo cuyas claves quedaron apuntadas.

## 4. ¿Por qué un atacante en el medio no puede hacerlo mismo?

Porque carece de los dos extremos:
- **No puede calcular el secreto de un handshake DH** aunque capture los paquetes (es el problema del logaritmo discreto: matemáticamente intratable hoy).
- **No puede inyectar la variable SSLKEYLOGFILE en un proceso ya vivo** (el entorno de un proceso se lee solo al arrancar, y no hay API de Windows para "parchearlo" de otra sesión sin permisos del mismo usuario).

Por eso la técnica "solo funciona" si el propio usuario/admin de la máquina colabora: lanzar el navegador con la variable, o fijarla en su perfil de usuario. Es una herramienta de **análisis consentido**, no de intercepción. Un MITM clásico (proxy con CA propia, ARP spoofing + SSL strip...) son técnicas *distintas* con otros riesgos y detecciones; tlskeylab no hace nada de eso.

## 5. Cómo encaja cada pieza concreta de tlskeylab

| Pieza | Qué resuelve |
|---|---|
| `setup` fija `SSLKEYLOGFILE` en `HKCU\Environment` | Los navegadores iniciados en esa sesión de usuario ya leerán la variable al arrancar. La notificación `WM_SETTINGCHANGE` evita tener que cerrar sesión. |
| `launch <navegador>` | Arranca el proceso con la variable SIEMPRE inyectada (cmd.Env), independientemente del registro/sesión. Es la vía más fiable. |
| `capture` (dumpcap) | dumpcap es el motor de captura de Wireshark: mismo formato pcapng, misma Npcap, sin la GUI. Autonomía total en la víctima. |
| auto-instalación vía winget | Si dumpcap no está (no hay Wireshark), lo instala silenciosamente desde los repositorios de winget de Windows. |
| recurso SMB del keylog | El "pase de claves" entre máquinas: la carpeta se comparte de solo lectura para que la atacante se descargue el fichero por SMB. |
| `tlsviewer.py` (atacante) | Empareja keylog + pcap y abre Wireshark con un perfil (`TLSKeyLab`) que ya lleva `tls.keylog_file` configurado: cero clicks de menús. |

## 6. Qué ves exactamente al descifrar y qué espera Wireshark

Al abrir el pcap con el keylog configurado:

- En la sección de detalles del paquete TLS aparece un árbol "Decrypted TLS data (SSL/TLS record)" con el HTTP2/HTTP en claro debajo. Sigue la conversación con clic derecho → Follow → TLS/HTTP2 Stream.
- Wireshark empareja paquete ↔ secreto por el `Random` del ClientHello de **ese TCP stream**. Si el keylog se pasa con las claves después de capturar, no pasa nada: el emparejado se hace al abrir, no al capturar (a diferencia del parser antiguo "SSL (pre)-master-secret log", el actual lee el keylog bajo demanda).
- El keylog puede crecer después: si el pcap contiene una sesión cuyas claves llegaron después, basta reabrir o recargar el fichero para que se descifre (Wireshark lo lee de nuevo al re-cargar el pcap).

## 7. Qué NO puede hacer esta técnica

- Descifrar tráfico de navegadores/apps que no escribieron el keylog (curl, PowerShell, apps que usan Schannel sin esa convención).
- Descifrar sesiones que **ya se cerraron** si sus claves no llegaron a registrarse.
- Descifrar tráfico de **otros usuarios** del sistema: la variable es por usuario, y `launch` solo afecta al proceso que arranca.
- Interceptar en red: no hay ARP spoofing, ni proxy, ni fake CA; solo el fichero de claves que el propio software del usuario genera.

## 8. Ética y marco de uso

En un laboratorio (dos máquinas tuyas, IPs privadas), la técnica permite estudiar HTTP/2, cabeceras, cookies, QUIC, como lo hace cualquier equipo de desarrollo que depure su app. Fuera del laboratorio, usar esta técnica sobre equipos de terceros sin consentimiento explícito puede ser ilegal (protección de datos, secretos empresariales, acceso no autorizado a sistemas) además de antiético. El propósito del proyecto es docente: entender por dentro cómo funciona el cifrado que usas cada día.

---

*Documento generado para el proyecto tlskeylab. Correcciones y feedback bienvenidos.*
