#!/usr/bin/env python3
"""
tlsviewer.py - Abre Wireshark automáticamente con el keylog TLS cargado y el pcap abierto.

Uso típico: tras usar `tlskeylab.exe capture` en la máquina víctima, ten en la MISMA
carpeta (o indícalos por argumento) el fichero sslkeys.log y uno o más *.pcapng:

    python3 tlsviewer.py

El script:
    1. Localiza el keylog (*.log) y el pcapng más reciente en la carpeta actual
       (o los que pases por argumento).
    2. Localiza un ejecutable de Wireshark (Linux o Windows).
    3. Crea/actualiza un perfil de Wireshark llamado "TLSKeyLab" con la clue de TLS
       (Pre)-Master-Secret log filename apuntando al keylog absoluto.
    4. Lanza Wireshark con:  -C TLSKeyLab  -r <pcapng>
       Wireshark arranca con el perfil listo y el pcap abierto y descifrado.

Opciones:
    --keylog RUTA    keylog concreto (por defecto: sslkeys.log en la carpeta)
    --pcap RUTA      pcapng concreto (por defecto: el más reciente *.pcapng)
    --wireshark RUTA ruta al ejecutable de Wireshark si no está en el PATH
    --dir DIR        carpeta donde buscar (por defecto: la actual)
    --list           solo mostrar qué usaría y no abrir nada
"""

import argparse
import glob
import os
import shutil
import subprocess
import sys
import tempfile

PROFILE_NAME = "TLSKeyLab"

# Rutas típicas del ejecutable de Wireshark, por SO.
WIRESHARK_CANDIDATES = {
    "win": [
        r"C:\Program Files\Wireshark\Wireshark.exe",
        r"C:\Program Files (x86)\Wireshark\Wireshark.exe",
    ],
    "linux": [
        "/usr/bin/wireshark",
        "/usr/local/bin/wireshark",
        "/opt/wireshark/bin/wireshark",
        "/snap/bin/wireshark",
    ],
    "darwin": [
        "/Applications/Wireshark.app/Contents/MacOS/Wireshark",
    ],
}


def find_wireshark(user_path):
    """Devuelve la ruta al ejecutable de Wireshark (o None)."""
    if user_path and os.path.isfile(user_path):
        return user_path
    which = shutil.which("wireshark")
    if which:
        return which
    win = sys.platform.startswith("win")
    can = WIRESHARK_CANDIDATES["win" if win else ("darwin" if sys.platform == "darwin" else "linux")]
    for c in can:
        if os.path.isfile(c):
            return c
    return None


def find_keylog(directory, user_path):
    """Localiza el keylog: sslkeys.log por preferencia, luego cualquier *.log."""
    if user_path:
        return user_path
    pref = os.path.join(directory, "sslkeys.log")
    if os.path.isfile(pref):
        return pref
    for pat in ("*.log", "*.keylog", "*.keys"):
        matches = sorted(glob.glob(os.path.join(directory, pat)), key=os.path.getmtime, reverse=True)
        for m in matches:
            # Evitar logs de la herramienta que no son el keylog.
            if "tool.log" not in os.path.basename(m):
                return m
    return None


def find_pcap(directory, user_path):
    """Localiza el pcapng más reciente (o el indicado por el usuario)."""
    if user_path:
        return user_path
    matches = []
    for pat in ("*.pcapng", "*.pcap"):
        matches.extend(glob.glob(os.path.join(directory, pat)))
    if not matches:
        return None
    return sorted(matches, key=os.path.getmtime, reverse=True)[0]


def write_profile(keylog_abs):
    """Escribe el perfil TLSKeyLab con el keylog configurado en la sección TLS.

    Devuelve el nombre del perfil. Wireshark lee perfiles desde:
        Windows: %APPDATA%\\Wireshark\\profiles\\<perfil>\\preferences
        Linux:   ~/.config/wireshark/profiles/<perfil>/preferences  (o ~/.wireshark en versiones antiguas)
    """
    home = os.path.expanduser("~")
    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
        base = os.path.join(appdata, "Wireshark", "profiles", PROFILE_NAME)
    else:
        # Directorio de configuración de Wireshark en Linux.
        cfg_candidates = [
            os.path.join(home, ".config", "wireshark", "profiles", PROFILE_NAME),
            os.path.join(home, ".wireshark", "profiles", PROFILE_NAME),
        ]
        existing = next((c for c in cfg_candidates if os.path.isdir(os.path.dirname(c))),
                        cfg_candidates[0])
        base = existing
    os.makedirs(base, exist_ok=True)
    prefs = os.path.join(base, "preferences")
    # Nota: en preferences el keylog se indica con la clave tls.keylog_file.
    # Usamos el formato estándar de Wireshark (sin espacios tras el separador).
    line = f"tls.keylog_file: {keylog_abs}\n"
    # Sobrescribimos o añadimos la línea si el perfil ya existía.
    body = []
    if os.path.isfile(prefs):
        with open(prefs, "r", encoding="utf-8", errors="replace") as f:
            body = [ln for ln in f.readlines() if not ln.startswith("tls.keylog_file:")]
    body.append(line)
    with open(prefs, "w", encoding="utf-8") as f:
        f.writelines(body)
    return PROFILE_NAME


def main():
    ap = argparse.ArgumentParser(
        description="Abre Wireshark con el keylog configurado y el pcapng más reciente cargado.")
    ap.add_argument("--keylog", help="Ruta al fichero de claves TLS (sslkeys.log)")
    ap.add_argument("--pcap", help="Ruta al pcapng a abrir")
    ap.add_argument("--wireshark", help="Ruta al ejecutable de Wireshark")
    ap.add_argument("--dir", default=os.getcwd(), help="Carpeta donde buscar (por defecto: cwd)")
    ap.add_argument("--list", action="store_true", help="Mostrar qué usaría y salir")
    args = ap.parse_args()

    keylog = find_keylog(args.dir, args.keylog)
    pcap = find_pcap(args.dir, args.pcap)

    if not keylog or not fpath_readable(keylog):
        print("[!] No encontré un keylog TLS (sslkeys.log) en:", args.dir)
        print("    Pásalo explícito:  python3 tlsviewer.py --keylog /ruta/sslkeys.log")
        return 1
    keylog_abs = os.path.abspath(keylog)

    if not pcap:
        print("[!] No encontré ningún *.pcapng en:", args.dir)
        print("    Pásalo explícito:  python3 tlsviewer.py --pcap /ruta/capture.pcapng")
        return 1
    pcap_abs = os.path.abspath(pcap)

    ws = find_wireshark(args.wireshark)
    if not ws:
        print("[!] Wireshark no encontrado (ni en PATH ni en las rutas típicas).")
        print("    Pásalo explícito:  python3 tlsviewer.py --wireshark /ruta/Wireshark")
        return 1

    profile = write_profile(keylog_abs)
    print("[+] Perfil %s actualizado con el keylog:" % profile)
    print("    tls.keylog_file = %s" % keylog_abs)
    print("[+] Pcapng a abrir: %s" % pcap_abs)
    print("[+] Wireshark:      %s" % ws)

    if args.list:
        return 0

    cmd = [ws, "-C", profile, "-r", pcap_abs]
    print("[*] Ejecutando:", " ".join(cmd))
    try:
        subprocess.Popen(cmd)
    except Exception as e:
        print("[!] No se pudo abrir Wireshark:", e)
        return 1
    return 0


def fpath_readable(path):
    return os.path.isfile(path) and os.access(path, os.R_OK)


if __name__ == "__main__":
    sys.exit(main())
