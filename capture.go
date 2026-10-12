// Modo capture de tlskeylab: captura tráfico con dumpcap (motor de captura de Wireshark)
// y deja un pcapng en la misma carpeta que el keylog, listo para analizar junto a las claves.
//
// Uso:
//
//	tlskeylab.exe capture          -> captura hasta Ctrl+C en la interfaz activa
//	tlskeylab.exe capture 30       -> captura 30 segundos
//	tlskeylab.exe capture -i 4     -> captura en la interfaz nº 4 (ver "dumpcap -D")
//	tlskeylab.exe capture 60 -i 4  -> ambas cosas
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

// findDumpcap busca dumpcap.exe en las rutas típicas y en el PATH. Si no está,
// intenta instalar Wireshark automáticamente vía winget (una sola vez, visible y con log).
func findDumpcap() (string, bool) {
	for _, c := range dumpcapCandidatesWin() {
		if fpathExists(c) {
			return c, false
		}
	}
	if p, err := exec.LookPath("dumpcap.exe"); err == nil {
		return p, false
	}
	if !ensureDumpcapInstalled() {
		return "", false
	}
	for _, c := range dumpcapCandidatesWin() {
		if fpathExists(c) {
			return c, true
		}
	}
	if p, err := exec.LookPath("dumpcap.exe"); err == nil {
		return p, true
	}
	return "", false
}

// ensureDumpcapInstalled instala Wireshark (trae dumpcap) vía winget de forma visible.
func ensureDumpcapInstalled() bool {
	info("dumpcap.exe no está presente; intentando instalar Wireshark automáticamente...")
	winget, err := exec.LookPath("winget.exe")
	if err != nil {
		logLine("WARN", "winget no está disponible; instala Wireshark a mano desde https://www.wireshark.org")
		return false
	}
	logLine("INFO", "Ejecutando: winget install --id WiresharkFoundation.Wireshark (puede tardar 2-3 min)")
	out, code := run(winget, "install", "--id", "WiresharkFoundation.Wireshark",
		"--silent", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity")
	if code != 0 {
		logLine("WARN", "winget devolvió código "+fmt.Sprint(code)+": "+lastLine(out))
		logLine("WARN", "Instala Wireshark manualmente desde https://www.wireshark.org y reejecuta 'capture'.")
		return false
	}
	logLine("OK", "Wireshark instalado correctamente (incluye dumpcap y tshark).")
	return true
}

// lastLine devuelve la última línea no vacía de una salida de comandos.
func lastLine(s string) string {
	lines := splitLines(s)
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			return t
		}
	}
	return ""
}

// captureOutPath genera el nombre del pcapng de salida (junto al keylog, con timestamp).
func captureOutPath() string {
	stamp := time.Now().Format("20060102_150405")
	return filepath.Join(toolDir(), "capture_"+stamp+".pcapng")
}

// parseCaptureArgs interpreta [duracion] [-i N].
func parseCaptureArgs(args []string) (iface int, durationSec int) {
	iface, durationSec = -1, 0 // -1 = elegir por defecto; 0 = infinito (Ctrl+C)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.EqualFold(a, "-i") && i+1 < len(args):
			iface = mustAtoi(args[i+1])
			i++
		case len(a) > 2 && strings.HasPrefix(strings.ToLower(a), "-i"):
			iface = mustAtoi(a[2:])
		case isPositiveInt(a):
			durationSec = mustAtoi(a)
		}
	}
	return
}

func isPositiveInt(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// modeCapture ejecuta la captura. Ctrl+C (SIGINT) o la duración la terminan; dumpcap
// cierra y voltea el pcapng correctamente al recibir la señal.
func modeCapture(args []string) {
	banner()
	complyingNotice()
	os.MkdirAll(toolDir(), 0755)

	dumpcap, installed := findDumpcap()
	if dumpcap == "" {
		warn("dumpcap.exe no encontrado e intento de instalación automática fallido.")
		fmt.Println("  Rutas buscadas: " + strings.Join(dumpcapCandidatesWin(), " | "))
		fmt.Println("  Instala Wireshark manualmente desde https://www.wireshark.org y reejecuta.")
		os.Exit(1)
	}
	if installed {
		ok("dumpcap instalado automáticamente: " + dumpcap)
	} else {
		ok("dumpcap: " + dumpcap)
	}

	// Lista de interfaces (dumpcap -D) para elegir y para la heurística de por defecto.
	dOut, _ := run(dumpcap, "-D")
	info("Interfaces disponibles (elige con -i N):")
	for _, line := range splitLines(dOut) {
		if strings.TrimSpace(line) != "" {
			fmt.Println("    " + strings.TrimSpace(line))
		}
	}

	iface, duration := parseCaptureArgs(args)
	if iface < 0 {
		iface = defaultIfaceWin(dOut) // saltar loopback y adaptadores virtuales
		if iface <= 0 {
			iface = 4 // fallback razonable (Ethernet0 en el laboratorio)
			warn("No detecté la interfaz activa; usando la 4 por defecto.")
		}
	}

	outPcap := captureOutPath()
	if _, err := os.Stat(outPcap); err == nil {
		os.Remove(outPcap)
	}

	dcmd := []string{"-i", fmt.Sprintf("%d", iface), "-w", outPcap}
	if duration > 0 {
		dcmd = append(dcmd, "-a", "duration:"+fmt.Sprint(duration))
		ok(fmt.Sprintf("Capturando en interfaz %d durante %d s...", iface, duration))
	} else {
		ok(fmt.Sprintf("Capturando en interfaz %d hasta Ctrl+C...", iface))
	}
	info("Salida: " + outPcap)
	fmt.Println()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	cmd := exec.Command(dumpcap, dcmd...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		warn("No se pudo iniciar dumpcap: " + err.Error())
		os.Exit(1)
	}

	done := make(chan struct{})
	go func() {
		cmd.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		info("Ctrl+C recibido; cerrando la captura de forma limpia...")
	case <-done:
	}

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		warn("dumpcap no terminó en 15 s; forzando cierre.")
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		<-done
	}
	cancel()

	if st, err := os.Stat(outPcap); err == nil && st.Size() > 0 {
		ok(fmt.Sprintf("Captura finalizada: %s (%d bytes)", outPcap, st.Size()))
		info("Cópialo junto con el keylog a la máquina atacante y ábrelo en Wireshark con TLS keylog_file configurado.")
	} else {
		warn("La captura quedó vacía (¿interfaz equivocada? prueba 'capture -i N' con otra N).")
	}
	logLine("INFO", fmt.Sprintf("capture terminado: iface=%d duracion=%ds salida=%s", iface, duration, outPcap))
}
