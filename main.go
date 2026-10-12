// tlskeylab - Herramienta de laboratorio para descifrar tráfico HTTPS PROPIO con Wireshark
// mediante el mecanismo estándar SSLKEYLOGFILE (TLS keylog).
//
// Modos de uso:
//
//	tlskeylab.exe setup            Configura todo (variable de entorno, fichero de claves, recurso SMB, firewall)
//	tlskeylab.exe status           Muestra el estado actual de la configuración
//	tlskeylab.exe launch chrome    Arranca Chrome con SSLKEYLOGFILE inyectada en el proceso
//	tlskeylab.exe launch edge      Arranca Edge con SSLKEYLOGFILE inyectada en el proceso
//	tlskeylab.exe uninstall        Revierte todos los cambios (usa --purge para borrar ficheros también)
//
// Seguridad y alcance (por diseño):
//   - Solo toca la máquina local donde se ejecuta (HKCU, ficheros del usuario, firewall de entrada).
//   - Todo queda registrado en un log visible: %USERPROFILE%\tlskeylab\tool.log
//   - Todo es idempotente y reversible con "uninstall".
//   - No hay persistencia oculta ni intercepción de tráfico de terceros: la herramienta no
//     captura nada por sí misma; solo habilita el mecanismo estándar de keylog TLS que los
//     navegadores escriben para SUS PROPIAS sesiones.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	appName     = "tlskeylab"
	envVar      = "SSLKEYLOGFILE"
	shareName   = "tlskeys"
	firewallRul = "tlskeylab SMB-in"
)

// ==== rutas ====

func toolDir() string   { return filepath.Join(homeDir(), "tlskeylab") }
func logPath() string   { return filepath.Join(toolDir(), "tool.log") }
func keylogPath() string { return filepath.Join(toolDir(), "sslkeys.log") }

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return `C:\Users\` + os.Getenv("USERNAME")
	}
	return h
}

// ==== utilidades de presentación ====

func info(c string) { fmt.Println("[*]", c) }
func ok(c string)   { fmt.Println("[+]", c) }
func warn(c string) { fmt.Println("[!]", c) }

// ==== utilidades de sistema ====

// run ejecuta un comando y devuelve (salida combinada, código de salida).
func run(name string, args ...string) (string, int) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, isEE := err.(*exec.ExitError); isEE {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return strings.TrimSpace(string(out)), code
}

// logLine escribe una línea con timestamp en tool.log y en consola.
func logLine(kind, msg string) {
	f, err := os.OpenFile(logPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		fmt.Fprintf(f, "%s [%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), kind, msg)
		f.Close()
	}
	switch kind {
	case "OK":
		ok(msg)
	case "WARN":
		warn(msg)
	default:
		info(msg)
	}
}

// queryReg devuelve el valor REG_SZ de HKCU bajo la ruta/clave dada (cadena vacía si no existe).
func queryReg(regPath, value string) string {
	out, _ := run("reg", "query", regPath, "/v", value)
	rows := strings.Split(out, "\n")
	for _, row := range rows {
		cols := strings.Fields(strings.TrimSpace(row))
		if len(cols) >= 3 && strings.EqualFold(cols[0], value) {
			return strings.Join(cols[2:], " ")
		}
	}
	return ""
}

// broadcastEnvChange avisa a las aplicaciones (Explorer incluido) de que cambió el entorno
// de usuario, para que los procesos nuevos hereden la nueva variable sin cerrar sesión.
func broadcastEnvChange() { userBroadcastEnvChange() }

// ==== modos ====

func modeSetup() {
	banner()
	complyingNotice()

	os.MkdirAll(toolDir(), 0755)

	// 1) Fichero de claves TLS (crearlo vacío si no existe; nunca se sobreescribe).
	if _, err := os.Stat(keylogPath()); os.IsNotExist(err) {
		if f, ferr := os.OpenFile(keylogPath(), os.O_CREATE|os.O_WRONLY, 0644); ferr == nil {
			f.Close()
			logLine("OK", "Fichero de claves creado en "+keylogPath())
		} else {
			logLine("WARN", "No se pudo crear el fichero de claves: "+ferr.Error())
		}
	} else {
		logLine("INFO", "Fichero de claves ya existe en "+keylogPath())
	}

	// 2) Variable de entorno de usuario SSLKEYLOGFILE (idempotente).
	envPath := regEnvPathFull
	if cur := queryReg(envPath, envVar); strings.EqualFold(cur, keylogPath()) {
		logLine("INFO", "Variable "+envVar+" ya estaba configurada con el valor correcto")
	} else if cur != "" {
		logLine("WARN", "Variable "+envVar+" ya existía con otro valor ("+cur+"); NO se sobreescribe.")
		logLine("WARN", "Elimínala o corrígela manualmente si quieres que tlskeylab la gestione.")
	} else {
		_, code := run("reg", "add", envPath, "/v", envVar, "/t", "REG_SZ", "/d", keylogPath(), "/f")
		if code == 0 {
			logLine("OK", "Variable "+envVar+" fijada (HKCU\\Environment) a "+keylogPath())
			broadcastEnvChange()
		} else {
			logLine("WARN", "No se pudo fijar la variable "+envVar)
		}
	}

	// 3) Recurso compartido SMB de solo lectura (necesita elevación).
	setupShare()

	// 4) Regla de firewall para SMB solo desde la LAN local (necesita elevación).
	setupFirewall()

	// 5) Resumen.
	fmt.Println()
	modeStatus()
	logLine("INFO", "setup completado")
}

func setupShare() {
	out, _ := run("cmd", "/c", "net share "+shareName)
	if strings.Contains(out, "Nombre de recurso") || strings.Contains(out, "Share name") {
		logLine("INFO", "Recurso "+shareName+" ya existe (no se toca)")
		return
	}
	// El nombre "Everyone" es "Todos" en Windows localizado en español; probamos ambas variantes.
	shareOK := false
	lastOut := ""
	for _, grant := range []string{"Everyone", "Todos"} {
		out2, code2 := run("cmd", "/c", fmt.Sprintf(`net share %s=%s /grant:%s,READ`, shareName, toolDir(), grant))
		lastOut = out2
		if code2 == 0 {
			shareOK = true
			break
		}
	}
	if shareOK {
		logLine("OK", "Recurso SMB \\\\"+hostname()+"\\"+shareName+" -> "+toolDir())
	} else {
		logLine("WARN", "No se pudo crear el recurso SMB: "+lastOut)
		logLine("WARN", "Ejecuta de nuevo tlskeylab como Administrador, o crea el recurso a mano:")
		logLine("WARN", fmt.Sprintf(`  net share %s="%s" /grant:Todos,READ`, shareName, toolDir()))
	}
}

func setupFirewall() {
	_, code := run("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+firewallRul, "dir=in", "action=allow", "profile=domain,private",
		"protocol=TCP", "localport=445", "remoteip=LocalSubnet")
	if code == 0 {
		logLine("OK", "Regla de firewall creada/actualizada: "+firewallRul+" (SMB solo en red local)")
	} else {
		logLine("WARN", "No se pudo crear la regla de firewall (¿permisos de administrador?).")
	}
}

func modeStatus() {
	allGood := true

	// Variable de entorno
	envVal := queryReg(regEnvPathFull, envVar)
	if envVal == "" {
		envVal = os.Getenv(envVar) // puede venir heredada de la sesión
	}
	if envVal == "" {
		warn("Variable " + envVar + ": NO configurada")
		allGood = false
	} else if strings.EqualFold(envVal, keylogPath()) {
		ok("Variable " + envVar + " = " + envVal)
	} else {
		warn("Variable " + envVar + " = " + envVal + " (no es la ruta por defecto de tlskeylab)")
	}

	// Fichero de claves + número de claves
	n, lines := countKeys(keylogPath())
	if n >= 0 {
		ok(fmt.Sprintf("Fichero de claves: %s (%d claves, %d líneas)", keylogPath(), n, lines))
	} else {
		warn("Fichero de claves no existe todavía: se creará en setup o al arrancar un navegador")
	}

	// Recurso compartido
	out, _ := run("cmd", "/c", "net share "+shareName)
	if strings.Contains(out, "Nombre de recurso") || strings.Contains(out, "Share name") {
		ok("Recurso SMB \\\\" + hostname() + "\\" + shareName + " activo")
	} else {
		warn("Recurso SMB " + shareName + " no disponible (necesita setup como Administrador)")
	}

	// Regla de firewall
	_, code := run("netsh", "advfirewall", "firewall", "show", "rule", "name="+firewallRul)
	if code == 0 {
		ok("Regla de firewall " + firewallRul + " presente")
	} else {
		warn("Regla de firewall " + firewallRul + " no presente")
	}

	if !allGood {
		fmt.Println("\nEjecuta: " + appName + ".exe setup  (como Administrador para SMB y firewall)")
	}
}

func countKeys(path string) (claves int, lineas int) {
	claves, lineas = -1, 0
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	claves = 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		lineas++
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		claves++
	}
	return
}

func modeLaunch(browserName string) {
	b := findBrowser(browserName)
	if b == nil {
		warn("Navegador no encontrado o no soportado: " + browserName)
		fmt.Println("Navegadores soportados: chrome, edge")
		os.Exit(1)
	}
	// Asegurar que el fichero existe; el navegador añadirá sus claves.
	os.MkdirAll(toolDir(), 0755)
	if f, ferr := os.OpenFile(keylogPath(), os.O_CREATE|os.O_WRONLY, 0644); ferr == nil {
		f.Close()
	}

	if !ensureNoOtherInstances(b) {
		warn("Parece que ya hay un " + b.name + " en ejecución. Ciérralo antes para que las")
		warn("sesiones nuevas usen la variable " + envVar + " (los procesos ya arrancados NO la leen de nuevo).")
	}

	env := os.Environ()
	env = append(env, envVar+"="+keylogPath())
	cmd := exec.Command(b.exe)
	cmd.Env = env
	cmd.Dir = homeDir()
	if err := cmd.Start(); err != nil {
		warn("Error arrancando el navegador: " + err.Error())
		os.Exit(1)
	}
	go cmd.Wait()
	logLine("OK", b.name+" lanzado con "+envVar+"="+keylogPath())
	logLine("INFO", "Las claves aparecerán en el fichero a medida que navegues por sitios HTTPS.")
}

func ensureNoOtherInstances(b *browserDef) bool {
	out, _ := run("tasklist", "/FI", "IMAGENAME eq "+b.image)
	return !strings.Contains(strings.ToLower(out), strings.ToLower(b.image))
}

// browserDef representa un navegador soportado por el modo launch.
type browserDef struct {
	name, image, exe string
}

var supported = []struct {
	name   string
	images string
	cands  []string
}{
	{"chrome", "chrome.exe", []string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	}},
	{"edge", "msedge.exe", []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	}},
}

func findBrowser(name string) *browserDef {
	key := strings.ToLower(strings.TrimSpace(name))
	for _, s := range supported {
		if strings.ToLower(s.name) == key {
			for _, c := range s.cands {
				if _, err := os.Stat(c); err == nil {
					return &browserDef{name: s.name, image: s.images, exe: c}
				}
			}
		}
	}
	return nil
}

func modeUninstall(purge bool) {
	banner()
	complyingNotice()

	// 1) Variable de entorno (solo si la gestionamos nosotros).
	if cur := queryReg(regEnvPathFull, envVar); strings.EqualFold(cur, keylogPath()) {
		_, code := run("reg", "delete", regEnvPathFull, "/v", envVar, "/f")
		if code == 0 {
			logLine("OK", "Variable "+envVar+" eliminada de HKCU\\Environment")
			broadcastEnvChange()
		}
	} else if cur == "" {
		logLine("INFO", "Variable "+envVar+" no estaba en el registro (nada que hacer)")
	} else {
		logLine("WARN", "Variable "+envVar+" contiene otro valor ("+cur+"); no se toca.")
	}

	// 2) Recurso compartido.
	if _, code := run("cmd", "/c", "net share "+shareName+" /delete /y"); code == 0 {
		logLine("OK", "Recurso compartido "+shareName+" eliminado")
	} else {
		logLine("INFO", "Recurso "+shareName+" no existía o no se pudo borrar (requiere admin)")
	}

	// 3) Regla de firewall.
	if _, code := run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+firewallRul); code == 0 {
		logLine("OK", "Regla de firewall "+firewallRul+" eliminada")
	} else {
		logLine("INFO", "Regla de firewall no existía (nada que hacer)")
	}

	// 4) Ficheros (solo con --purge; por defecto se conservan para análisis posterior).
	if purge {
		if err := os.RemoveAll(toolDir()); err == nil {
			logLine("OK", "Directorio "+toolDir()+" eliminado (--purge)")
		} else {
			logLine("WARN", "No se pudo borrar "+toolDir()+": "+err.Error())
		}
	} else {
		logLine("INFO", "Ficheros en "+toolDir()+" se conservan (usa --purge para borrarlos también)")
	}

	logLine("OK", "uninstall completado. Reinicia los navegadores para que la variable deje de tener efecto.")
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	return h
}

func banner() {
	fmt.Println(appName + " - laboratorio SSLKEYLOGFILE para Wireshark (solo tráfico propio)")
	fmt.Println("---------------------------------------------------------------------")
}

func complyingNotice() {
	fmt.Println("Alcance: solo tu máquina local y tu LAN privada de laboratorio.")
	fmt.Println("No captura tráfico por sí misma: habilita el keylog TLS estándar de tus navegadores.")
	fmt.Println("Todos los cambios quedan en " + logPath())
	fmt.Println()
}

func main() {
	os.Exit(realMain(os.Args[1:]))
}

func realMain(args []string) int {
	if len(args) == 0 {
		fmt.Println("Uso: " + appName + ".exe <setup|status|launch chrome|launch edge|capture|uninstall>")
		fmt.Println("Opciones: uninstall --purge    (borra también el directorio de claves y logs)")
		fmt.Println("          capture [duracion] [-i N]   (captura pcapng hasta Ctrl+C o N segundos)")
		return 2
	}
	os.MkdirAll(toolDir(), 0755)

	mode := strings.ToLower(args[0])
	switch mode {
	case "setup":
		modeSetup()
	case "status":
		modeStatus()
	case "launch":
		if len(args) < 2 {
			warn("Falta el navegador: launch chrome|launch edge")
			return 2
		}
		modeLaunch(args[1])
	case "capture":
		modeCapture(args[1:])
	case "uninstall":
		modeUninstall(hasFlag(args, "--purge"))
	default:
		warn("Modo desconocido: " + mode)
		return 2
	}
	return 0
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args[1:] {
		if strings.EqualFold(a, flag) {
			return true
		}
	}
	return false
}
