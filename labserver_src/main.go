// labserver.go - Servidor web de LOGIN para el laboratorio tlskeylab.
// Sirve una página de login por HTTPS con certificado autofirmado y guarda
// los usuarios en SQLite. Todo autocontenido; ejecutar en la máquina "víctima".
//
// Uso:  labserver.exe                 (arranca: genera cert, prepara BD, firewall y abre puertos)
//       labserver.exe -port 8443      (cambia puerto; por defecto 8443)
//       labserver.exe -stop           (detiene la instancia previa y sale)
//
// Es una herramienta de laboratorio para ver TU PROPIO tráfico descifrado con
// Wireshark + SSLKEYLOGFILE. Las credenciales demo son "demo"/"demo123".
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	demoUser = "demo"
	demoPass = "demo123"
	appBrand = "tlskeylab-lab"
)

var portFlag = flag.String("port", "8443", "puerto HTTPS del servidor")
var stopFlag = flag.Bool("stop", false, "detener instancia en ejecución y salir")

func toolDir() string {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return `C:\Users\` + os.Getenv("USERNAME")
	}
	return h
}

func labDir() string { return filepath.Join(toolDir(), "labserver") }

// ---- plantillas ----

var pageTpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>{{.Brand}} — login</title>
<style>
 body { font-family: system-ui,sans-serif; background:#0e1526; color:#e8eefc;
        display:flex; align-items:center; justify-content:center; height:100vh; margin:0 }
 .card{ background:#16203a; padding:36px 44px; border-radius:16px; box-shadow:0 20px 60px rgba(0,0,0,.5) }
 h1{ margin:0 0 6px; font-size:1.4rem } small{ color:#8fa0c6 }
 input{ display:block; width:260px; margin:10px 0; padding:11px 14px; border-radius:9px;
        border:1px solid #2b3a63; background:#0e1526; color:#e8eefc; font-size:1rem }
 button{ width:288px; padding:12px; border:0; border-radius:9px; background:linear-gradient(92deg,#00e5ff,#7c4dff);
        color:#001018; font-weight:700; cursor:pointer; font-size:1rem }
 .msg{ margin-top:16px; padding:10px 14px; border-radius:9px; font-size:.92rem }
 .ok{ background:#0d3b1e; color:#7dffb2 } .bad{ background:#4a1026; color:#ff9db8 }
 code{ background:#0e1526; padding:2px 7px; border-radius:6px; color:#7cc9ff }
</style></head><body>
 <div class="card">
  <h1>{{.Brand}}</h1><small>laboratorio de descifrado TLS — credenciales demo: <code>{{.User}} / {{.Pass}}</code></small>
  <form method="POST" action="/login">
   <input name="username" placeholder="usuario" autocomplete="off" required>
   <input name="password" type="password" placeholder="contraseña" required>
   <button>Iniciar sesión</button>
  </form>
  {{if .Msg}}<div class="msg {{if .Ok}}ok{{else}}bad{{end}}">{{.Msg}}</div>{{end}}
 </div>
</body></html>`))

func render(w http.ResponseWriter, msg string, ok bool) {
	// Los campos van EXPLORADOS (mayúscula): los no explorados no son alcanzables
	// por Go templates, y Execute corta la respuesta justo en la primera variable
	// (era la causa de la página en blanco del lab).
	data := struct {
		Brand, User, Pass string
		Msg               string
		Ok                bool
	}{appBrand, demoUser, demoPass, msg, ok}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTpl.Execute(w, data); err != nil {
		// Nunca silenciamos: si la plantilla falla, la causa se registra en el
		// log del servidor y queda visible al depurar.
		fmt.Println("[!] Error renderizando plantilla:", err)
	}
}

// ---- handlers ----

func hRoot(w http.ResponseWriter, r *http.Request) { render(w, "", false) }

func hLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	user := strings.TrimSpace(r.FormValue("username"))
	pass := r.FormValue("password")
	ip := ""
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}
	ok, _ := checkUser(user, pass)
	loginLog(user, pass, bool2int(ok), ip)
	if ok {
		render(w, "✅ ¡Login correcto! Bienvenido, "+user+". (Las credenciales viajaron cifradas por TLS; reverbéralas en Wireshark con el keylog.)", true)
	} else {
		render(w, "❌ Credenciales incorrectas. Prueba "+demoUser+"/"+demoPass, false)
	}
}

func bool2int(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---- certificado autofirmado ----

func ensureCert(dir string) (tls.Certificate, error) {
	crtPath := filepath.Join(dir, "lab.crt")
	keyPath := filepath.Join(dir, "lab.key")
	if _, err := os.Stat(crtPath); err == nil {
		if _, e2 := os.Stat(keyPath); e2 == nil {
			cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
			if err == nil {
				return cert, nil
			}
		}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"tlskeylab lab"},
			CommonName:   "labserver.local",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"labserver.local", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.5.154")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	os.WriteFile(crtPath, certPEM, 0600)
	os.WriteFile(keyPath, keyPEM, 0600)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	return cert, err
}

// ---- firewall ----

func openFirewall(port string) {
	_, code := runFirewallCMD("netsh", "advfirewall", "firewall", "add", "rule",
		"name=tlskeylab lab HTTPS", "dir=in", "action=allow",
		"protocol=TCP", "localport="+port, "profile=any")
	if code != 0 {
		fmt.Println("[!] No se pudo abrir el firewall; ábrelo a mano si vas a entrar desde otra máquina.")
	} else {
		fmt.Println("[+] Firewall abierto para HTTPS en el puerto " + port)
	}
}

// installCert instala el certificado autofirmado en el almacén de raíces de
// confianza DEL USUARIO (no requiere administrador). Así Chrome/Edge cargan la
// página SIN el aviso de "su conexión no es privada" y sin páginas en blanco.
// Se usa la API nativa de Windows (CertAddCertificateContextToStore) porque
// certutil -addstore -user Root falla con ERROR_NOT_SUPPORTED en algunas builds.
func installCert(dir string) {
	der, err := os.ReadFile(filepath.Join(dir, "lab.crt"))
	if err != nil {
		fmt.Println("[!] No se pudo leer lab.crt para instalarlo:", err)
		return
	}
	pemBytes, _ := pem.Decode(der)
	if pemBytes == nil {
		fmt.Println("[!] lab.crt no es un PEM válido")
		return
	}
	if err := winAddUserRoot(pemBytes.Bytes); err != nil {
		fmt.Println("[!] No se pudo instalar el cert en el almacén del usuario:", err)
		fmt.Println("    Instálalo a mano: doble clic en " + filepath.Join(dir, "lab.crt") + " →")
		fmt.Println("    Instalar certificado → Usuario actual → Entidades emisoras de raíz de confianza.")
		return
	}
	fmt.Println("[+] Cert instalado en el almacén de raíces del usuario (Chrome/Edge sin aviso).")
}

// winAddUserRoot añade un cert DER al almacén "Root" del USUARIO ACTUAL.
func winAddUserRoot(der []byte) error {
	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM_W, // almacén de sistema
		0,                                // encoding por defecto
		0,                                // provider por defecto
		windows.CERT_SYSTEM_STORE_CURRENT_USER,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("Root"))))
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	ctx, err := windows.CertCreateCertificateContext(
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		&der[0], uint32(len(der)))
	if err != nil {
		return err
	}
	defer windows.CertFreeCertificateContext(ctx)
	return windows.CertAddCertificateContextToStore(store, ctx, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil)
}

func runFirewallCMD(name string, args ...string) (string, int) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return strings.TrimSpace(string(out)), code
}

// ---- arranque como tarea en background visible ----

// isRunning comprueba si un labserver ya está a la escucha (probe TCP).
func isRunning(port string) bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 800*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ---- main ----

func main() {
	flag.Parse()
	dir := labDir()
	os.MkdirAll(dir, 0755)

	if *stopFlag {
		fmt.Println("[*] Deteniendo labserver (si está corriendo)...")
		// la CLI "taskkill" con imagen y/o puerto; usamos el nombre de proceso.
		out, code := runFirewallCMD("taskkill", "/F", "/IM", "labserver.exe")
		if code != 0 {
			fmt.Println("[*]", out)
		} else {
			fmt.Println("[+] Instancias de labserver.exe detenidas.")
		}
		_, _ = runFirewallCMD("netsh", "advfirewall", "firewall", "delete", "rule", "name=tlskeylab lab HTTPS")
		return
	}

	if isRunning(*portFlag) {
		fmt.Printf("[+] El labserver ya está a la escucha en el puerto %s (nada que hacer).\n", *portFlag)
		fmt.Printf("    Accede con:  https://localhost:%s  (o https://IP-de-la-victima:%s)\n", *portFlag, *portFlag)
		return
	}

	// BD
	if err := openDB(dir); err != nil {
		fmt.Println("[!] Error preparando SQLite:", err)
		os.Exit(1)
	}
	ensureUser(demoUser, demoPass)
	fmt.Printf("[+] SQLite listo (%s\\lab_users.db). Usuario demo: %s / %s\n", dir, demoUser, demoPass)

	// Certificado
	cert, err := ensureCert(dir)
	if err != nil {
		fmt.Println("[!] Error generando certificado autofirmado:", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Certificado autofirmado listo (%s\\lab.crt) con SANs localhost + LAN.\n", dir)

	// Firewall
	openFirewall(*portFlag)

	// Instalar el cert en el almacén del usuario para que el navegador no
	// rechace el handshake (era la causa de la web “en blanco”).
	installCert(dir)

	mux := http.NewServeMux()
	mux.HandleFunc("/", hRoot)
	mux.HandleFunc("/login", hLogin)

	srv := &http.Server{
		Addr:    "0.0.0.0:" + *portFlag,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			// Para el LAB forzamos HTTP/1.1 (el navegador lo hará de todos modos si
			// se lanzó con tlskeylab.exe launch; aquí lo dejamos al navegador).
			NextProtos: []string{"http/1.1"},
		},
	}

	fmt.Printf("[+] Servidor de login a la escucha en:  https://localhost:%s\n", *portFlag)
	fmt.Println("    Asegúrate de abrirlo con https:// (NO http://): es un servidor TLS.")
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		fmt.Println("[!] Servidor detenido:", err)
	}
	_ = bufio.NewReader(os.Stdin)
	_ = bytes.MinRead
}
