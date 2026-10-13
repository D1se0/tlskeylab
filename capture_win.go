// Parte específica de Windows para el modo capture de tlskeylab.
package main

// dumpcapCandidatesWin: rutas típicas de dumpcap en Windows.
func dumpcapCandidatesWin() []string {
	return []string{
		`C:\Program Files\Wireshark\dumpcap.exe`,
		`C:\Program Files (x86)\Wireshark\dumpcap.exe`,
		`C:\Users\diseo\AppData\Local\Programs\Wireshark\dumpcap.exe`,
	}
}

// defaultIfaceWin elige la interfaz por defecto a partir de la salida de "dumpcap -D".
// dumpcap numera las interfaces igual que tshark -D; saltamos loopback y las
// "Conexión de área local*" (adaptadores virtuales de Wi-Fi Direct de Windows).
func defaultIfaceWin(dumpcapDOut string) int {
	const (
		markLoopback = "loopback"
		markWFD      = "conexión de área local*" // adaptadores virtuales Windows
		markWFDAlt   = "local area connection*"
	)
	for _, line := range splitLines(dumpcapDOut) {
		idx, ok := parseIfaceIndex(line)
		if !ok {
			continue
		}
		l := toLowerASCII(line)
		if contains(l, markLoopback) || contains(l, markWFD) || contains(l, markWFDAlt) {
			continue
		}
		return idx
	}
	return 0
}
