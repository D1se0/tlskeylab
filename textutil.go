// Utilidades de texto compartidas por los modos de tlskeylab.
package main

import (
	"os"
	"sort"
	"strconv"
	"strings"
)

func splitLines(s string) []string { return strings.Split(s, "\n") }

func toLowerASCII(s string) string { return strings.ToLower(s) }

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// parseIfaceIndex extrae el índice inicial "N." de una línea de "dumpcap -D".
func parseIfaceIndex(line string) (int, bool) {
	line = strings.TrimSpace(line)
	dot := strings.Index(line, ".")
	if dot <= 0 {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[:dot]))
	if err != nil {
		return 0, false
	}
	return n, true
}

// sortStrings devuelve una copia ordenada de s.
func sortStrings(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}

// fpathExists comprueba si existe un fichero.
func fpathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// mustAtoi convierte a entero tolerando errores (devuelve 0 si no es numérico).
func mustAtoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}
