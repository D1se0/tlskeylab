// ldb.go - Base de datos SQLite del labserver (driver moderno-go sqlite, sin CGO).
package main

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // driver SQLite puro-Go
)

var db *sql.DB

// openDB abre (y crea si no existe) la BD del lab en <dir>\lab_users.db.
func openDB(dir string) error {
	var err error
	db, err = sql.Open("sqlite", dir+`\lab_users.db`)
	if err != nil {
		return fmt.Errorf("abriendo sqlite: %w", err)
	}
	// Tabla de usuarios del laboratorio.
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id       INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("creando tabla users: %w", err)
	}
	// Tabla de logins registrados (para que veas también el lado servidor).
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS logins (
		id    INTEGER PRIMARY KEY AUTOINCREMENT,
		user  TEXT NOT NULL,
		pass  TEXT NOT NULL,
		ok    INTEGER NOT NULL,
		ip    TEXT,
		ts    TEXT DEFAULT CURRENT_TIMESTAMP
	)`)
	return err
}

// ensureUser inserta el usuario demo si no existe (INSERT OR IGNORE: idempotente).
func ensureUser(user, pass string) {
	_, _ = db.Exec(`INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`, user, pass)
}

// checkUser valida credenciales y devuelve (ok, nombreReal).
func checkUser(user, pass string) (bool, string) {
	var stored string
	err := db.QueryRow(`SELECT password FROM users WHERE username = ?`, user).Scan(&stored)
	if err == sql.ErrNoRows {
		return false, ""
	}
	if err != nil {
		return false, ""
	}
	if stored == pass {
		return true, user
	}
	return false, ""
}

// loginLog registra intento de login (lado servidor).
func loginLog(user, pass string, ok int, ip string) {
	_, _ = db.Exec(`INSERT INTO logins (user, pass, ok, ip) VALUES (?, ?, ?, ?)`, user, pass, ok, ip)
}
