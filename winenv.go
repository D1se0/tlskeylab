// Funciones específicas de Windows para tlskeylab: notificación WM_SETTINGCHANGE
// para que las aplicaciones ya en ejecución (Explorador, shells) recojan la nueva
// variable de entorno de usuario sin cerrar la sesión.
package main

import (
	"syscall"
	"unsafe"
)

// regEnvPathFull es la ruta del registro donde Windows guarda el entorno de usuario.
const regEnvPathFull = `HKEY_CURRENT_USER\Environment`

var (
	user32       = syscall.NewLazyDLL("user32.dll")
	sendMessageW = user32.NewProc("SendMessageW")
)

// Constantes WinAPI.
const (
	hwndBroadcast   = ^uintptr(0) // HWND_BROADCAST
	wmSettingChange = 0x001A
)

// userBroadcastEnvChange emite WM_SETTINGCHANGE con lParam = "Environment".
func userBroadcastEnvChange() {
	lp, _, _ := sendMessageW.Call(
		hwndBroadcast,
		wmSettingChange,
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Environment"))),
	)
	_ = lp
}
