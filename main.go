// SentinelProxy routes any application's traffic through SOCKS/HTTP proxies
// by rules — per app, per host, per port — with live connection
// monitoring, proxy chains and failover, and import/export for other tools.
package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/DestroyersTaken/SentinelProxy/internal/elevate"
	"github.com/DestroyersTaken/SentinelProxy/internal/service"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var appIcon []byte

//go:embed build/trayicon.png
var trayIcon []byte

var version = "0.1.0"

func dataDir(flagDir string) string {
	if flagDir != "" {
		return flagDir
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		// Portable mode: a "portable" marker next to the executable keeps
		// everything in a data folder beside it.
		if _, err := os.Stat(filepath.Join(dir, "portable")); err == nil {
			return filepath.Join(dir, "data")
		}
	}
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "SentinelProxy")
}

func main() {
	dirFlag := flag.String("data", "", "data directory (profiles, logs)")
	start := flag.Bool("start", false, "turn proxying on at launch")
	minimized := flag.Bool("minimized", false, "start hidden in the system tray")
	profile := flag.String("profile", "", "profile to activate")
	showVersion := flag.Bool("version", false, "print the version and exit")
	waitPID := flag.Int("wait-pid", 0, "wait for this process to exit first (used when restarting as administrator)")
	flag.Parse()
	if *waitPID > 0 {
		elevate.WaitForPID(*waitPID, 15*time.Second)
	}
	if *showVersion {
		fmt.Println("SentinelProxy", version)
		return
	}
	service.Version = version

	api, err := service.New(dataDir(*dirFlag))
	if err != nil {
		fmt.Fprintln(os.Stderr, "SentinelProxy:", err)
		os.Exit(1)
	}
	if *profile != "" {
		if _, err := api.SwitchProfile(*profile); err != nil {
			fmt.Fprintln(os.Stderr, "profile:", err)
		}
	}
	prefs := api.AppPrefs()

	dist, _ := fs.Sub(assets, "frontend/dist")
	var win *application.WebviewWindow
	app := application.New(application.Options{
		Name:        "SentinelProxy",
		Description: "Rule-based proxy routing for every app",
		Icon:        appIcon,
		Services:    []application.Service{application.NewService(api)},
		Assets:      application.AssetOptions{Handler: application.AssetFileServerFS(dist)},
		LogLevel:    slog.LevelWarn,
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "com.destroyerstaken.sentinelproxy",
			OnSecondInstanceLaunch: func(application.SecondInstanceData) {
				if win != nil {
					win.Show()
					win.Focus()
				}
			},
		},
		Mac:        application.MacOptions{ApplicationShouldTerminateAfterLastWindowClosed: false},
		OnShutdown: api.Shutdown,
		Server:     application.ServerOptions{Host: "127.0.0.1", Port: 8765},
	})
	api.Emit = func(name string, data any) { app.Event.Emit(name, data) }
	api.Quit = app.Quit
	api.SaveDialog = func(name string) (string, error) {
		return app.Dialog.SaveFile().SetFilename(name).CanCreateDirectories(true).PromptForSingleSelection()
	}

	hidden := *minimized || prefs.StartMinimized
	win = app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:             "main",
		Title:            "SentinelProxy",
		Width:            1320,
		Height:           840,
		MinWidth:         980,
		MinHeight:        620,
		URL:              "/",
		Hidden:           hidden,
		BackgroundColour: application.NewRGB(14, 16, 21),
	})

	var quitting atomic.Bool
	win.RegisterHook(events.Common.WindowClosing, func(ev *application.WindowEvent) {
		if quitting.Load() || !api.AppPrefs().CloseToTray {
			quitting.Store(true)
			app.Quit()
			return
		}
		ev.Cancel()
		win.Hide()
	})

	tray := app.SystemTray.New()
	tray.SetIcon(trayIcon)
	tray.SetTooltip("SentinelProxy")
	menu := application.NewMenu()
	menu.Add("Open SentinelProxy").OnClick(func(*application.Context) { win.Show(); win.Focus() })
	toggle := menu.AddCheckbox("Proxying enabled", false)
	toggle.OnClick(func(*application.Context) { api.Toggle() })
	menu.AddSeparator()
	menu.Add("Quit").OnClick(func(*application.Context) { quitting.Store(true); app.Quit() })
	tray.SetMenu(menu)
	tray.OnClick(func() { win.Show(); win.Focus() })
	api.OnStateChange = func(running bool) {
		toggle.SetChecked(running)
		if running {
			tray.SetTooltip("SentinelProxy — proxying on")
		} else {
			tray.SetTooltip("SentinelProxy — off")
		}
		menu.Update()
	}

	if *start || prefs.StartEnabled {
		api.SetRunning(true)
	}
	if err := app.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
