// Панель awg-cascade и агент статистики сервера 2.
// Только стандартная библиотека Go: один файл без зависимостей.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const version = "0.8.2"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "команды: serve, agent, set-password, setup-token, version")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "serve":
		cmdServe(os.Args[2:])
	case "agent":
		cmdAgent(os.Args[2:])
	case "set-password":
		cmdSetPassword(os.Args[2:])
	case "setup-token":
		cmdSetupToken(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "неизвестная команда:", os.Args[1])
		os.Exit(2)
	}
}

func cmdSetPassword(args []string) {
	fs := flag.NewFlagSet("set-password", flag.ExitOnError)
	state := fs.String("state", "/etc/awg-cascade", "каталог состояния")
	_ = fs.Parse(args)
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	pass := strings.TrimRight(string(b), "\r\n")
	if len(pass) < 8 {
		log.Fatal("пароль короче 8 символов")
	}
	dir := filepath.Join(*state, "panel")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Fatal(err)
	}
	path := filepath.Join(dir, "auth.json")
	_ = os.Remove(filepath.Join(dir, "sessions.json")) // новый пароль закрывает все входы
	old, _ := readAuth(path)
	if err := writeAuth(path, old.User, pass); err != nil {
		log.Fatal(err)
	}
}

func cmdSetupToken(args []string) {
	fs := flag.NewFlagSet("setup-token", flag.ExitOnError)
	state := fs.String("state", "/etc/awg-cascade", "каталог состояния")
	_ = fs.Parse(args)
	tok, err := newSetupToken(*state)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(tok)
}

func cmdAgent(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	listen := fs.String("listen", "10.87.2.1:8711", "адрес внутри туннеля")
	tunnel := fs.String("tunnel-if", "awgexit", "интерфейс туннеля")
	_ = fs.Parse(args)

	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(readHost(*tunnel))
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfg := Config{}
	fs.StringVar(&cfg.State, "state", "/etc/awg-cascade", "каталог состояния")
	fs.IntVar(&cfg.Port, "port", 0, "порт панели")
	fs.StringVar(&cfg.Base, "base", "", "секретный адрес, например /abc")
	fs.StringVar(&cfg.Host, "host", "", "внешний IP для сертификата")
	fs.StringVar(&cfg.CLI, "cli", "/usr/local/sbin/awg-cascade", "программа управления")
	fs.StringVar(&cfg.Agent, "agent", "10.87.2.1:8711", "адрес агента сервера 2")
	fs.StringVar(&cfg.ClientsIf, "clients-if", "awgclients", "туннель устройств")
	fs.StringVar(&cfg.UplinkIf, "uplink-if", "awguplink", "туннель к серверу 2")
	fs.StringVar(&cfg.AWG, "awg", "awg", "программа awg")
	_ = fs.Parse(args)
	if cfg.Port == 0 || len(cfg.Base) < 2 || cfg.Base[0] != '/' {
		log.Fatal("нужны --port и --base")
	}
	cfg.Base = strings.TrimRight(cfg.Base, "/")

	col := NewCollector(cfg)
	col.Load()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go col.Run(ctx)

	app, err := NewApp(cfg, col)
	if err != nil {
		log.Fatal(err)
	}
	srv, err := app.Server()
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	col.Save()
}
