// Command tokencrypt is the TokenCrypt daemon and agent CLI.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"tokencrypt/internal/api"
	"tokencrypt/internal/cli"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/daemon"
	"tokencrypt/internal/vault"
)

func main() {
	ctx := context.Background()
	if len(os.Args) > 1 && (os.Args[1] == "serve" || os.Args[1] == "init") {
		report, err := daemon.Harden()
		if err != nil {
			fmt.Fprintln(os.Stderr, "tokencrypt: process hardening failed")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "tokencrypt: dumpable=%d memlock_soft=%d memlock_hard=%d; memory locks are best effort\n", report.Dumpable, report.MemlockSoft, report.MemlockHard)
		var cancel context.CancelFunc
		ctx, cancel = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer cancel()
	}
	os.Exit(runWithInput(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithInput(context.Background(), args, os.Stdin, stdout, stderr)
}

func runWithInput(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "init":
			return initialize(ctx, args[1:], stdin, stdout, stderr)
		case "serve":
			opts, err := parseServe(args[1:])
			if err != nil {
				fmt.Fprintln(stderr, "usage: tokencrypt serve [--vault-dir DIR] [--state-dir DIR] [--socket PATH] [--listen IP:PORT] [--allowed-hosts HOSTS] [--secure-cookies] [--approval-url URL] [--telegram-api-base URL] [--env-file PATH]")
				return 2
			}
			if err := serve(ctx, opts); err != nil {
				fmt.Fprintf(stderr, "tokencrypt: %s\n", err)
				return 1
			}
			return 0
		}
	}
	return cli.Run(args, stdout, stderr, func() (*api.Client, error) {
		socket := os.Getenv("TOKENCRYPT_SOCKET")
		if socket == "" {
			runtime := os.Getenv("XDG_RUNTIME_DIR")
			if runtime == "" {
				return nil, api.ErrSocket
			}
			socket = filepath.Join(runtime, "tokencrypt", "sock")
		}
		return api.Dial(socket)
	})
}

type serveOptions struct {
	daemon.Config
	AllowedHosts, ApprovalURL, TelegramAPIBase, EnvFile string
	SecureCookies                                       bool
}

func paths() (vaultDir, stateDir, socket string) {
	home, _ := os.UserHomeDir()
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" && home != "" {
		data = filepath.Join(home, ".local", "share")
	}
	state := os.Getenv("XDG_STATE_HOME")
	if state == "" && home != "" {
		state = filepath.Join(home, ".local", "state")
	}
	if data != "" {
		vaultDir = filepath.Join(data, "tokencrypt")
	}
	if state != "" {
		stateDir = filepath.Join(state, "tokencrypt")
	}
	socket = os.Getenv("TOKENCRYPT_SOCKET")
	if runtime := os.Getenv("XDG_RUNTIME_DIR"); socket == "" && runtime != "" {
		socket = filepath.Join(runtime, "tokencrypt", "sock")
	}
	return
}

// defaultEnvFile resolves $XDG_CONFIG_HOME/tokencrypt/telegram.env, falling
// back to ~/.config/tokencrypt/telegram.env.
func defaultEnvFile() string {
	config := os.Getenv("XDG_CONFIG_HOME")
	if home, _ := os.UserHomeDir(); config == "" && home != "" {
		config = filepath.Join(home, ".config")
	}
	if config == "" {
		return ""
	}
	return filepath.Join(config, "tokencrypt", "telegram.env")
}

func parseServe(args []string) (serveOptions, error) {
	var opts serveOptions
	vaultDir, stateDir, socket := paths()
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&opts.VaultDir, "vault-dir", vaultDir, "")
	fs.StringVar(&opts.StateDir, "state-dir", stateDir, "")
	fs.StringVar(&opts.SocketPath, "socket", socket, "")
	fs.StringVar(&opts.Listen, "listen", "127.0.0.1:8765", "")
	fs.StringVar(&opts.AllowedHosts, "allowed-hosts", "crypt.local,localhost,127.0.0.1", "")
	fs.BoolVar(&opts.SecureCookies, "secure-cookies", false, "")
	fs.StringVar(&opts.ApprovalURL, "approval-url", "https://crypt.local", "")
	fs.StringVar(&opts.TelegramAPIBase, "telegram-api-base", "", "")
	fs.StringVar(&opts.EnvFile, "env-file", defaultEnvFile(), "")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() != 0 {
		return opts, errors.New("unexpected positional arguments")
	}
	return opts, nil
}

func initialize(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	vaultDir, _, _ := paths()
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&vaultDir, "vault-dir", vaultDir, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || vaultDir == "" {
		fmt.Fprintln(stderr, "usage: tokencrypt init [--vault-dir DIR]")
		return 2
	}
	if file, ok := stdin.(*os.File); ok {
		fd := int(file.Fd())
		original, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err == nil {
			hidden := *original
			hidden.Lflag &^= unix.ECHO | unix.ECHONL
			if err := unix.IoctlSetTermios(fd, unix.TCSETS, &hidden); err != nil {
				fmt.Fprintln(stderr, "tokencrypt: cannot disable terminal echo")
				return 1
			}
			defer func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, original) }()
		}
		stdin = pollReader{ctx: ctx, file: file}
	}
	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	fmt.Fprint(stderr, "Passphrase: ")
	if !scanner.Scan() {
		fmt.Fprintln(stderr, "tokencrypt: cannot read passphrase")
		return 1
	}
	pass := bytes.Clone(scanner.Bytes())
	clear(scanner.Bytes())
	defer clear(pass)
	fmt.Fprint(stderr, "\nConfirm passphrase: ")
	if !scanner.Scan() {
		fmt.Fprintln(stderr, "tokencrypt: cannot read confirmation")
		return 1
	}
	confirmation := bytes.Clone(scanner.Bytes())
	clear(scanner.Bytes())
	defer clear(confirmation)
	fmt.Fprintln(stderr)
	if len(pass) == 0 || !bytes.Equal(pass, confirmation) {
		fmt.Fprintln(stderr, "tokencrypt: passphrases must match and be nonempty")
		return 1
	}
	if err := vault.Init(vaultDir, pass, crypto.DefaultParams()); err != nil {
		fmt.Fprintln(stderr, "tokencrypt: vault initialization failed")
		return 1
	}
	fmt.Fprintln(stdout, "Vault initialized")
	return 0
}

// pollReader lets signal cancellation reach a terminal read so initialize's
// deferred termios restoration runs before the process exits.
type pollReader struct {
	ctx  context.Context
	file *os.File
}

func (r pollReader) Read(p []byte) (int, error) {
	for {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		fds := []unix.PollFd{{Fd: int32(r.file.Fd()), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n > 0 {
			return r.file.Read(p)
		}
	}
}
