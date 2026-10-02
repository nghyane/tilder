// Command tilder runs on each machine: shells served over WebRTC to the
// owner's devices, introduced by a rendezvous (docs/v2/ARCHITECTURE.md).
//
//	TILDER_JOIN=tilder1_… tilder join <server-url>   # once, as the console's command runs it
//	tilder                                      # every start after that
//	tilder service install|uninstall|status     # run it as your own service (ADR 0016)
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/nghyane/tilder/go/internal/agent/files"
	"github.com/nghyane/tilder/go/internal/agent/fschan"
	"github.com/nghyane/tilder/go/internal/agent/hostinfo"
	"github.com/nghyane/tilder/go/internal/agent/link"
	"github.com/nghyane/tilder/go/internal/agent/ptychan"
	"github.com/nghyane/tilder/go/internal/agent/rtc"
	"github.com/nghyane/tilder/go/internal/agent/state"
	"github.com/nghyane/tilder/go/internal/agent/transfer"
	"github.com/nghyane/tilder/go/internal/agent/xferchan"
	"github.com/nghyane/tilder/go/internal/clock"
	"github.com/nghyane/tilder/go/internal/holder"
	"github.com/nghyane/tilder/go/internal/identity"
	"github.com/nghyane/tilder/go/internal/service"
	"github.com/nghyane/tilder/go/internal/update"
)

// version is set at release (-ldflags "-X main.version=…"); a local build
// reports "dev".
var version = "dev"

// releaseRoot is the release root's public key (ADR 0023), set at release
// (-ldflags "-X main.releaseRoot=…"). A build without it never updates itself.
var releaseRoot string

func main() {
	// The join token is read once, then gone from this process's
	// environment, so no shell or helper the agent starts inherits it.
	joinToken := os.Getenv("TILDER_JOIN")
	_ = os.Unsetenv("TILDER_JOIN")
	if err := run(os.Args[1:], joinToken); err != nil {
		if errors.Is(err, errNoServiceManager) {
			os.Exit(3)
		}
		if errors.Is(err, errRestart) {
			fmt.Fprintln(os.Stderr, "tilder:", err)
			os.Exit(restartExit)
		}
		fmt.Fprintln(os.Stderr, "tilder:", err)
		os.Exit(1)
	}
}

func run(args []string, joinToken string) error {
	home, err := homeDir()
	if err != nil {
		return err
	}
	if len(args) > 0 && args[0] == "hold" {
		return hold(args[1:])
	}
	if len(args) > 0 && args[0] == "service" {
		return runService(home, args[1:])
	}
	if len(args) > 0 && args[0] == "join" {
		asService, err := join(home, args[1:], joinToken)
		if err != nil {
			return err
		}
		if asService {
			return startService(home)
		}
		// join only records: the install script runs it before anything is
		// installed and waits for it, so it must return, never serve.
		fmt.Println("joined; start the agent with `tilder` or `tilder service install`")
		return nil
	}
	return serve(home)
}

// join records how to reach the owner, from the token in the command the
// console printed (ADR 0020). The owner key comes from that token — which
// the owner pasted — never from the server (PROTOCOL §2.1). The token rides
// in the environment, not the command line, which every user on the
// machine can read. With --service the agent is then installed as the
// owner's service (ADR 0016) rather than run here.
func join(home string, args []string, token string) (asService bool, err error) {
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	asSvc := fs.Bool("service", false, "install as a service that starts at login, instead of running here")
	if len(args) == 0 {
		return false, errors.New("usage: TILDER_JOIN=tilder1_… tilder join <server-url> [--service]")
	}
	server, err := rendezvousURL(args[0])
	if err != nil {
		return false, err
	}
	if err = fs.Parse(args[1:]); err != nil {
		return false, err
	}
	if token == "" {
		return false, errors.New("join needs TILDER_JOIN: run the command from Add machine in the console")
	}
	tok, err := identity.ParseJoinToken(token)
	if err != nil {
		return false, errors.New("the join token is cut short or mistyped: copy the command from the console again")
	}
	// The home must be this agent's before anything is written or a service
	// installed: another install's files there (tilder v1 kept its key in
	// ~/.tilder too) would make the service fail at every start while the
	// console waits for a machine that never comes.
	if _, err := state.MachineKey(home); err != nil {
		return false, fmt.Errorf("%s holds another tilder install's files (%w): remove that install first, or set TILDER_HOME to another directory", home, err)
	}
	cfg := state.Config{Server: server, Owner: tok.Root.String(), JoinSecret: base64.RawURLEncoding.EncodeToString(tok.Secret[:])}
	return *asSvc, state.SaveConfig(home, cfg)
}

// rendezvousURL is the WebSocket the agent dials, from the server's address
// as the command gives it (https://tilder.example) or the socket itself.
func rendezvousURL(server string) (string, error) {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%q is not a server address like https://tilder.example", server)
	}
	switch u.Scheme {
	case "https", "wss":
		u.Scheme = "wss"
	case "http", "ws":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("%q is not a server address like https://tilder.example", server)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/ws"
	}
	return u.String(), nil
}

// errNoServiceManager exits 3: the install script then starts the agent in
// the background instead (a container, an SSH session to a Mac).
var errNoServiceManager = errors.New("no service manager")

// startService installs and starts the joined agent as a service.
func startService(home string) error { return runService(home, []string{"install"}) }

func serve(home string) error {
	runtime.GOMAXPROCS(procsFor(runtime.GOMAXPROCS(0), os.Getenv("GOMAXPROCS")))
	if binary, err := thisBinary(); err == nil {
		update.CleanOld(binary)
		if back, uerr := update.Started(home, version, binary, maxUnprovenStarts); back {
			// The service manager starts the previous release in our place.
			return fmt.Errorf("release %s failed to start %d times; went back to the previous one: %w", version, maxUnprovenStarts, uerr)
		}
	}
	cfg, err := state.LoadConfig(home)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("not joined yet: run the `tilder join …` command the console shows")
	}
	if err != nil {
		return err
	}
	owner, err := cfg.OwnerKey()
	if err != nil {
		return err
	}
	key, err := state.MachineKey(home)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	provedUpdate, rolledBack := watchUpdate(home, clock.Real(), log)
	defer stop()

	// Each shell lives in its own holder process (ADR 0005): stopping or
	// crashing the agent leaves them running, and the next agent finds them.
	runDir := holder.RunDir(home)
	// systemd sets INVOCATION_ID for the processes of a unit.
	shells := holder.NewHolders(runDir, holder.ExecSpawner(runDir, os.Getenv("INVOCATION_ID") != ""), clock.Real())
	defer shells.Close()
	// The owner's files (ADR 0022): the user's home, never the agent's own directory.
	userHome, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	tree := files.New(userHome, home, clock.Real())
	sizes := ptychan.NewSizes() // one per agent: every client of a shell counts (ADR 0033)
	// Copies from the owner's other machines (ADR 0035); reaching them needs
	// the link, set below.
	copies := &transfer.Manager{Tree: tree, Home: home, Clock: clock.Real(), Log: log}
	endpoint := rtc.New(rtc.Options{ICEServers: iceServers()}, func(ctx context.Context, peer rtc.Peer, label string, ch io.ReadWriteCloser) {
		switch channelFor(peer, label) {
		case "pty":
			_ = ptychan.Serve(ctx, ch, shells, tree.DirPath, &ptychan.Where{Cwd: holder.WorkingDir, Home: userHome, Clock: clock.Real()}, sizes)
		case "fs":
			_ = fschan.Serve(ctx, ch, tree, clock.Real())
		case "xfer":
			_ = xferchan.Serve(ctx, ch, tree, *peer.Transfer)
		case "xfer-lan":
			serveLAN(ctx, peer, ch, tree)
		case "xfer-ctl":
			_ = transfer.ServeCtl(ctx, ch, copies)
		default:
			_ = ch.Close() // not for this peer, or a kind this build does not serve
		}
	})
	defer endpoint.Close()

	var secret []byte
	if cfg.JoinSecret != "" {
		secret, _ = base64.RawURLEncoding.DecodeString(cfg.JoinSecret)
	}
	hostname, _ := os.Hostname()
	clk := clock.Real()
	l := &link.Link{
		Server: cfg.Server, Key: key, Owner: owner, Hostname: hostname, Host: hostinfo.Gather(version),
		Answerer: endpoint, Clock: clk, Log: log, JoinSecret: secret,
		// The owner's removed devices (ADR 0004): kept across restarts, and
		// their live connections cut the moment the list arrives.
		Revocations: state.Revocations{Home: home},
		OnConnected: func() {
			if err := state.MarkConnected(home, clk.Now()); err != nil {
				log.Warn("could not record the connection", slog.Any("error", err))
			}
			provedUpdate()
		},
		OnRevoked: func(devices []identity.DevicePublic) {
			for _, d := range devices {
				endpoint.ClosePeer(link.PeerName(d))
			}
			copies.Revoked(devices)
		},
		OnJoined: func() {
			cfg.JoinSecret = "" // spent: never reopen a door with it
			if err := state.SaveConfig(home, cfg); err != nil {
				log.Error("could not erase the used join token", slog.Any("error", err))
			}
		},
	}
	updated := make(chan string, 1)
	asks := make(chan updateAsk)
	l.OnUpdateNow = askUpdate(asks)
	go autoUpdate(ctx, cfg.Server, home, clk, log, asks, updated)
	runErr := make(chan error, 1)
	startCopies(ctx, l, copies, dialSource(endpoint, l))
	defer copies.Close()
	go func() { runErr <- l.Run(ctx) }()
	select {
	case err := <-runErr:
		return err
	case v := <-updated:
		log.Info("updated; restarting into the new release", slog.String("version", v))
		stop()
		<-runErr
		return restart()
	case <-rolledBack:
		log.Info("restarting into the previous release")
		stop()
		<-runErr
		return restart()
	}
}

// hold is the holder process the agent spawns for one shell (ADR 0005).
func hold(args []string) error {
	fs := flag.NewFlagSet("hold", flag.ContinueOnError)
	runDir := fs.String("run", "", "the holder socket directory")
	id := fs.String("id", "", "the shell id")
	cols := fs.Uint("cols", 80, "columns")
	rows := fs.Uint("rows", 24, "rows")
	dir := fs.String("dir", "", "where the shell starts: a real directory the agent resolved (ADR 0024)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *runDir == "" || *id == "" {
		return errors.New("usage: tilder hold --run <dir> --id <shell> [--cols n --rows n --dir path]")
	}
	cfg := shellConfig()
	if *dir != "" {
		if !filepath.IsAbs(*dir) {
			return errors.New("hold: --dir must be an absolute path")
		}
		cfg.Dir = *dir
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	// Caught, not ignored: an ignored signal stays ignored across exec, so the
	// shell and its jobs would inherit a SIGHUP they cannot receive (dtach and
	// abduco ignore it only after the fork; Go resets handled signals at exec).
	signal.Notify(make(chan os.Signal, 1), syscall.SIGHUP)
	return holder.RunHolder(ctx, cfg, *runDir, *id, uint16(min(*cols, 1000)), uint16(min(*rows, 1000))) //nolint:gosec // G115: clamped
}

// runService installs, removes or reports the agent as the owner's own
// service (ADR 0016). The service runs this very binary with this TILDER_HOME.
func runService(home string, args []string) error {
	const usage = "usage: tilder service install|uninstall|status|run [--name agent]"
	if len(args) == 0 {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	name := fs.String("name", "agent", "tells installs apart (a demo beside the real one)")
	runHome := fs.String("home", "", "the agent's home (run: the Windows monitor is told it, having no TILDER_HOME)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	user, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if *runHome != "" {
		home = *runHome
	}
	absHome, err := filepath.Abs(home)
	if err != nil {
		return err
	}
	// A service starts with none of the login environment: bake in what the
	// agent and its shells need.
	env := map[string]string{"TILDER_HOME": absHome, "PATH": envOr("PATH", "/usr/local/bin:/usr/bin:/bin"), "SHELL": envOr("SHELL", "/bin/sh")}
	if runtime.GOOS == "windows" {
		// Started at sign-in, the Windows monitor has the login environment:
		// only which agent it runs is baked in.
		env = map[string]string{"TILDER_HOME": absHome}
	}
	for _, k := range []string{"LANG", "LC_ALL", "TILDER_STUN"} {
		if v := os.Getenv(k); v != "" {
			env[k] = v
		}
	}
	m := service.Manager{
		Spec: service.Spec{Name: *name, Binary: self, Env: env, Home: user, UID: os.Getuid()},
		OS:   runtime.GOOS, Run: service.ExecRunner, Clock: clock.Real(),
	}
	ctx := context.Background()
	switch args[0] {
	case "install":
		note, installErr := m.Install(ctx)
		if installErr != nil {
			// Exit 3: the install script then runs the agent in the
			// background instead (a container, an SSH session to a Mac).
			fmt.Fprintln(os.Stderr, "tilder: could not install the service:", installErr)
			return errNoServiceManager
		}
		fmt.Println("installed; it starts at login and comes back if it stops")
		if note != "" {
			fmt.Println(note)
		}
	case "uninstall":
		if uninstallErr := m.Uninstall(ctx); uninstallErr != nil {
			return uninstallErr
		}
		fmt.Println("uninstalled; shells already running are left alone")
		return nil
	case "status":
	case "run":
		return m.Monitor(ctx, os.Getenv(service.HiddenEnv) != "")
	default:
		return errors.New(usage)
	}
	status, err := m.Status(ctx)
	if err != nil {
		return err
	}
	fmt.Println(status)
	return nil
}
