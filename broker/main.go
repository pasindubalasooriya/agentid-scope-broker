// Command broker narrows an agent's standing authority to the authority one
// delegated request actually needs.
//
// It verifies the caller's ThunderID token, derives the minimum scope set for
// the named capability, exchanges the caller's token for one carrying only that
// set, and forwards the call to the specialist agent with the narrowed token.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(log); err != nil {
		log.Error("broker stopped", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, policy, err := LoadConfig()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Telemetry must never stop the broker from brokering. A bad collector
	// address or a resource that will not build degrades to no tracing, the
	// same way Agent Manager's own instrumentation fails open.
	tracer, err := NewTracer(ctx, cfg)
	if err != nil {
		log.Warn("tracing disabled", "error", err)
		tracer = noopTracer{}
	}
	defer func() {
		if err := tracer.Shutdown(context.Background()); err != nil {
			log.Warn("flushing traces failed", "error", err)
		}
	}()

	broker := NewBroker(cfg, policy, log, tracer)

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           broker.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errs := make(chan error, 1)
	go func() {
		log.Info("broker listening",
			"addr", cfg.Addr,
			"thunder", cfg.ThunderBaseURL,
			"specialist", cfg.SpecialistURL,
			"capabilities", len(policy.Capabilities),
			"resource", policy.Resource,
			"tracing", cfg.OTLPEndpoint != "",
		)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}
