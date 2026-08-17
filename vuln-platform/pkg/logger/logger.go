// Package logger configures zerolog for structured JSON logging,
// consistent across all components (import, correlation, SSH
// verification, patch execution, audit).
package logger

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// New builds a base logger. level accepts zerolog level names
// (debug, info, warn, error); env "dev" enables human-readable
// console output, anything else emits structured JSON suitable for
// shipping to Loki/ELK.
//
// BUG THIS FUNCTION USED TO HAVE, for anyone touching this again:
// zerolog.ParseLevel("") returns (zerolog.NoLevel, nil) — no error —
// so checking only `err != nil` to decide whether to fall back to
// InfoLevel let an unset/empty VULN_LOG_LEVEL silently set the
// *global* level to NoLevel. zerolog.SetGlobalLevel(NoLevel)
// suppresses every log line at every level, Fatal included — so the
// application would exit(1) on any startup failure (e.g. can't reach
// Postgres) with zero output anywhere, making the failure look like
// a silent crash instead of a logged, diagnosable error. Caught by
// actually running the compiled binary against a real startup
// failure, not by any static check — the lesson being that "no
// error returned" and "the fallback default we wanted" are not the
// same thing, and it's worth checking the actual returned value too.
func New(env, level string) zerolog.Logger {
	zerolog.TimeFieldFormat = time.RFC3339Nano

	lvl, err := zerolog.ParseLevel(strings.ToLower(level))
	if err != nil || lvl == zerolog.NoLevel {
		lvl = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(lvl)

	var out zerolog.ConsoleWriter
	if strings.EqualFold(env, "dev") {
		out = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
		return zerolog.New(out).With().Timestamp().Caller().Logger()
	}

	return zerolog.New(os.Stdout).With().Timestamp().Logger()
}
