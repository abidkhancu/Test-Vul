package importer

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

// HostResolver turns a scanner report's free-text "Host/Application"
// column into a real host_id, auto-creating a minimal Host record if
// none matches yet.
//
// This exists because scanner_findings.host_id is what the
// correlation engine's UnresolvedForCorrelation query filters on
// (WHERE host_id IS NOT NULL) — without resolving it during import,
// every imported finding would sit with host_id NULL forever, and
// the correlation engine would never see any of them. Auto-created
// hosts get Environment="" (distinct from a real "prod"/"stg"/"dev"
// classification) specifically so the dashboard/host list can
// distinguish "we've seen this hostname in scanner data" from "this
// host has been registered for SSH verification/patching" — the
// latter additionally requires SSH connection details and a
// credential, set separately through host administration, which
// auto-creation here deliberately does not attempt to guess at.
type HostResolver struct {
	hosts repository.HostRepository

	mu    sync.Mutex
	cache map[string]string // normalized hostname -> host ID, scoped to one import run
}

func NewHostResolver(hosts repository.HostRepository) *HostResolver {
	return &HostResolver{hosts: hosts, cache: make(map[string]string)}
}

// Resolve returns the host ID for hostRaw, creating a minimal Host
// record on first sight of a given hostname. Empty/whitespace-only
// hostRaw resolves to "" (no error) — some scanner exports leave this
// column blank for certain finding types (e.g. web-application scans
// not tied to a specific host), and those findings are intentionally
// left without a host_id rather than resolved to a bogus placeholder
// host.
func (r *HostResolver) Resolve(ctx context.Context, hostRaw string) (string, error) {
	key := strings.ToLower(strings.TrimSpace(hostRaw))
	if key == "" {
		return "", nil
	}

	r.mu.Lock()
	if id, ok := r.cache[key]; ok {
		r.mu.Unlock()
		return id, nil
	}
	r.mu.Unlock()

	// FindByHostnameOrIP first, since re-imports of the same fleet
	// should land on the same host record rather than relying on
	// Upsert's ON CONFLICT every time (cheaper read path, and works
	// even if the existing record has an Environment set that a blind
	// Upsert with Environment="" wouldn't match against, given the
	// (hostname, environment) uniqueness constraint).
	if host, err := r.hosts.FindByHostnameOrIP(ctx, key); err == nil && host != nil {
		r.mu.Lock()
		r.cache[key] = host.ID
		r.mu.Unlock()
		return host.ID, nil
	}

	host := &entity.Host{
		Hostname:    key,
		Environment: "", // unclassified until an administrator sets it explicitly
		Status:      entity.HostStatusUnknown,
	}
	if err := r.hosts.Upsert(ctx, host); err != nil {
		return "", fmt.Errorf("auto-create host %q: %w", key, err)
	}

	r.mu.Lock()
	r.cache[key] = host.ID
	r.mu.Unlock()
	return host.ID, nil
}
