package constants

import "testing"

func TestAASAAppsFallback(t *testing.T) {
	t.Parallel()

	origTeam := TeamID
	origBundle := BundleID
	t.Cleanup(func() {
		TeamID = origTeam
		BundleID = origBundle
	})

	TeamID = ""
	BundleID = ""

	apps := AASAApps()
	if len(apps) != 1 {
		t.Fatalf("expected one app, got %d", len(apps))
	}
	if apps[0] != "QUR8QTGXNB.ch.argio.psso" {
		t.Fatalf("unexpected fallback app %q", apps[0])
	}
}

func TestAASAAppsTrimsValues(t *testing.T) {
	t.Parallel()

	origTeam := TeamID
	origBundle := BundleID
	t.Cleanup(func() {
		TeamID = origTeam
		BundleID = origBundle
	})

	TeamID = "  TEAM  "
	BundleID = "  bundle.id  "

	apps := AASAApps()
	if len(apps) != 1 {
		t.Fatalf("expected one app, got %d", len(apps))
	}
	if apps[0] != "TEAM.bundle.id" {
		t.Fatalf("unexpected app %q", apps[0])
	}
}
