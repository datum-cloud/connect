package daemonservice

import (
	"encoding/json"
	"errors"
	"github.com/kardianos/service"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHelperCheckErrorExplainsStaleOverlapBehavior(t *testing.T) {
	err := helperCheckError([]byte(`Error: Custom { kind: InvalidInput, error: "helper attachments must not install overlapping routes" }`))
	message := err.Error()
	for _, want := range []string{
		"networking helper is outdated",
		"overlapping route approvals saved for different networks",
		"No approval or active interface was changed",
		"--upgrade-helper --replace-helper-approval --helper-executable PATH",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("error %q does not explain %q", message, want)
		}
	}
}

func TestApprovalsAreAdditiveAndCannotRetarget(t *testing.T) {
	first := InterfaceApproval{InterfaceName: "dcfirst", AssignedAddress: "fd00::1/128", PeerAddress: "fd00::2/128", MTU: 1280}
	second := InterfaceApproval{InterfaceName: "dcsecond", AssignedAddress: "fd01::1/128", PeerAddress: "fd01::2/128", MTU: 1280}
	old := HelperApprovals{AllowedUID: 501, Approvals: []InterfaceApproval{first}}
	merged, _, err := mergeApprovals(old, HelperApprovals{AllowedUID: 501, Approvals: []InterfaceApproval{first, second}}, false)
	if err != nil || len(merged.Approvals) != 2 {
		t.Fatalf("%+v %v", merged, err)
	}
	changed := first
	changed.PeerAddress = "fd00::3/128"
	if _, _, err := mergeApprovals(old, HelperApprovals{AllowedUID: 501, Approvals: []InterfaceApproval{changed}}, false); err == nil {
		t.Fatal("retargeted existing grant")
	}
	if _, _, err := mergeApprovals(old, HelperApprovals{AllowedUID: 502, Approvals: []InterfaceApproval{second}}, false); err == nil {
		t.Fatal("changed approved user")
	}
	if len(old.Approvals) != 1 || !sameApproval(old.Approvals[0], first) {
		t.Fatal("mutated existing approvals")
	}
}

func TestExistingApprovalCannotGainSubnetAccess(t *testing.T) {
	host := InterfaceApproval{InterfaceName: "dcfirst", AssignedAddress: "fd00::1/128", PeerAddress: "fd00::2/128", MTU: 1280}
	subnet := host
	subnet.Routes = []string{"fd20::/64"}
	if _, _, err := mergeApprovals(HelperApprovals{AllowedUID: 501, Approvals: []InterfaceApproval{host}}, HelperApprovals{AllowedUID: 501, Approvals: []InterfaceApproval{subnet}}, false); err == nil {
		t.Fatal("expanded existing host approval")
	}
	merged, changed, err := mergeApprovals(HelperApprovals{AllowedUID: 501, Approvals: []InterfaceApproval{host}}, HelperApprovals{AllowedUID: 501, Approvals: []InterfaceApproval{subnet}}, true)
	if err != nil || !changed || len(merged.Approvals) != 1 || !sameApproval(merged.Approvals[0], subnet) {
		t.Fatalf("explicit replacement failed: merged=%+v changed=%v err=%v", merged, changed, err)
	}
	if !sameApproval(host, HelperApprovals{AllowedUID: 501, Approvals: []InterfaceApproval{host}}.Approvals[0]) {
		t.Fatal("replacement mutated the old approval")
	}
	empty := host
	empty.Routes = []string{}
	if !sameApproval(host, empty) {
		t.Fatal("empty optional prefixes must remain compatible with old host approvals")
	}
}

func TestManagedPolicyInstallsOnceAndCannotSilentlyExpand(t *testing.T) {
	policy := &ManagedPolicy{ClientOnly: true, AddressRanges: []string{"fc00::/7"}, RouteRanges: []string{"fc00::/7"}, MinimumRoutePrefix: 16, MinimumMTU: 1280, MaximumMTU: 1500, InterfacePrefix: "dc", InterfaceBehavior: "ephemeral_exclusive", MaximumActiveAttachments: 8, MaximumRoutesPerAttachment: 32, DenyConnectRouteOverlap: true}
	installed, changed, err := mergeApprovals(HelperApprovals{}, HelperApprovals{AllowedUID: 501, ManagedPolicy: policy}, false)
	if err != nil || changed || !sameManagedPolicy(installed.ManagedPolicy, policy) {
		t.Fatalf("first policy install failed: %+v changed=%v err=%v", installed, changed, err)
	}
	expanded := *policy
	expanded.RouteRanges = []string{"::/1"}
	if _, _, err := mergeApprovals(installed, HelperApprovals{AllowedUID: 501, ManagedPolicy: &expanded}, false); err == nil {
		t.Fatal("silently expanded installed policy")
	}
	if _, _, err := mergeApprovals(HelperApprovals{}, HelperApprovals{AllowedUID: 501, ManagedPolicy: &expanded}, false); err == nil {
		t.Fatal("accepted default-route policy range")
	}
}

func TestPolicyOnlyApprovalSerializesEmptyApprovalList(t *testing.T) {
	policy := &ManagedPolicy{ClientOnly: true, AddressRanges: []string{"fc00::/7"}, RouteRanges: []string{"fc00::/7"}, MinimumRoutePrefix: 16, MinimumMTU: 1280, MaximumMTU: 1500, InterfacePrefix: "dc", InterfaceBehavior: "ephemeral_exclusive", MaximumActiveAttachments: 8, MaximumRoutesPerAttachment: 32, DenyConnectRouteOverlap: true}
	merged, _, err := mergeApprovals(HelperApprovals{}, HelperApprovals{AllowedUID: 501, ManagedPolicy: policy}, false)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(merged)
	if err != nil {
		t.Fatal(err)
	}
	// The helper's serde config rejects null for its approvals Vec.
	if !strings.Contains(string(data), `"approvals":[]`) {
		t.Fatalf("helper config must carry an empty approvals list, got %s", data)
	}
}

type helperTestService struct {
	service.Service
	events []string
	fail   string
}

func (s *helperTestService) call(event string) error {
	s.events = append(s.events, event)
	if s.fail == event {
		return errors.New("failed " + event)
	}
	return nil
}
func (s *helperTestService) Start() error     { return s.call("start") }
func (s *helperTestService) Stop() error      { return s.call("stop") }
func (s *helperTestService) Install() error   { return s.call("install") }
func (s *helperTestService) Uninstall() error { return s.call("uninstall") }

func TestHelperActivationKeepsLiveSessionsAndRollsBackUpgrades(t *testing.T) {
	svc := &helperTestService{}
	if err := activateHelper(svc, true, service.StatusRunning, false, func() error { return nil }, nil); err != nil || len(svc.events) != 0 {
		t.Fatalf("additive change restarted service: %+v %v", svc.events, err)
	}
	for _, failure := range []string{"stop", "uninstall", "install", "start", "receipt"} {
		t.Run(failure, func(t *testing.T) {
			svc := &helperTestService{fail: failure}
			restored := 0
			err := activateHelper(svc, true, service.StatusRunning, true, func() error {
				if failure == "receipt" {
					return errors.New("disk full")
				}
				return nil
			}, func() error { restored++; return nil })
			if err == nil || restored != 1 {
				t.Fatalf("err=%v restored=%d events=%v", err, restored, svc.events)
			}
		})
	}
	svc = &helperTestService{}
	if err := activateHelper(svc, false, service.StatusUnknown, false, func() error { return nil }, nil); err != nil || len(svc.events) != 2 || svc.events[0] != "install" || svc.events[1] != "start" {
		t.Fatalf("%v %v", svc.events, err)
	}
}

func TestHelperSetupRefusesContainers(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("container markers are Linux-only")
	}
	original := containerMarkers
	t.Cleanup(func() { containerMarkers = original })
	dir := t.TempDir()
	containerMarkers = []string{filepath.Join(dir, ".toolboxenv")}
	if err := refuseContainer(); err != nil {
		t.Fatalf("refused without a marker: %v", err)
	}
	if err := os.WriteFile(containerMarkers[0], nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := refuseContainer(); err == nil || !strings.Contains(err.Error(), "from the host") {
		t.Fatalf("container was not refused: %v", err)
	}
}

func TestHelperActivationErrorsNameTheFailedStep(t *testing.T) {
	err := activateHelper(&helperTestService{fail: "start"}, false, service.StatusUnknown, false, func() error { return nil }, nil)
	if err == nil || !strings.Contains(err.Error(), "start helper service") {
		t.Fatalf("error does not name the failed step: %v", err)
	}
}
