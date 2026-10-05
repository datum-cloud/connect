package daemonservice

import (
	"errors"
	"github.com/kardianos/service"
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
	old := HelperApprovals{501, []InterfaceApproval{first}}
	merged, _, err := mergeApprovals(old, HelperApprovals{501, []InterfaceApproval{first, second}}, false)
	if err != nil || len(merged.Approvals) != 2 {
		t.Fatalf("%+v %v", merged, err)
	}
	changed := first
	changed.PeerAddress = "fd00::3/128"
	if _, _, err := mergeApprovals(old, HelperApprovals{501, []InterfaceApproval{changed}}, false); err == nil {
		t.Fatal("retargeted existing grant")
	}
	if _, _, err := mergeApprovals(old, HelperApprovals{502, []InterfaceApproval{second}}, false); err == nil {
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
	if _, _, err := mergeApprovals(HelperApprovals{501, []InterfaceApproval{host}}, HelperApprovals{501, []InterfaceApproval{subnet}}, false); err == nil {
		t.Fatal("expanded existing host approval")
	}
	merged, changed, err := mergeApprovals(HelperApprovals{501, []InterfaceApproval{host}}, HelperApprovals{501, []InterfaceApproval{subnet}}, true)
	if err != nil || !changed || len(merged.Approvals) != 1 || !sameApproval(merged.Approvals[0], subnet) {
		t.Fatalf("explicit replacement failed: merged=%+v changed=%v err=%v", merged, changed, err)
	}
	if !sameApproval(host, HelperApprovals{501, []InterfaceApproval{host}}.Approvals[0]) {
		t.Fatal("replacement mutated the old approval")
	}
	empty := host
	empty.Routes = []string{}
	if !sameApproval(host, empty) {
		t.Fatal("empty optional prefixes must remain compatible with old host approvals")
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
