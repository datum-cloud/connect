package daemonservice

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/kardianos/service"
)

type onboardingService struct {
	service.Service
	status              service.Status
	statusErr, startErr error
	starts              int
}

func (s *onboardingService) Status() (service.Status, error) { return s.status, s.statusErr }
func (s *onboardingService) Start() error                    { s.starts++; return s.startErr }

func TestOnboardingServiceNeverOverwritesExistingConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name                               string
		status                             service.Status
		statusErr                          error
		decline                            bool
		wantInstall, wantStart, wantPrompt int
		wantErr                            bool
	}{
		{"missing accepted", service.StatusUnknown, service.ErrNotInstalled, false, 1, 1, 1, false},
		{"missing declined", service.StatusUnknown, service.ErrNotInstalled, true, 0, 0, 1, true},
		{"stopped", service.StatusStopped, nil, false, 0, 1, 0, false},
		{"running but unreachable", service.StatusRunning, nil, false, 0, 0, 0, true},
		{"unknown", service.StatusUnknown, nil, false, 0, 0, 0, true},
		{"inspection failure", service.StatusUnknown, errors.New("permission denied"), false, 0, 0, 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svc := &onboardingService{status: tt.status, statusErr: tt.statusErr}
			installed, prompts, waited := 0, 0, 0
			err := ensureUserService(context.Background(), svc, io.Discard, func(string) error {
				prompts++
				if tt.decline {
					return errors.New("declined")
				}
				return nil
			}, func() error { installed++; return nil }, func() error { waited++; return nil })
			if (err != nil) != tt.wantErr || installed != tt.wantInstall || svc.starts != tt.wantStart || prompts != tt.wantPrompt || waited != tt.wantStart {
				t.Fatalf("err=%v installed=%d started=%d prompts=%d waited=%d", err, installed, svc.starts, prompts, waited)
			}
		})
	}
}

func TestOnboardingFailuresStopFurtherWork(t *testing.T) {
	for _, stage := range []string{"download", "start", "ready", "cancelled"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			svc := &onboardingService{statusErr: service.ErrNotInstalled}
			if stage == "start" {
				svc.startErr = errors.New("start failed")
			}
			installed, waited := 0, 0
			err := ensureUserService(ctx, svc, io.Discard, func(string) error { return nil }, func() error {
				installed++
				if stage == "download" {
					return errors.New("checksum mismatch")
				}
				if stage == "cancelled" {
					cancel()
				}
				return nil
			}, func() error { waited++; return errors.New("readiness failed") })
			if err == nil || installed != 1 {
				t.Fatalf("err=%v installed=%d", err, installed)
			}
			if (stage == "download" || stage == "cancelled") && svc.starts != 0 {
				t.Fatal("started after installation failure/cancellation")
			}
			if stage != "ready" && waited != 0 {
				t.Fatal("waited after earlier failure")
			}
		})
	}
}
