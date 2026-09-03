package signals

import (
	"errors"
	"os"
	"testing"
	"time"
)

type recordingProcess struct {
	signals   []os.Signal
	killCount int
	onSignal  func()
	onKill    func()
	signalErr error
	killErr   error
}

func (p *recordingProcess) Signal(signal os.Signal) error {
	p.signals = append(p.signals, signal)
	if p.signalErr != nil {
		return p.signalErr
	}
	if p.onSignal != nil {
		p.onSignal()
	}
	return nil
}

func TestForwardFallsBackToKillWhenSignalDeliveryFails(t *testing.T) {
	childExited := make(chan struct{})
	process := &recordingProcess{
		signalErr: errors.New("signal unsupported"),
		onKill:    func() { close(childExited) },
	}
	signals := make(chan os.Signal, 1)
	signals <- os.Interrupt

	if err := forward(process, childExited, time.Millisecond, signals); err != nil {
		t.Fatalf("forward returned an error: %v", err)
	}
	if process.killCount != 1 {
		t.Fatalf("kill count = %d, want 1", process.killCount)
	}
}

func (p *recordingProcess) Kill() error {
	p.killCount++
	if p.onKill != nil {
		p.onKill()
	}
	return p.killErr
}

func TestForwardReturnsKillFailureWithoutWaitingForChildExit(t *testing.T) {
	wantErr := errors.New("kill denied")
	process := &recordingProcess{killErr: wantErr}
	signals := make(chan os.Signal, 1)
	signals <- os.Interrupt

	err := forward(process, make(chan struct{}), time.Millisecond, signals)
	if !errors.Is(err, wantErr) {
		t.Fatalf("forward error = %v, want %v", err, wantErr)
	}
	if process.killCount != 1 {
		t.Fatalf("kill count = %d, want 1", process.killCount)
	}
}

func TestForwardTreatsAlreadyExitedChildAsSuccessfulKill(t *testing.T) {
	childExited := make(chan struct{})
	process := &recordingProcess{
		killErr: os.ErrProcessDone,
		onKill:  func() { close(childExited) },
	}
	signals := make(chan os.Signal, 1)
	signals <- os.Interrupt

	if err := forward(process, childExited, time.Millisecond, signals); err != nil {
		t.Fatalf("forward returned an error for an exited child: %v", err)
	}
	if process.killCount != 1 {
		t.Fatalf("kill count = %d, want 1", process.killCount)
	}
}

func TestForwardReturnsWhenCallerReportsChildExit(t *testing.T) {
	childExited := make(chan struct{})
	close(childExited)
	process := &recordingProcess{}

	if err := forward(process, childExited, time.Hour, make(chan os.Signal)); err != nil {
		t.Fatalf("forward returned an error: %v", err)
	}
	if len(process.signals) != 0 || process.killCount != 0 {
		t.Fatalf("touched exited child: signals=%v kills=%d", process.signals, process.killCount)
	}
}

func TestForwardAllowsGracefulExit(t *testing.T) {
	childExited := make(chan struct{})
	process := &recordingProcess{onSignal: func() { close(childExited) }}
	signals := make(chan os.Signal, 1)
	signals <- os.Interrupt

	if err := forward(process, childExited, time.Hour, signals); err != nil {
		t.Fatalf("forward returned an error: %v", err)
	}
	if len(process.signals) != 1 || process.signals[0] != os.Interrupt {
		t.Fatalf("forwarded signals = %v, want [%v]", process.signals, os.Interrupt)
	}
	if process.killCount != 0 {
		t.Fatalf("kill count = %d, want 0", process.killCount)
	}
}

func TestForwardKillsChildAfterGracePeriod(t *testing.T) {
	childExited := make(chan struct{})
	process := &recordingProcess{onKill: func() { close(childExited) }}
	signals := make(chan os.Signal, 1)
	signals <- os.Interrupt

	if err := forward(process, childExited, time.Millisecond, signals); err != nil {
		t.Fatalf("forward returned an error: %v", err)
	}
	if len(process.signals) != 1 || process.signals[0] != os.Interrupt {
		t.Fatalf("forwarded signals = %v, want [%v]", process.signals, os.Interrupt)
	}
	if process.killCount != 1 {
		t.Fatalf("kill count = %d, want 1", process.killCount)
	}
}
