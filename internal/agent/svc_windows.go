//go:build windows

package agent

import (
	"context"
	"errors"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// Minimal Windows service integration using only the standard library.

const (
	svcWin32OwnProcess = 0x10

	svcStopped      = 1
	svcStartPending = 2
	svcStopPending  = 3
	svcRunning      = 4

	svcAcceptStop     = 0x1
	svcAcceptShutdown = 0x4

	svcCtlStop        = 1
	svcCtlInterrogate = 4
	svcCtlShutdown    = 5

	errCallNotImplemented   = 120
	errFailedServiceConnect = 1063
)

type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type serviceTableEntry struct {
	Name *uint16
	Proc uintptr
}

var (
	procStartServiceCtrlDispatcher   = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerEx = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus             = advapi32.NewProc("SetServiceStatus")

	svcName   *uint16
	svcRun    func(ctx context.Context)
	svcHandle uintptr
	svcState  atomic.Uint32
	svcCancel context.CancelFunc
	svcMainCb uintptr
	svcCtlCb  uintptr
)

// ErrNotService is returned by RunService when the process was not started by the SCM.
var ErrNotService = errors.New("not started by the service control manager")

// RunService hands the process to the Service Control Manager and runs fn until
// the service is stopped. It blocks until the service has stopped.
func RunService(name string, fn func(ctx context.Context)) error {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	svcName, svcRun = p, fn
	svcMainCb = syscall.NewCallback(svcServiceMain)
	svcCtlCb = syscall.NewCallback(svcCtlHandler)
	table := [2]serviceTableEntry{{Name: p, Proc: svcMainCb}, {}}
	r, _, e := procStartServiceCtrlDispatcher.Call(uintptr(unsafe.Pointer(&table[0])))
	if r == 0 {
		if en, ok := e.(syscall.Errno); ok && en == errFailedServiceConnect {
			return ErrNotService
		}
		return e
	}
	return nil
}

func setSvcStatus(state, accepted, waitHint, checkpoint uint32) {
	svcState.Store(state)
	st := serviceStatus{ServiceType: svcWin32OwnProcess, CurrentState: state, ControlsAccepted: accepted,
		WaitHint: waitHint, CheckPoint: checkpoint}
	procSetServiceStatus.Call(svcHandle, uintptr(unsafe.Pointer(&st)))
}

// svcServiceMain is called by the SCM on its own thread (ServiceMain).
func svcServiceMain(argc, argv uintptr) uintptr {
	h, _, _ := procRegisterServiceCtrlHandlerEx.Call(uintptr(unsafe.Pointer(svcName)), svcCtlCb, 0)
	if h == 0 {
		return 0
	}
	svcHandle = h
	setSvcStatus(svcStartPending, 0, 10000, 1)
	ctx, cancel := context.WithCancel(context.Background())
	svcCancel = cancel
	done := make(chan struct{})
	go func() {
		defer close(done)
		svcRun(ctx)
	}()
	setSvcStatus(svcRunning, svcAcceptStop|svcAcceptShutdown, 0, 0)
	<-done
	setSvcStatus(svcStopped, 0, 0, 0)
	return 0
}

// svcCtlHandler receives control requests (HandlerEx).
func svcCtlHandler(ctl, eventType, eventData, ctxArg uintptr) uintptr {
	switch ctl {
	case svcCtlStop, svcCtlShutdown:
		setSvcStatus(svcStopPending, 0, 15000, 1)
		if svcCancel != nil {
			svcCancel()
		}
		return 0
	case svcCtlInterrogate:
		acc := uint32(0)
		if svcState.Load() == svcRunning {
			acc = svcAcceptStop | svcAcceptShutdown
		}
		setSvcStatus(svcState.Load(), acc, 0, 0)
		return 0
	}
	return errCallNotImplemented
}
