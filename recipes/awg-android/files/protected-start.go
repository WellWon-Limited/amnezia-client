/* SPDX-License-Identifier: Apache-2.0 */

package main

// #include <stdlib.h>
// #include <android/log.h>
import "C"

import (
	"errors"
	"math"
	"net"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/ipc"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/unix"
)

const protectedStartTimeout = 5 * time.Second

var errProtectedStartAborted = errors.New("protected start aborted before socket protection")
var errProtectedStartTimeout = errors.New("protected start socket protection timed out")

// protectedBind opens the UDP sockets inside Device.Up, reports that the FDs
// exist, and blocks Open before any receive routine or peer is started. Android
// can therefore VpnService.protect() both FDs and only then release Device.Up.
type protectedBind struct {
	conn.Bind
	ready       chan error
	release     chan struct{}
	cancel      chan struct{}
	releaseOnce sync.Once
	cancelOnce  sync.Once
}

func newProtectedBind(bind conn.Bind) *protectedBind {
	return &protectedBind{
		Bind: bind,
		ready: make(chan error, 1),
		release: make(chan struct{}),
		cancel: make(chan struct{}),
	}
}

func (bind *protectedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	receive, actualPort, err := bind.Bind.Open(port)
	bind.ready <- err
	if err != nil {
		return nil, 0, err
	}
	timer := time.NewTimer(protectedStartTimeout)
	defer timer.Stop()
	select {
	case <-bind.release:
		return receive, actualPort, nil
	case <-bind.cancel:
		_ = bind.Bind.Close()
		return nil, 0, errProtectedStartAborted
	case <-timer.C:
		_ = bind.Bind.Close()
		return nil, 0, errProtectedStartTimeout
	}
}

func (bind *protectedBind) PeekLookAtSocketFd4() (int, error) {
	peek, ok := bind.Bind.(conn.PeekLookAtSocketFd)
	if !ok {
		return -1, errors.New("IPv4 socket FD is unavailable")
	}
	return peek.PeekLookAtSocketFd4()
}

func (bind *protectedBind) PeekLookAtSocketFd6() (int, error) {
	peek, ok := bind.Bind.(conn.PeekLookAtSocketFd)
	if !ok {
		return -1, errors.New("IPv6 socket FD is unavailable")
	}
	return peek.PeekLookAtSocketFd6()
}

func (bind *protectedBind) resume() bool {
	resumed := false
	bind.releaseOnce.Do(func() {
		close(bind.release)
		resumed = true
	})
	return resumed
}

func (bind *protectedBind) abort() {
	bind.cancelOnce.Do(func() { close(bind.cancel) })
}

type protectedTunnelHandle struct {
	device   *device.Device
	uapi     net.Listener
	bind     *protectedBind
	upResult chan error
	mu       sync.Mutex
	state    int
}

const (
	protectedPrepared = iota
	protectedResuming
	protectedActive
	protectedStopped
)

var protectedTunnelHandles = struct {
	sync.Mutex
	handles map[int32]*protectedTunnelHandle
}{handles: make(map[int32]*protectedTunnelHandle)}

func removeProtectedHandle(handle int32) *protectedTunnelHandle {
	protectedTunnelHandles.Lock()
	defer protectedTunnelHandles.Unlock()
	value := protectedTunnelHandles.handles[handle]
	delete(protectedTunnelHandles.handles, handle)
	return value
}

func getProtectedHandle(handle int32) *protectedTunnelHandle {
	protectedTunnelHandles.Lock()
	defer protectedTunnelHandles.Unlock()
	return protectedTunnelHandles.handles[handle]
}

//export awgPrepareProtected
func awgPrepareProtected(interfaceName string, tunFd int32, settings string) int32 {
	tag := cstring("AmneziaWG/" + interfaceName)
	logger := &device.Logger{
		Verbosef: AndroidLogger{level: C.ANDROID_LOG_DEBUG, tag: tag}.Printf,
		Errorf: AndroidLogger{level: C.ANDROID_LOG_ERROR, tag: tag}.Printf,
	}
	tunDevice, name, err := tun.CreateUnmonitoredTUNFromFD(int(tunFd))
	if err != nil {
		_ = unix.Close(int(tunFd))
		logger.Errorf("CreateUnmonitoredTUNFromFD failed")
		return -1
	}
	bind := newProtectedBind(conn.NewStdNetBind())
	dev := device.NewDevice(tunDevice, bind, logger)
	if err = dev.IpcSet(settings); err != nil {
		dev.Close()
		logger.Errorf("IpcSet failed")
		return -1
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()

	var uapi net.Listener
	if uapiFile, openErr := ipc.UAPIOpen(name); openErr == nil {
		if listener, listenErr := ipc.UAPIListen(name, uapiFile); listenErr == nil {
			uapi = listener
			go func() {
				for {
					client, acceptErr := listener.Accept()
					if acceptErr != nil {
						return
					}
					go dev.IpcHandle(client)
				}
			}()
		} else {
			_ = uapiFile.Close()
		}
	}

	protectedTunnelHandles.Lock()
	var id int32
	for id = 0; id < math.MaxInt32; id++ {
		if _, exists := protectedTunnelHandles.handles[id]; !exists {
			break
		}
	}
	if id == math.MaxInt32 {
		protectedTunnelHandles.Unlock()
		if uapi != nil {
			_ = uapi.Close()
		}
		dev.Close()
		return -1
	}
	handle := &protectedTunnelHandle{
		device: dev,
		uapi: uapi,
		bind: bind,
		upResult: make(chan error, 1),
		state: protectedPrepared,
	}
	protectedTunnelHandles.handles[id] = handle
	protectedTunnelHandles.Unlock()

	go func() { handle.upResult <- dev.Up() }()
	timer := time.NewTimer(protectedStartTimeout)
	defer timer.Stop()
	select {
	case openErr := <-bind.ready:
		if openErr == nil {
			return id
		}
	case <-timer.C:
	}
	awgProtectedTurnOff(id)
	return -1
}

//export awgResumeProtected
func awgResumeProtected(id int32) int32 {
	handle := getProtectedHandle(id)
	if handle == nil {
		return -1
	}
	handle.mu.Lock()
	if handle.state != protectedPrepared || !handle.bind.resume() {
		handle.mu.Unlock()
		return -1
	}
	handle.state = protectedResuming
	handle.mu.Unlock()

	timer := time.NewTimer(protectedStartTimeout)
	defer timer.Stop()
	select {
	case err := <-handle.upResult:
		if err == nil {
			handle.mu.Lock()
			handle.state = protectedActive
			handle.mu.Unlock()
			return 0
		}
	case <-timer.C:
	}
	awgProtectedTurnOff(id)
	return -1
}

//export awgProtectedTurnOff
func awgProtectedTurnOff(id int32) {
	handle := removeProtectedHandle(id)
	if handle == nil {
		return
	}
	handle.mu.Lock()
	handle.state = protectedStopped
	handle.mu.Unlock()
	handle.bind.abort()
	if handle.uapi != nil {
		_ = handle.uapi.Close()
	}
	handle.device.Close()
}

//export awgProtectedGetSocketV4
func awgProtectedGetSocketV4(id int32) int32 {
	handle := getProtectedHandle(id)
	if handle == nil {
		return -1
	}
	fd, err := handle.bind.PeekLookAtSocketFd4()
	if err != nil {
		return -1
	}
	return int32(fd)
}

//export awgProtectedGetSocketV6
func awgProtectedGetSocketV6(id int32) int32 {
	handle := getProtectedHandle(id)
	if handle == nil {
		return -1
	}
	fd, err := handle.bind.PeekLookAtSocketFd6()
	if err != nil {
		return -1
	}
	return int32(fd)
}

//export awgProtectedGetConfig
func awgProtectedGetConfig(id int32) *C.char {
	handle := getProtectedHandle(id)
	if handle == nil {
		return nil
	}
	settings, err := handle.device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}
