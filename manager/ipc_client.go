/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/updater"
)

var (
	runningTunnelMap = make(map[string]bool)
	tunnelIsP2PMap   = make(map[string]bool)
)

type Tunnel struct {
	Name string
}

type TunnelState int

const (
	TunnelUnknown TunnelState = iota
	TunnelStarted
	TunnelStopped
	TunnelStarting
	TunnelStopping
)

type NotificationType int

const (
	TunnelChangeNotificationType NotificationType = iota
	TunnelsChangeNotificationType
	ManagerStoppingNotificationType
	UpdateFoundNotificationType
	UpdateProgressNotificationType
)

type MethodType int

const (
	StoredConfigMethodType MethodType = iota
	RuntimeConfigMethodType
	StartMethodType
	StopMethodType
	WaitForStopMethodType
	DeleteMethodType
	StateMethodType
	GlobalStateMethodType
	CreateMethodType
	TunnelsMethodType
	QuitMethodType
	UpdateStateMethodType
	UpdateMethodType
	LogMethodType
	SetIPMethodType
	SetConfigurationMethodType
	AddFireWallRuleMethodType
)

var (
	rpcEncoder *gob.Encoder
	rpcDecoder *gob.Decoder
	rpcMutex   sync.Mutex
)

type TunnelChangeCallback struct {
	cb func(tunnel *Tunnel, state, globalState TunnelState, err error)
}

var tunnelChangeCallbacks = make(map[*TunnelChangeCallback]bool)

type TunnelsChangeCallback struct {
	cb func()
}

var tunnelsChangeCallbacks = make(map[*TunnelsChangeCallback]bool)

type ManagerStoppingCallback struct {
	cb func()
}

var managerStoppingCallbacks = make(map[*ManagerStoppingCallback]bool)

type UpdateFoundCallback struct {
	cb func(updateState UpdateState)
}

var updateFoundCallbacks = make(map[*UpdateFoundCallback]bool)

type UpdateProgressCallback struct {
	cb func(dp updater.DownloadProgress)
}

var updateProgressCallbacks = make(map[*UpdateProgressCallback]bool)

func InitializeIPCClient(reader, writer, events *os.File) {
	rpcDecoder = gob.NewDecoder(reader)
	rpcEncoder = gob.NewEncoder(writer)
	go func() {
		decoder := gob.NewDecoder(events)
		for {
			var notificationType NotificationType
			err := decoder.Decode(&notificationType)
			if err != nil {
				return
			}
			switch notificationType {
			case TunnelChangeNotificationType:
				var tunnel string
				err := decoder.Decode(&tunnel)
				if err != nil || len(tunnel) == 0 {
					continue
				}
				var state TunnelState
				err = decoder.Decode(&state)
				if err != nil {
					continue
				}
				var globalState TunnelState
				err = decoder.Decode(&globalState)
				if err != nil {
					continue
				}
				var errStr string
				err = decoder.Decode(&errStr)
				if err != nil {
					continue
				}
				var retErr error
				if len(errStr) > 0 {
					retErr = errors.New(errStr)
				}
				if state == TunnelUnknown {
					continue
				}
				t := &Tunnel{Name: tunnel}
				for cb := range tunnelChangeCallbacks {
					cb.cb(t, state, globalState, retErr)
				}
			case TunnelsChangeNotificationType:
				for cb := range tunnelsChangeCallbacks {
					cb.cb()
				}
			case ManagerStoppingNotificationType:
				for cb := range managerStoppingCallbacks {
					cb.cb()
				}
			case UpdateFoundNotificationType:
				var state UpdateState
				err = decoder.Decode(&state)
				if err != nil {
					continue
				}
				for cb := range updateFoundCallbacks {
					cb.cb(state)
				}
			case UpdateProgressNotificationType:
				var dp updater.DownloadProgress
				err = decoder.Decode(&dp.Activity)
				if err != nil {
					continue
				}
				err = decoder.Decode(&dp.BytesDownloaded)
				if err != nil {
					continue
				}
				err = decoder.Decode(&dp.BytesTotal)
				if err != nil {
					continue
				}
				var errStr string
				err = decoder.Decode(&errStr)
				if err != nil {
					continue
				}
				if len(errStr) > 0 {
					dp.Error = errors.New(errStr)
				}
				err = decoder.Decode(&dp.Complete)
				if err != nil {
					continue
				}
				for cb := range updateProgressCallbacks {
					cb.cb(dp)
				}
			}
		}
	}()
}

func rpcDecodeError() error {
	var str string
	err := rpcDecoder.Decode(&str)
	if err != nil {
		return err
	}
	if len(str) == 0 {
		return nil
	}
	return errors.New(str)
}

func (t *Tunnel) StoredConfig() (c conf.Config, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(StoredConfigMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&c)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func (t *Tunnel) RuntimeConfig() (c conf.Config, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(RuntimeConfigMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&c)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func (t *Tunnel) Start() (err error) {
	runningTunnelMap[t.Name] = true

	cf, err := t.StoredConfig()
	if err != nil {
		return
	}

	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	if err = rpcEncoder.Encode(StartMethodType); err != nil {
		return
	}

	if err = rpcEncoder.Encode(t.Name); err != nil {
		return
	}

	if err = rpcDecodeError(); err != nil {
		return
	}

	if t.IsP2P() {
		return
	}

	hip := make(map[string]string, 0)
	for _, v := range cf.Peers {
		var ip string
		ip, err = conf.ResolveHostname(v.Endpoint.Host)
		if err != nil {
			t.Stop()
			return err
		}

		hip[v.Endpoint.Host] = ip

		if len(hip[v.Endpoint.Host]) == 0 {
			t.Stop()
			if err = SendLog(fmt.Sprintf("解析域名[%s]ip失败", v.Endpoint.Host)); err != nil {
				return
			}

			err = fmt.Errorf("解析域名[%s]ip失败", v.Endpoint.Host)
			return
		}
	}

	go t.ListenIp(t.Name, cf, hip)

	return
}

func (t *Tunnel) Stop() (err error) {
	runningTunnelMap[t.Name] = false

	if t.IsP2P() {
		defer t.Delete()
		delete(tunnelIsP2PMap, t.Name)
	}

	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	if rpcEncoder.Encode(StopMethodType); err != nil {
		return
	}

	if err = rpcEncoder.Encode(t.Name); err != nil {
		return
	}

	err = rpcDecodeError()

	return
}

func (t *Tunnel) Toggle() (oldState TunnelState, err error) {
	oldState, err = t.State()
	if err != nil {
		oldState = TunnelUnknown
		return
	}
	if oldState == TunnelStarted {
		err = t.Stop()
	} else if oldState == TunnelStopped {
		err = t.Start()
	}
	return
}

func (t *Tunnel) ListenIp(name string, cf conf.Config, hip map[string]string) {
	time.Sleep(time.Second * 2)

	var (
		err                error
		host, newIP, oldIP string
	)

	for {
		if !t.IsRunning() {
			return
		}

		for k, v := range cf.Peers {
			newIP, err = conf.ResolveHostname(v.Endpoint.Host)
			if err != nil {
				continue
			}

			if hip[v.Endpoint.Host] != newIP {
				host = v.Endpoint.Host
				oldIP = hip[v.Endpoint.Host]
				cf.Peers[k].Endpoint.Host = newIP

				if err = SendLog(fmt.Sprintf("[%s] host:%s, ip发生改变,原ip为: %s  新ip为: %s", name, host, oldIP, newIP)); err != nil {
					return
				}

				err = t.SetIP(&cf)
				if err != nil {
					SendLog(err.Error())
				}

				hip[v.Endpoint.Host] = newIP
				cf.Peers[k].Endpoint.Host = host
			}
		}

		time.Sleep(time.Second * 60)
	}
}

func (t *Tunnel) WaitForStop() (err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(WaitForStopMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func (t *Tunnel) Delete() (err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(DeleteMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func (t *Tunnel) State() (tunnelState TunnelState, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(StateMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(t.Name)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&tunnelState)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func (t *Tunnel) SetIP(cf *conf.Config) (err error) {
	if err = rpcEncoder.Encode(SetIPMethodType); err != nil {
		return
	}

	if err = rpcEncoder.Encode(cf); err != nil {
		return
	}

	return
}

func (t *Tunnel) SetConfiguration(cf *conf.Config) (err error) {
	if err = rpcEncoder.Encode(SetConfigurationMethodType); err != nil {
		return
	}

	if err = rpcEncoder.Encode(cf); err != nil {
		return
	}

	return
}

func (t *Tunnel) IsRunning() bool {
	if v, ok := runningTunnelMap[t.Name]; ok {
		return v
	}

	return false
}

func (t *Tunnel) IsP2P() bool {
	if v, ok := tunnelIsP2PMap[t.Name]; ok {
		return v
	}

	return false
}

func (t *Tunnel) SetP2P() {
	tunnelIsP2PMap[t.Name] = true
}

func IPCClientGlobalState() (tunnelState TunnelState, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(GlobalStateMethodType)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&tunnelState)
	if err != nil {
		return
	}
	return
}

func IPCClientNewTunnel(conf *conf.Config) (tunnel Tunnel, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(CreateMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(*conf)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&tunnel)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func IPCClientTunnels() (tunnels []Tunnel, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(TunnelsMethodType)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&tunnels)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func IPCClientQuit(stopTunnelsOnQuit bool) (alreadyQuit bool, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(QuitMethodType)
	if err != nil {
		return
	}
	err = rpcEncoder.Encode(stopTunnelsOnQuit)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&alreadyQuit)
	if err != nil {
		return
	}
	err = rpcDecodeError()
	return
}

func IPCClientUpdateState() (updateState UpdateState, err error) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err = rpcEncoder.Encode(UpdateStateMethodType)
	if err != nil {
		return
	}
	err = rpcDecoder.Decode(&updateState)
	if err != nil {
		return
	}
	return
}

func IPCClientUpdate() error {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	return rpcEncoder.Encode(UpdateMethodType)
}

func IPCClientRegisterTunnelChange(cb func(tunnel *Tunnel, state, globalState TunnelState, err error)) *TunnelChangeCallback {
	s := &TunnelChangeCallback{cb}
	tunnelChangeCallbacks[s] = true
	return s
}

func (cb *TunnelChangeCallback) Unregister() {
	delete(tunnelChangeCallbacks, cb)
}

func IPCClientRegisterTunnelsChange(cb func()) *TunnelsChangeCallback {
	s := &TunnelsChangeCallback{cb}
	tunnelsChangeCallbacks[s] = true
	return s
}

func (cb *TunnelsChangeCallback) Unregister() {
	delete(tunnelsChangeCallbacks, cb)
}

func IPCClientRegisterManagerStopping(cb func()) *ManagerStoppingCallback {
	s := &ManagerStoppingCallback{cb}
	managerStoppingCallbacks[s] = true
	return s
}

func (cb *ManagerStoppingCallback) Unregister() {
	delete(managerStoppingCallbacks, cb)
}

func IPCClientRegisterUpdateFound(cb func(updateState UpdateState)) *UpdateFoundCallback {
	s := &UpdateFoundCallback{cb}
	updateFoundCallbacks[s] = true
	return s
}

func (cb *UpdateFoundCallback) Unregister() {
	delete(updateFoundCallbacks, cb)
}

func IPCClientRegisterUpdateProgress(cb func(dp updater.DownloadProgress)) *UpdateProgressCallback {
	s := &UpdateProgressCallback{cb}
	updateProgressCallbacks[s] = true
	return s
}

func (cb *UpdateProgressCallback) Unregister() {
	delete(updateProgressCallbacks, cb)
}

func SendLog(logStr string) (err error) {
	if err = rpcEncoder.Encode(LogMethodType); err != nil {
		return
	}

	if err = rpcEncoder.Encode(logStr); err != nil {
		return
	}

	return
}

func AddFireWallRule(port int) (err error) {
	if err = rpcEncoder.Encode(AddFireWallRuleMethodType); err != nil {
		return
	}

	rule := fmt.Sprintf(`netsh advfirewall firewall add rule name="feishu" dir=in action=allow protocol=TCP localport=%d`, port)

	if err = rpcEncoder.Encode(rule); err != nil {
		return
	}

	return
}
