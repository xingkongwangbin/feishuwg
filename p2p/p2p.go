package p2p

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/manager"
	"golang.zx2c4.com/wireguard/windows/utils"
)

type Token struct {
	Server string `json:"server"` //服务端地址
	Aid    string `json:"aid"`    //服务端分配的p2p区域ID
	Cid    string `json:"cid"`    //服务端分配的客户端ID
	CIp    string `json:"cip"`    //服务端分配的客户端IP
	Cn     string `json:"cn"`     //服务端分配的客户端wg网卡名称
}

type P2PSocketParams struct {
	MType  string           `json:"mType"`
	IfInfo P2PInterfaceInfo `json:"ifInfo,omitempty"`
	Peers  []P2PPeerInfo    `json:"peers,omitempty"`
}

type P2PPeerInfo struct {
	Name  string `json:"name,omitempty"`
	PuK   string `json:"puK,omitempty"`
	Ip    string `json:"ip,omitempty"`
	AllIp string `json:"allIp,omitempty"`
	Mode  string `json:"mode,omitempty"` //p2p relay
	IIp   string `json:"IIp,omitempty"`
	On    string `json:"on,omitempty"` //系统名称
	Cp    string `json:"cp,omitempty"` //控制端口
}

type P2PInterfaceInfo struct {
	P2PPeerInfo
	PrK string `json:"prK,omitempty"`
}

type TransmitParams struct {
	Operate        string `json:"operate"`
	EncryptionData string `json:"encryptionData"`
}

type LocalPeer struct {
	Name             string    `json:"name"`
	PublicKey        string    `json:"publicKey"`
	Status           int       `json:"status"`           //状态，1已配置，2已连接，3连接失败，4已删除
	Mode             string    `json:"mode"`             //传输类型，p2p直连，relay中继
	Ip               string    `json:"ip"`               //ip地址
	InnerIp          string    `json:"innerIp"`          //内部ip地址
	ConfigAddTime    time.Time `json:"configAddTime"`    //配置添加时间
	ConfigUpdateTime time.Time `json:"configUpdateTime"` //配置更新时间
	ConfigDelTime    time.Time `json:"configDelTime"`    //配置删除时间
	OsName           string    `json:"osName"`           //系统名称
	ControlPort      string    `json:"controlPort"`      //控制端口
	FailCount        int       `json:"failCount"`        //心跳失败次数
}

func (l *LocalPeer) StatusToStr() string {
	if l.Status == 1 {
		return "已配置"
	} else if l.Status == 2 {
		return "已连接"
	} else if l.Status == 3 {
		return "连接失败"
	} else if l.Status == 4 {
		return "已删除"
	} else {
		return "未知"
	}
}

var (
	closeFunc   func()
	pongWait    = 60 * time.Second
	writeWait   = 10 * time.Second
	pingPeriod  = (pongWait * 8) / 10
	localPeers  = make(map[string]*LocalPeer)
	mux         sync.Mutex
	controlPort = 0

	conn   *websocket.Conn
	tunnel manager.Tunnel
)

func Start(t manager.Tunnel, token Token) error {
	tunnel = t

	runConf, err := tunnel.RuntimeConfig()
	if err != nil {
		return err
	}

	go startWebSocket(token, fmt.Sprintf("%d", runConf.Interface.ListenPort))

	return nil
}

func RegisterCloseFunc(f func()) {
	closeFunc = f
}

func startWebSocket(token Token, port string) {
	defer func() {
		manager.SendLog(fmt.Sprintf("p2p socket关闭: %s", token.Cid))
		if conn != nil {
			conn.Close()
			conn = nil
		}
		if tunnel.IsRunning() {
			time.Sleep(time.Second * 10)
			startWebSocket(token, port)
		}
	}()

	var (
		err    error
		osName = runtime.GOOS
		header = http.Header{}
		u      = url.URL{Scheme: "ws", Host: token.Server, Path: "/p2pWs"}
	)

	header.Add(`p2p-cid`, token.Cid)
	header.Add(`p2p-aid`, token.Aid)
	header.Add(`p2p-pt`, port)
	header.Add(`p2p-on`, osName)
	header.Add(`p2p-cp`, fmt.Sprintf("%d", controlPort))

	manager.SendLog("开始 p2p socket 连接")
	conn, _, err = websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		manager.SendLog(fmt.Sprintf("p2p socket 连接[%s]失败:%s", u.String(), err.Error()))
		return
	}

	go p2pPing()
	go checkPeerNormalStatus()
	go checkTunnelStatus()

	for {
		if conn == nil || !tunnel.IsRunning() {
			manager.SendLog("渠道已关闭,p2p socket 断开连接")
			return
		}

		conn.SetReadDeadline(time.Now().Add(pongWait))
		transmitParams := TransmitParams{}
		err := conn.ReadJSON(&transmitParams)
		if err != nil {
			manager.SendLog(fmt.Sprintf("p2p socket 断开连接 接收server json失败:%s", err))
			if conn != nil {
				conn.Close()
				conn = nil
			}
			break
		}
		//log.Infof(`接收server消息原始数据[%+v]`, transmitParams)
		params, err := decrypt(transmitParams.EncryptionData, utils.DefaultAesKey)
		if err != nil {
			manager.SendLog(fmt.Sprintf("p2p socket 接收server消息再次解密失败:%s", err))
			continue
		}
		str, err := json.Marshal(params)
		if err != nil {
			manager.SendLog(fmt.Sprintf("p2p socket 接收server消息json[%s]", str))
		} else {
			manager.SendLog(fmt.Sprintf("p2p socket 接收server消息[%+v]", params))
		}
		switch params.MType {
		case `peer`:
			handlerPeer(tunnel, params)
		}
	}
}

func handlerPeer(tunnel manager.Tunnel, params *P2PSocketParams) {
	mux.Lock()
	defer mux.Unlock()

	if len(params.IfInfo.PrK) == 0 {
		manager.SendLog("未收到interface信息")
		return
	}

	//本地peer信息
	runCf, err := tunnel.RuntimeConfig()
	if err != nil {
		manager.SendLog(fmt.Sprintf(`获取运行配置失败:%s`, err))
		return
	}

	key, _ := conf.NewPrivateKeyFromString(params.IfInfo.PrK)
	runCf.Interface.PrivateKey = *key

	if selfIp == "" {
		selfIp = params.IfInfo.Ip
	}
	if selfClientName == "" {
		selfClientName = params.IfInfo.Name
	}

	if runCf.Interface.PrivateKey.String() != params.IfInfo.PrK {
		selfIp = params.IfInfo.Ip
		selfClientName = params.IfInfo.Name
	}

	addr, err := conf.ParseIPCidr(params.IfInfo.Ip)
	if err != nil {
		return
	}
	runCf.Interface.Addresses = []netip.Prefix{addr}

	peers := make([]conf.Peer, 0)
	needCheck := false
	for _, rPeer := range params.Peers {
		pky, err := conf.NewPrivateKeyFromString(rPeer.PuK)
		if err != nil {
			manager.SendLog(fmt.Sprintf(`p2p socket ping server 失败:%s`, err.Error()))
			continue
		}

		endpoint := strings.Split(rPeer.Ip, ":")
		if len(endpoint) != 2 {
			continue
		}

		port, err := conf.ParsePort(endpoint[1])
		if err != nil {
			continue
		}

		ip := endpoint[0]
		if ip, err = conf.ResolveHostname(ip); err != nil {
			ip = endpoint[0]
		}

		allIP, err := conf.ParseIPCidr(rPeer.AllIp)
		if err != nil {
			continue
		}

		peer := conf.Peer{
			PublicKey: *pky,
			Endpoint: conf.Endpoint{
				Host: ip,
				Port: port,
			},
			AllowedIPs:          []netip.Prefix{allIP},
			PersistentKeepalive: 15,
		}

		for _, v := range runCf.Peers {
			if v.PublicKey.String() == rPeer.PuK {
				peer.LastHandshakeTime = v.LastHandshakeTime
			}
		}

		peers = append(peers, peer)

		if p, ok := localPeers[rPeer.PuK]; ok {
			if p.Ip != rPeer.Ip {
				p.ConfigUpdateTime = time.Now()
				p.Ip = rPeer.Ip
				p.Mode = rPeer.Mode
				p.Status = 1
				needCheck = true
			}
		} else {
			localPeers[rPeer.PuK] = &LocalPeer{
				Name:          rPeer.Name,
				PublicKey:     rPeer.PuK,
				Status:        1,
				Mode:          rPeer.Mode,
				Ip:            rPeer.Ip,
				InnerIp:       rPeer.IIp,
				ConfigAddTime: time.Now(),
				OsName:        rPeer.On,
				ControlPort:   rPeer.Cp,
			}
			needCheck = true
		}
	}

	for _, p := range localPeers {
		exit := false
		for _, rPeer := range params.Peers {
			if rPeer.PuK == p.PublicKey {
				exit = true
			}
		}
		if !exit {
			p.ConfigDelTime = time.Now()
			p.Status = 4
		}
	}

	runCf.Peers = peers

	if needCheck {
		go checkInitPeerStatus()
	}

	tunnel.SetConfiguration(&runCf)
}

func checkInitPeerStatus() {
	for i := 0; i < 55; i++ {
		if conn == nil || !tunnel.IsRunning() {
			return
		}

		fails := make([]P2PPeerInfo, 0)
		mux.Lock()
		for _, p := range localPeers {
			if p.Status == 1 {
				if err := get(p.InnerIp, p.ControlPort); err != nil {
					p.FailCount = p.FailCount + 1
					if p.FailCount >= 50 {
						//已配置状态失败50次
						p.Status = 3
						p.FailCount = 0
						fails = append(fails, P2PPeerInfo{PuK: p.PublicKey})
						manager.SendLog(fmt.Sprintf("[%s]上报失败", p.InnerIp))
					}
				} else {
					p.Status = 2
					p.FailCount = 0
					manager.SendLog(fmt.Sprintf("[%s]改为连接成功", p.InnerIp))
				}
			}
		}
		mux.Unlock()

		if len(fails) == 0 {
			continue
		}

		if err := sendJsonToMaster(P2PSocketParams{MType: `fails`, Peers: fails}, true); err != nil {
			manager.SendLog(fmt.Sprintf("上送连接失败信息失败: %s", err))
		}

		time.Sleep(time.Second)
	}
}

func checkPeerNormalStatus() {
	ticker := time.NewTicker(time.Second * 60)
	for range ticker.C {
		if conn == nil || !tunnel.IsRunning() {
			return
		}

		fails := make([]P2PPeerInfo, 0)

		mux.Lock()
		for _, peer := range localPeers {
			if peer.Status == 2 {
				if err := get(peer.Ip, peer.ControlPort); err != nil {
					peer.FailCount = peer.FailCount + 1
					if peer.FailCount >= 4 {
						peer.Status = 3
						peer.FailCount = 0
						fails = append(fails, P2PPeerInfo{PuK: peer.PublicKey})
						manager.SendLog(fmt.Sprintf("[%s]上报失败", peer.InnerIp))
					}
				}
			}
		}
		mux.Unlock()

		if len(fails) == 0 {
			continue
		}

		if err := sendJsonToMaster(P2PSocketParams{MType: `fails`, Peers: fails}, true); err != nil {
			manager.SendLog(fmt.Sprintf("上送连接失败信息失败:%s", err.Error()))
		}
	}
}

func checkTunnelStatus() {
	ticker := time.NewTicker(time.Second)
	for range ticker.C {
		if !tunnel.IsRunning() {
			closeFunc()
			if conn != nil {
				conn.Close()
				conn = nil
			}
			ticker.Stop()
			return
		}
	}
}

func p2pPing() {
	ticker := time.NewTicker(pingPeriod)
	for range ticker.C {
		if conn == nil || !tunnel.IsRunning() {
			ticker.Stop()
			return
		}

		if err := sendJsonToMaster(P2PSocketParams{MType: `ping`}, true); err != nil {
			manager.SendLog(fmt.Sprintf(`p2p socket ping server 失败:%s`, err.Error()))
			break
		}
	}
}

func sendJsonToMaster(data P2PSocketParams, logSw bool) error {
	if conn == nil {
		return fmt.Errorf(`与server未建立socket连接`)
	}
	enData, err := encryptionDataByP2p(utils.DefaultAesKey, data)
	if err != nil {
		return err
	}
	conn.SetWriteDeadline(time.Now().Add(writeWait))
	if err := conn.WriteJSON(&enData); err != nil {
		return fmt.Errorf(`发送json失败:%s`, err.Error())
	}
	if logSw {
		manager.SendLog(fmt.Sprintf(`socket 发送json成功,原始数据[%+v]`, data))
	}
	return nil
}

func encryptionDataByP2p(key string, data P2PSocketParams) (interface{}, error) {
	if len(key) != 0 {
		str, err := json.Marshal(data)
		if err != nil {
			manager.SendLog(fmt.Sprintf(`p2p socket 发送json 对象转json失败:%s`, err.Error()))
			return nil, err
		}
		encryptStr, err := utils.AesEncryptByKey(string(str), key)
		if err != nil {
			manager.SendLog(fmt.Sprintf(`p2p socket 发送json 数据加密失败:%s`, err.Error()))
			return nil, err
		}
		return TransmitParams{EncryptionData: encryptStr}, nil
	}
	return data, nil
}

func decrypt(encryptStr, key string) (*P2PSocketParams, error) {
	if len(encryptStr) != 0 {
		jsonStr, err := utils.AesDecryptByKey(encryptStr, key)
		if err != nil {
			manager.SendLog(fmt.Sprintf("p2p socket 解密失败:%s", err))
			return nil, err
		}
		params := P2PSocketParams{}
		err = json.Unmarshal([]byte(jsonStr), &params)
		if err != nil {
			manager.SendLog(fmt.Sprintf("p2p socket 解密后[%s]转json失败:%s", []byte(jsonStr), err))
			return nil, err
		}
		return &params, nil
	}
	return nil, nil
}
