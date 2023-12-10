package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/manager"
	"golang.zx2c4.com/wireguard/windows/utils"
	"gvisor.dev/gvisor/pkg/log"
)

type Token struct {
	Server string `json:"server"` //服务端地址
	Aid    string `json:"aid"`    //服务端分配的p2p区域ID
	Cid    string `json:"cid"`    //服务端分配的客户端ID
	CIp    string `json:"cip"`    //服务端分配的客户端IP
}

type P2PPage struct {
	*walk.TabPage
	p2pContainer  walk.Container
	tokenTextEdit *walk.TextEdit
	openButton    *walk.PushButton
	closeButton   *walk.PushButton

	tunnel manager.Tunnel
}

type LocalPeer struct {
	Name             string    `json:"name"`
	PublicKey        string    `json:"publicKey"`
	Status           int       `json:"status"`           //状态，1已配置，2已连接，3连接失败，4已删除
	Mode             string    `json:"mode"`             //传输类型，p2p直连，relay中继
	Ip               string    `json:"ip"`               //ip地址
	ConfigAddTime    time.Time `json:"configAddTime"`    //配置添加时间
	ConfigUpdateTime time.Time `json:"configUpdateTime"` //配置更新时间
	ConfigDelTime    time.Time `json:"configDelTime"`    //配置删除时间
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
}

type P2PInterfaceInfo struct {
	P2PPeerInfo
	PrK string `json:"prK,omitempty"`
}

type TransmitParams struct {
	Operate        string `json:"operate"`
	EncryptionData string `json:"encryptionData"`
}

var (
	wgName              string
	token               Token
	serverConn          *websocket.Conn
	pongWait            = 60 * time.Second
	writeWait           = 10 * time.Second
	pingPeriod          = (pongWait * 8) / 10
	LocalPeers          = make(map[string]*LocalPeer)
	interfacePrivateKey = ""
)

func NewP2PPage() (*P2PPage, error) {
	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	p2p := new(P2PPage)
	if p2p.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}
	disposables.Add(p2p)

	p2p.SetTitle("P2P打洞")
	p2p.SetLayout(walk.NewVBoxLayout())

	if err = p2p.NewP2PView(); err != nil {
		return nil, err
	}

	disposables.Spare()

	return p2p, nil
}

func (p2p *P2PPage) NewP2PView() error {
	p2p.p2pContainer, _ = walk.NewComposite(p2p)
	vlayout := walk.NewVBoxLayout()
	vlayout.SetSpacing(5)
	p2p.p2pContainer.SetLayout(vlayout)

	titleLabel, err := walk.NewTextLabel(p2p.p2pContainer)
	if err != nil {
		return err
	}

	titleLabel.SetText("Token:")

	if p2p.tokenTextEdit, err = walk.NewTextEdit(p2p.p2pContainer); err != nil {
		return err
	}

	p2p.tokenTextEdit.SetText("u3vs9AxkjTvi2bRSNWAmjv1V4cyh8m3ep/CNjDHQWck0r68ixlXFtuff3/OTvzwQRLc3RSrhd56RirbqHmD/HcXGaE+bnODUhH9Kw3uItsCxAKANwv50pwTsT5f/NthDJORrR9UEWWW/JjrZ+A/Of8AdlZe1oH+zHUSLMLPIt1k=")

	if p2p.openButton, err = walk.NewPushButton(p2p.p2pContainer); err != nil {
		return err
	}

	p2p.openButton.SetText("开始打洞")
	p2p.openButton.Clicked().Attach(p2p.onOpenClicked)

	if p2p.closeButton, err = walk.NewPushButton(p2p.p2pContainer); err != nil {
		return err
	}

	p2p.closeButton.SetText("停止打洞")
	p2p.closeButton.SetEnabled(false)
	p2p.closeButton.Clicked().Attach(p2p.onCloseClicked)

	return nil
}

func (p2p *P2PPage) onOpenClicked() {
	tokenText := strings.TrimSpace(p2p.tokenTextEdit.Text())
	if tokenText == "" {
		walk.MsgBox(p2p.Form(), "错误", "Token不能为空!", walk.MsgBoxIconError)
		return
	}

	tokenJsonStr, err := utils.AesDecrypt(tokenText)
	if err != nil {
		walk.MsgBox(p2p.Form(), "错误", "Token解析失败!", walk.MsgBoxIconError)
		return
	}

	err = json.Unmarshal([]byte(tokenJsonStr), &token)
	if err != nil {
		walk.MsgBox(p2p.Form(), "错误", "Token格式错误!", walk.MsgBoxIconError)
		return
	}

	if len(token.Server) == 0 {
		walk.MsgBox(p2p.Form(), "错误", "服务端地址为空!", walk.MsgBoxIconError)
		return
	}
	if len(token.CIp) == 0 {
		walk.MsgBox(p2p.Form(), "错误", "客户端IP为空!", walk.MsgBoxIconError)
		return
	}

	p2p.openButton.SetEnabled(false)
	p2p.tokenTextEdit.SetReadOnly(true)
	p2p.openButton.SetText("打洞中...")
	p2p.closeButton.SetEnabled(true)

	wgName = `fsP2P_` + uuid.New().String()[:8]
	p2p.tunnel, err = manager.IPCClientNewTunnel(&conf.Config{Name: wgName})
	p2p.tunnel.P2POpening = true
	if err != nil {
		walk.MsgBox(p2p.Form(), "错误", "获取配置失败: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	go func() {
		err = p2p.tunnel.Start()
		if err != nil {
			walk.MsgBox(p2p.Form(), "错误", "启动渠道失败: "+err.Error(), walk.MsgBoxIconError)
			return
		}

		time.Sleep(time.Second * 2)

		runConf, err := p2p.tunnel.RuntimeConfig()
		if err != nil {
			walk.MsgBox(p2p.Form(), "错误", "获取配置失败: "+err.Error(), walk.MsgBoxIconError)
			return
		}

		go p2p.checkPeerStatus()
		go p2p.startWs(fmt.Sprintf("%d", runConf.Interface.ListenPort))
	}()
}

func (p2p *P2PPage) onCloseClicked() {
	p2p.openButton.SetEnabled(true)
	p2p.closeButton.SetEnabled(false)
	p2p.tokenTextEdit.SetReadOnly(false)
	p2p.openButton.SetText("打洞")
	p2p.tunnel.P2POpening = false

	p2p.tunnel.Stop()
	p2p.tunnel.Delete()
}

func (p2p *P2PPage) startWs(port string) {
	u := url.URL{Scheme: "ws", Host: token.Server, Path: "/p2pWs"}
	log.Infof("p2p socket 尝试连接:%s", u.String())
	header := http.Header{}
	header.Add(`p2p-cid`, token.Cid)
	header.Add(`p2p-aid`, token.Aid)
	header.Add(`p2p-pt`, port)
	c, _, err := websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		manager.SendLog(fmt.Sprintf("p2p socket 连接[%s]失败:%s", u.String(), err.Error()))
		time.Sleep(time.Second * 10)
		p2p.startWs(port)
		return
	}
	serverConn = c
	manager.SendLog(fmt.Sprintf("p2p socket 连接服务成功:%s", u.String()))
	go func() {
		for {
			if serverConn == nil {
				return
			}

			if !p2p.tunnel.P2POpening {
				manager.SendLog("p2p socket 断开连接 接收server")
				return
			}

			c.SetReadDeadline(time.Now().Add(pongWait))
			transmitParams := TransmitParams{}
			err := c.ReadJSON(&transmitParams)
			if err != nil {
				manager.SendLog(fmt.Sprintf("p2p socket 断开连接 接收server json失败:%s", err))
				c.Close()
				serverConn = nil
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
				p2p.handlerPeer(params)
			}
		}
	}()
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		log.Infof(`conn关闭%d`, token.Cid)
		ticker.Stop()
		c.Close()
		serverConn = nil
		time.Sleep(time.Second * 10)
		p2p.startWs(port)
	}()
	for range ticker.C {
		if err := p2p.sendJsonToMaster(P2PSocketParams{MType: `ping`}, false); err != nil {
			manager.SendLog(fmt.Sprintf(`p2p socket ping server 失败:%s`, err.Error()))
			break
		}
	}
}

func (p2p *P2PPage) handlerPeer(params *P2PSocketParams) {
	if len(params.IfInfo.PrK) == 0 {
		manager.SendLog("未收到interface信息")
		return
	}
	//本地peer信息
	runCf, err := p2p.tunnel.RuntimeConfig()
	if err != nil {
		manager.SendLog(fmt.Sprintf(`获取运行配置失败:%s`, err))
		return
	}

	interfacePrivateKey = params.IfInfo.PrK
	key, _ := conf.NewPrivateKeyFromString(interfacePrivateKey)
	runCf.Interface.PrivateKey = *key

	addr, err := conf.ParseIPCidr(params.IfInfo.Ip)
	if err != nil {
		return
	}
	runCf.Interface.Addresses = []netip.Prefix{addr}

	peers := make([]conf.Peer, 0)
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

		p, ok := LocalPeers[rPeer.PuK]
		if !ok {
			p = &LocalPeer{}
			LocalPeers[rPeer.PuK] = p
		}

		p.ConfigUpdateTime = time.Now()
		p.Ip = rPeer.Ip
		p.Mode = rPeer.Mode
		p.Status = 1

		peers = append(peers, peer)
	}
	runCf.Peers = peers

	go p2p.tunnel.SetConfiguration(&runCf)
}

func (p2p *P2PPage) checkPeerStatus() {
	for {
		if !p2p.tunnel.P2POpening {
			return
		}

		time.Sleep(time.Second * 30)
		fails := make([]P2PPeerInfo, 0)

		runCf, err := p2p.tunnel.RuntimeConfig()
		if err != nil {
			manager.SendLog(fmt.Sprintf(`wg 获取interface信息失败:%s`, err.Error()))
			continue
		}

		for _, peer := range runCf.Peers {
			if (peer.LastHandshakeTime-116444736000000000)*100 > 4 {
				manager.SendLog(fmt.Sprintf("peer [%s] 状态为连接失败", peer.PublicKey))
				fails = append(fails, P2PPeerInfo{PuK: peer.PublicKey.String(), Name: runCf.Name})
			} else {
				manager.SendLog(fmt.Sprintf("peer [%s] 状态为连接成功", peer.PublicKey))
			}
		}
		if len(fails) == 0 {
			continue
		}
		manager.SendLog(fmt.Sprintf("开始上送连接失败信息:%v", fails))
		if err := p2p.sendJsonToMaster(P2PSocketParams{MType: `fails`, Peers: fails}, true); err != nil {
			manager.SendLog(fmt.Sprintf("上送连接失败信息失败:%s", err.Error()))
			continue
		}
	}
}

func (p2p *P2PPage) sendJsonToMaster(data P2PSocketParams, logSw bool) error {
	if serverConn == nil {
		return fmt.Errorf(`与server未建立socket连接`)
	}
	enData, err := encryptionDataByP2p(utils.DefaultAesKey, data)
	if err != nil {
		return err
	}
	serverConn.SetWriteDeadline(time.Now().Add(writeWait))
	if err := serverConn.WriteJSON(&enData); err != nil {
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
