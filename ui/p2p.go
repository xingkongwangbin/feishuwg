package ui

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/manager"
	"golang.zx2c4.com/wireguard/windows/p2p"
	"golang.zx2c4.com/wireguard/windows/utils"
)

type P2PPage struct {
	*walk.TabPage
	p2pContainer  walk.Container
	tokenTextEdit *walk.TextEdit
	openButton    *walk.PushButton
	closeButton   *walk.PushButton
}

var (
	tunnel manager.Tunnel
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

	p2p.tokenTextEdit.SetText("")

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

func (p *P2PPage) onOpenClicked() {
	tokenText := strings.TrimSpace(p.tokenTextEdit.Text())
	if tokenText == "" {
		walk.MsgBox(p.Form(), "错误", "Token不能为空!", walk.MsgBoxIconError)
		return
	}

	tokenJsonStr, err := utils.AesDecrypt(tokenText)
	if err != nil {
		walk.MsgBox(p.Form(), "错误", "Token解析失败!", walk.MsgBoxIconError)
		return
	}

	token := p2p.Token{}
	err = json.Unmarshal([]byte(tokenJsonStr), &token)
	if err != nil {
		walk.MsgBox(p.Form(), "错误", "Token格式错误!", walk.MsgBoxIconError)
		return
	}

	if len(token.Server) == 0 {
		walk.MsgBox(p.Form(), "错误", "服务端地址为空!", walk.MsgBoxIconError)
		return
	}
	if len(token.CIp) == 0 {
		walk.MsgBox(p.Form(), "错误", "客户端IP为空!", walk.MsgBoxIconError)
		return
	}
	if len(token.Cn) == 0 {
		walk.MsgBox(p.Form(), "错误", "客户端网卡名称为空!", walk.MsgBoxIconError)
		return
	}

	tunnel, err = manager.IPCClientNewTunnel(&conf.Config{Name: token.Cn})
	if err != nil {
		walk.MsgBox(p.Form(), "错误", "获取配置失败: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	tunnel.SetP2P()

	err = tunnel.Start()
	if err != nil {
		walk.MsgBox(p.Form(), "错误", "启动渠道失败: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	p2p.InitApi()

	p.Toggle()
	time.Sleep(time.Second * 2)

	p2p.Start(tunnel, token)
	p2p.RegisterCloseFunc(func() {
		p.Toggle()
	})
}

func (p *P2PPage) onCloseClicked() {
	tunnel.Stop()
	p.Toggle()
	tunnel.Delete()
}

func (p *P2PPage) Toggle() {
	if tunnel.IsRunning() {
		p.openButton.SetEnabled(false)
		p.tokenTextEdit.SetReadOnly(true)
		p.openButton.SetText("打洞中...")
		p.closeButton.SetEnabled(true)
	} else {
		p.openButton.SetEnabled(true)
		p.closeButton.SetEnabled(false)
		p.tokenTextEdit.SetReadOnly(false)
		p.openButton.SetText("打洞")
	}
}
