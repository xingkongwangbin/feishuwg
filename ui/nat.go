package ui

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/ccding/go-stun/stun"
	"github.com/lxn/walk"
)

const (
	DefaultStunAddr = "stun.qq.com"
	DefaultStunPort = "3478"
)

type NatPage struct {
	*walk.TabPage
	flag            int32
	natContainer    walk.Container
	serTextEdit     *walk.TextEdit
	portTextEdit    *walk.TextEdit
	checkButton     *walk.PushButton
	resultTextLabel *walk.TextLabel

	introContainer walk.Container
}

func NewNatPage() (*NatPage, error) {
	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	np := new(NatPage)
	if np.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}
	disposables.Add(np)

	np.SetTitle("NAT检测")
	np.SetLayout(walk.NewVBoxLayout())

	if err = np.NewNatView(); err != nil {
		return nil, err
	}

	if err = np.NewIntroView(); err != nil {
		return nil, err
	}

	disposables.Spare()

	return np, nil
}

func (np *NatPage) NewNatView() error {
	np.natContainer, _ = walk.NewComposite(np)
	np.natContainer.SetMinMaxSize(walk.Size{Width: 0, Height: 0}, walk.Size{Width: 675, Height: 100})
	vlayout := walk.NewVBoxLayout()
	vlayout.SetSpacing(5)
	np.natContainer.SetLayout(vlayout)

	titleLabel, err := walk.NewTextLabel(np.natContainer)
	if err != nil {
		return err
	}

	titleLabel.SetText("STUN服务器 + 端口")

	if np.serTextEdit, err = walk.NewTextEdit(np.natContainer); err != nil {
		return err
	}

	np.serTextEdit.SetText(DefaultStunAddr)
	np.serTextEdit.SetMinMaxSize(walk.Size{Width: 10, Height: 10}, walk.Size{Width: 80, Height: 22})

	if np.portTextEdit, err = walk.NewTextEdit(np.natContainer); err != nil {
		return err
	}

	np.portTextEdit.SetText(DefaultStunPort)
	np.portTextEdit.SetMinMaxSize(walk.Size{Width: 10, Height: 10}, walk.Size{Width: 50, Height: 22})

	if np.checkButton, err = walk.NewPushButton(np.natContainer); err != nil {
		return err
	}

	np.checkButton.SetText("开始检测")
	np.checkButton.Clicked().Attach(np.onActiveClicked)

	if np.resultTextLabel, err = walk.NewTextLabel(np.natContainer); err != nil {
		return err
	}

	return nil
}

func (np *NatPage) NewIntroView() error {
	np.introContainer, _ = walk.NewComposite(np)
	np.introContainer.SetMinMaxSize(walk.Size{Width: 0, Height: 0}, walk.Size{Width: 675, Height: 525})
	vlayout := walk.NewVBoxLayout()
	vlayout.SetSpacing(0)
	np.introContainer.SetLayout(vlayout)

	condLabel, err := walk.NewTextLabel(np.introContainer)
	if err != nil {
		return err
	}

	condLabel.SetText("P2P建立条件：\n联机的双方NAT类型有一方为Cone NAT时（以下前三种），才有概率建立P2P连接，如果双方都是Symmetric NAT，必然无法成功建立P2P连接（中转）。")
	condLabel.SetTextColor(walk.RGB(255, 0, 0))

	titleLabel, err := walk.NewTextLabel(np.introContainer)
	if err != nil {
		return err
	}

	titleLabel.SetText("几种常见的NAT类型：NAT的四种类型及类型检测（详细介绍）")

	detailsLabel, err := walk.NewTextLabel(np.introContainer)
	if err != nil {
		return err
	}

	detailsLabel.SetText("1. 完全锥形NAT\n\n2. 限制锥形NAT\n\n3. 端口限制锥形NAT\n\n4. 对称NAT")

	return nil
}

func (np *NatPage) onActiveClicked() {
	if !atomic.CompareAndSwapInt32(&np.flag, 0, 1) {
		return
	}

	np.resultTextLabel.SetText("检测中 ......")

	go func() {
		defer func() {
			atomic.StoreInt32(&np.flag, 0)
		}()

		ser := strings.TrimSpace(np.serTextEdit.Text())
		port := strings.TrimSpace(np.portTextEdit.Text())

		if ser == "" {
			np.resultTextLabel.SetText("服务器地址不能为空")
			return
		}

		if port == "" {
			np.resultTextLabel.SetText("服务器端口不能为空")
			return
		}

		serverAddr := fmt.Sprintf("%s:%s", ser, port)

		client := stun.NewClient()
		client.SetServerAddr(serverAddr)
		nat, host, err := client.Discover()
		if err != nil {
			np.resultTextLabel.SetText(err.Error())
			return
		}

		if host == nil {
			np.resultTextLabel.SetText("host获取失败")
			return
		}

		np.resultTextLabel.SetText(fmt.Sprintf("Nat类型:  %s;  外网IP:  %s:%d", nat, host.IP(), host.Port()))
	}()
}
