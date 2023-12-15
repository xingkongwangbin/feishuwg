package p2p

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-ping/ping"
)

func get(ip, port string) error {
	url := fmt.Sprintf("http://%s:%s/check", ip, port)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("wg", "wg")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("请求[%s]返回异常: %d", url, resp.StatusCode)
	}

	str, _ := io.ReadAll(resp.Body)
	if ip != string(str) {
		return fmt.Errorf("响应错误，应为[%s]，结果[%s]", ip, str)
	}

	return nil
}

func getRtt(ip string) (string, error) {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		return "", err
	}
	pinger.SetPrivileged(true)
	pinger.Count = 1
	pinger.Timeout = time.Second * 1
	err = pinger.Run()
	if err != nil {
		return "", err
	}
	stats := pinger.Statistics()
	return fmt.Sprintf(`%d`, stats.AvgRtt.Milliseconds()), nil
}
