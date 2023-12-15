package p2p

import (
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.zx2c4.com/wireguard/windows/manager"
)

var (
	selfClientName string
	selfIp         string
	srv            *http.Server
)

func InitApi() {
	router := gin.Default()
	router.GET("/p2p", getStatus)
	router.GET("/check", checkStatus)

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		manager.SendLog(fmt.Sprintf("api 监听端口失败:%s", err))
		return
	}

	controlPort = ln.Addr().(*net.TCPAddr).Port
	manager.AddFireWallRule(controlPort)

	manager.SendLog(fmt.Sprintf("飞鼠客户端地址curl: curl localhost:%d/p2p | jq\n", controlPort))

	srv = &http.Server{
		Handler: router,
	}

	go func() {
		if err = srv.Serve(ln); err != nil {
			manager.SendLog(fmt.Sprintf("api 启动失败:%s", err))
		}
	}()
}

func getStatus(c *gin.Context) {
	mux.Lock()
	defer mux.Unlock()

	if len(localPeers) == 0 {
		c.JSON(http.StatusOK, gin.H{"msg": "暂未连接"})
		return
	}

	list := make([]map[string]string, 0)
	self := make(map[string]string)
	self[`name`] = selfClientName + "(本机)"
	self[`ip`] = strings.Split(selfIp, `/`)[0]
	self[`OsName`] = runtime.GOOS
	list = append(list, self)
	for _, p := range localPeers {
		result := make(map[string]string)
		result[`name`] = p.Name
		result[`ip`] = p.InnerIp
		result[`mode`] = p.Mode
		result[`OsName`] = p.OsName
		result[`configAddTime`] = p.ConfigAddTime.Format("2006-01-02 15:04:05")
		result[`status`] = p.StatusToStr()
		if p.Status == 2 {
			rtt, err := getRtt(strings.Split(p.Ip, ":")[0])
			if err != nil {
				result[`rtt`] = "未知"

			} else {
				result[`rtt`] = rtt
			}
		}
		list = append(list, result)
	}
	sort.Slice(list, func(i, j int) bool {
		return strings.Compare(list[i][`name`], list[j][`name`]) > 0
	})
	c.JSON(http.StatusOK, gin.H{"msg": "ok", "list": list})
}

func checkStatus(c *gin.Context) {
	wg := c.Request.Header.Get("wg")
	if wg == `wg` {
		manager.SendLog(fmt.Sprintf("111111111:%s", strings.Split(selfIp, "/")[0]))
		c.Writer.WriteString(strings.Split(selfIp, "/")[0])
	}
}
