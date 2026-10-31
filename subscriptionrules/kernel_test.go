package subscriptionrules

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"trojan-panel/model/bo"
	"trojan-panel/model/constant"
)

// Optional local proof uses the installed core in test-only mode, with an isolated home.
// Provider caches are preseeded, so parser verification does not require external downloads.
func TestClashVergeKernelAcceptsCloudDefaults(t *testing.T) {
	core := os.Getenv("XWARP_TEST_MIHOMO")
	if core == "" {
		t.Skip("set XWARP_TEST_MIHOMO for an isolated installed-core check")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "ruleset"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string]string{
		"xwarp-direct.yaml": "payload:\n  - '+.qq.com'\n  - '+.taobao.com'\n",
		"xwarp-cncidr.yaml": "payload:\n  - 223.5.5.0/24\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, "ruleset", name), []byte(payload), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := bo.ClashConfig{Mode: "rule", Proxies: []interface{}{bo.Socks{Name: "candidate", Type: "socks5", Server: "127.0.0.1", Port: 9}}, ProxyGroups: ProxyGroups([]string{"candidate"})}
	prefix, err := yaml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := Compose(constant.ClashRules, "", constant.ClashLocalRules)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, append(prefix, []byte(rules)...), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("Mihomo rejected candidate: %v\n%s", err, output)
	}
	t.Log("Installed Mihomo accepted the complete cloud-provider subscription in an isolated directory")
}

// Replay the observed IPv6 Fake-IP destination through an isolated real core. The local
// SOCKS fixture records proxy routing without making a connection to any external server.
func TestIPv6FakeIPDoesNotGoDirect(t *testing.T) {
	core := os.Getenv("XWARP_TEST_MIHOMO")
	if core == "" {
		t.Skip("set XWARP_TEST_MIHOMO for an isolated routing replay")
	}
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	proxied := make(chan bool, 1)
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				header := make([]byte, 2)
				if _, err := io.ReadFull(conn, header); err != nil || header[0] != 5 {
					return
				}
				if _, err := io.ReadFull(conn, make([]byte, int(header[1]))); err != nil {
					return
				}
				if _, err := conn.Write([]byte{5, 0}); err != nil {
					return
				}
				request := make([]byte, 4)
				if _, err := io.ReadFull(conn, request); err == nil && request[0] == 5 && request[1] == 1 {
					address := make([]byte, 18)
					if request[3] != 4 {
						return
					}
					if _, err := io.ReadFull(conn, address); err != nil || !net.IP(address[:16]).Equal(net.ParseIP("fdfe:dcba:9876::11b")) {
						return
					}
					select {
					case proxied <- true:
					default:
					}
					conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
				}
			}()
		}
	}()
	portProbe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portProbe.Addr().(*net.TCPAddr).Port
	portProbe.Close()
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "ruleset"), 0700)
	for name, payload := range map[string]string{"xwarp-direct.yaml": "payload: ['+.qq.com']\n", "xwarp-cncidr.yaml": "payload: ['223.5.5.0/24']\n"} {
		if err := os.WriteFile(filepath.Join(dir, "ruleset", name), []byte(payload), 0600); err != nil {
			t.Fatal(err)
		}
	}
	rules, err := Compose(constant.ClashRules, "", constant.ClashLocalRules)
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("mixed-port: %d\nallow-lan: false\nmode: rule\nlog-level: debug\nproxies:\n  - name: fixture\n    type: socks5\n    server: 127.0.0.1\n    port: %d\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [fixture]\n", port, upstream.Addr().(*net.TCPAddr).Port) + rules
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(dir, "core.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "-d", dir, "-f", path)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	var conn net.Conn
	for i := 0; i < 60; i++ {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("isolated core did not start")
	}
	defer conn.Close()
	fmt.Fprint(conn, "CONNECT [fdfe:dcba:9876::11b]:443 HTTP/1.1\r\nHost: [fdfe:dcba:9876::11b]:443\r\n\r\n")
	// Mihomo opens lazy outbound connections only after receiving tunnel payload.
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: muse.ai\r\n\r\n")
	select {
	case <-proxied:
		t.Log("IPv6 Fake-IP reached the selected proxy rather than the private-network direct path")
	case <-time.After(4 * time.Second):
		cmd.Process.Kill()
		cmd.Wait()
		data, _ := os.ReadFile(logFile.Name())
		t.Log(string(data))
		t.Fatal("IPv6 Fake-IP was swallowed by direct routing instead of reaching the proxy fixture")
	}
}
