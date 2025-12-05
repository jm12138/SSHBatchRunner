package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/robfig/cron/v3"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	Name          string
	Host          string
	Port          string
	Username      string
	Password      string
	Commands      []Command
	OutputTimeout int
	CronExpr      string
	UseLegacy     bool
}

type Command struct {
	Cmd     string
	WaitSec int
}

func loadConfigFromFile(envPath string) (*Config, error) {
	envMap, err := godotenv.Read(envPath)
	if err != nil {
		return nil, fmt.Errorf("读取 %s 失败: %w", envPath, err)
	}

	get := func(key string) string {
		if v, ok := envMap[key]; ok {
			return v
		}
		return ""
	}

	cfg := &Config{
		Name:      filepath.Base(envPath),
		Host:      get("SSH_HOST"),
		Port:      get("SSH_PORT"),
		Username:  get("SSH_USER"),
		Password:  get("SSH_PASS"),
		UseLegacy: get("SSH_LEGACY") == "true",
	}

	if cfg.Host == "" || cfg.Port == "" || cfg.Username == "" || cfg.Password == "" {
		return nil, fmt.Errorf("[%s] 配置不完整", cfg.Name)
	}

	for i := 1; ; i++ {
		cmdKey := fmt.Sprintf("CMD_%d", i)
		waitKey := fmt.Sprintf("CMD_%d_WAIT", i)
		cmdVal := get(cmdKey)
		if cmdVal == "" {
			break
		}
		waitSec := 2
		if w := get(waitKey); w != "" {
			if d, err := time.ParseDuration(w + "s"); err == nil {
				waitSec = int(d.Seconds())
			}
		}
		cfg.Commands = append(cfg.Commands, Command{Cmd: cmdVal + "\n", WaitSec: waitSec})
	}
	if len(cfg.Commands) == 0 {
		return nil, fmt.Errorf("[%s] 未配置任何 CMD_n", cfg.Name)
	}

	cfg.OutputTimeout = 5
	if t := get("OUTPUT_TIMEOUT"); t != "" {
		if d, err := time.ParseDuration(t + "s"); err == nil {
			cfg.OutputTimeout = int(d.Seconds())
		}
	}

	cfg.CronExpr = get("CRON")

	return cfg, nil
}

func loadAllConfigs(dir string) ([]*Config, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.env"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("未在 %s 中找到任何 .env 文件", dir)
	}

	var configs []*Config
	for _, f := range files {
		cfg, err := loadConfigFromFile(f)
		if err != nil {
			log.Printf("⚠️ 跳过 %s: %v", f, err)
			continue
		}
		configs = append(configs, cfg)
	}
	return configs, nil
}

func createSSHClient(cfg *Config) (*ssh.Client, error) {
	sshConfig := &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(cfg.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	if cfg.UseLegacy {
		sshConfig.Config = ssh.Config{
			KeyExchanges: []string{
				"diffie-hellman-group-exchange-sha1",
				"diffie-hellman-group1-sha1",
				"diffie-hellman-group14-sha1",
			},
			Ciphers: []string{
				"aes128-cbc", "3des-cbc", "aes192-cbc", "aes256-cbc",
				"aes128-ctr", "aes192-ctr", "aes256-ctr",
			},
			MACs: []string{
				"hmac-sha1", "hmac-md5", "hmac-sha1-96", "hmac-md5-96",
			},
		}
	}

	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("[%s] SSH 连接失败: %w", cfg.Host, err)
	}
	return client, nil
}

func createSession(client *ssh.Client) (*ssh.Session, io.WriteCloser, io.Reader, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, nil, nil, err
	}
	modes := ssh.TerminalModes{ssh.ECHO: 0, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty("vt100", 80, 40, modes); err != nil {
		session.Close()
		return nil, nil, nil, err
	}
	stdout, _ := session.StdoutPipe()
	stdin, _ := session.StdinPipe()
	if err := session.Shell(); err != nil {
		session.Close()
		return nil, nil, nil, err
	}
	return session, stdin, stdout, nil
}

func executeCommands(stdin io.WriteCloser, stdout io.Reader, commands []Command, timeout int) ([]byte, error) {
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() { defer close(done); io.Copy(&buf, stdout) }()

	for _, cmd := range commands {
		io.WriteString(stdin, cmd.Cmd)
		time.Sleep(time.Duration(cmd.WaitSec) * time.Second)
	}

	select {
	case <-done:
	case <-time.After(time.Duration(timeout) * time.Second):
	}
	return buf.Bytes(), nil
}

func saveOutput(cfg *Config, data []byte) error {
	if err := os.MkdirAll("logs", 0755); err != nil {
		return err
	}
	filename := fmt.Sprintf("logs/%s_%s.log", cfg.Host, time.Now().Format("20060102150405"))
	return os.WriteFile(filename, data, 0644)
}

func runTask(cfg *Config) error {
	start := time.Now()
	client, err := createSSHClient(cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	session, stdin, stdout, err := createSession(client)
	if err != nil {
		return err
	}
	defer session.Close()

	output, err := executeCommands(stdin, stdout, cfg.Commands, cfg.OutputTimeout)
	if err != nil {
		return err
	}
	if err := saveOutput(cfg, output); err != nil {
		return err
	}
	log.Printf("✅ [%s] 完成 (耗时 %v, 输出 %d 字节)", cfg.Host, time.Since(start).Round(time.Second), len(output))
	return nil
}

func runAll(configs []*Config) {
	start := time.Now()
	log.Printf("🚀 开始执行 %d 台服务器任务...", len(configs))

	var wg sync.WaitGroup
	var success, failed int
	var mu sync.Mutex

	for _, cfg := range configs {
		wg.Add(1)
		go func(c *Config) {
			defer wg.Done()
			log.Printf("🔗 [%s] 连接中...", c.Host)
			if err := runTask(c); err != nil {
				log.Printf("❌ [%s] 失败: %v", c.Host, err)
				mu.Lock()
				failed++
				mu.Unlock()
				return
			}
			mu.Lock()
			success++
			mu.Unlock()
		}(cfg)
	}

	wg.Wait()
	total := time.Since(start).Round(time.Second)
	log.Printf("\n📊 执行完成: 成功 %d / 失败 %d / 总计 %d / 用时 %v\n",
		success, failed, len(configs), total)
}

func main() {
	ctx := context.Background()

	startInit := time.Now()
	configs, err := loadAllConfigs("configs")
	if err != nil {
		log.Fatalf("❌ %v", err)
	}
	log.Printf("✅ 初始化完成，共加载 %d 个服务器配置 (耗时 %v)", len(configs), time.Since(startInit).Round(time.Millisecond))

	hasCron := false
	for _, c := range configs {
		if c.CronExpr != "" {
			hasCron = true
			break
		}
	}

	if hasCron {
		cronJob := cron.New(cron.WithSeconds())
		for _, cfg := range configs {
			localCfg := cfg
			if localCfg.CronExpr == "" {
				continue
			}
			_, err := cronJob.AddFunc(localCfg.CronExpr, func() {
				log.Printf("⏰ [%s] 定时任务开始", localCfg.Host)
				if err := runTask(localCfg); err != nil {
					log.Printf("❌ [%s] 定时任务失败: %v", localCfg.Host, err)
				}
			})
			if err != nil {
				log.Printf("⚠️ [%s] 定时任务注册失败: %v", localCfg.Host, err)
			} else {
				log.Printf("🕒 [%s] 定时任务已注册 (%s)", localCfg.Host, localCfg.CronExpr)
			}
		}
		cronJob.Start()
		log.Println("✅ 定时任务已启动，按 Ctrl+C 退出")
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		cronJob.Stop()
		log.Println("👋 程序已退出")
	} else {
		runAll(configs)
	}

	_ = ctx
}
