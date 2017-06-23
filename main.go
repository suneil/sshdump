package main

import (
	//	"bufio"
	"fmt"
	"io"
	//	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"github.com/kevinburke/ssh_config"
	"io/ioutil"
	"strconv"
	"path/filepath"
)

type Endpoint struct {
	Host string
	Port int
}

func (endpoint *Endpoint) String() string {
	return fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)
}

type SSHtunnel struct {
	Local  *Endpoint
	Server *Endpoint
	Remote *Endpoint

	Config *ssh.ClientConfig
}

func PublicKeyFile(file string) ssh.AuthMethod {
	absFile, err := filepath.Abs(file)
	if err != nil {
		return nil
	}

	buffer, err := ioutil.ReadFile(absFile)
	if err != nil {
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil
	}
	return ssh.PublicKeys(key)
}

func dumpDatabase(listener net.Listener) {
	defer func() {
		listener.Close()
	}()

	cmd := exec.Command("mysqldump", "-P3308", "-h", "127.0.0.1", "-uuser", "-ppassword", "dbname", "--opt", "-R", "-C")

	now := time.Now()

	date := now.Format("20060102_150405")
	filename := "sshdump_" + date + ".sql"
	fmt.Println("Saving to", filename)
	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Printf("error opening file: %v", err)
	}
	defer f.Close()

	// On this line you're going to redirect the output to a file
	cmd.Stdout = f
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Command failed.", err)
		os.Exit(1)
	}
}

func (tunnel *SSHtunnel) Start() error {
	listener, err := net.Listen("tcp", tunnel.Local.String())
	if err != nil {
		return err
	}
	defer listener.Close()

	go dumpDatabase(listener)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go tunnel.forward(conn)
	}
}

func (tunnel *SSHtunnel) forward(localConn net.Conn) {
	serverConn, err := ssh.Dial("tcp", tunnel.Server.String(), tunnel.Config)
	if err != nil {
		fmt.Printf("Server dial error: %s\n", err)
		return
	}

	remoteConn, err := serverConn.Dial("tcp", tunnel.Remote.String())
	if err != nil {
		fmt.Printf("Remote dial error: %s\n", err)
		return
	}

	copyConn := func(writer, reader net.Conn) {
		_, err := io.Copy(writer, reader)
		if err != nil {
			fmt.Printf("io.Copy error: %s", err)
		}
	}

	fmt.Println("Houston, we have a go")

	go copyConn(localConn, remoteConn)
	go copyConn(remoteConn, localConn)
}

func SSHAgent() ssh.AuthMethod {
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
	}
	return nil
}

func main() {
	serverHost := ssh_config.Get("staging", "Hostname")
	serverPortString := ssh_config.Get("staging", "Port")
	identityFile, err := ssh_config.GetStrict("staging", "IdentityFile")
	if err != nil {
		panic(err)
	}

	serverPort, err :=strconv.Atoi(serverPortString)
	if err != nil {
		panic(err)
	}

	localEndpoint := &Endpoint{
		Host: "localhost",
		Port: 3308,
	}

	serverEndpoint := &Endpoint{
		//Host: "staging.loadexpress.com",
		//Port: 22,
		Host: serverHost,
		Port: serverPort,
	}

	remoteEndpoint := &Endpoint{
		Host: "database-host",
		Port: 3306,
	}

	sshConfig := &ssh.ClientConfig{
		User: "ubuntu",
		//Auth: []ssh.AuthMethod{PublicKeyFile("/Users/spatel/opt/infogation/loadexpress.osx.box/loadexpress-aws/loadexpress_staging.pem")},
		Auth: []ssh.AuthMethod{PublicKeyFile(identityFile)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		// Auth: []ssh.AuthMethod{
		// 	SSHAgent(),
		// },
	}

	tunnel := &SSHtunnel{
		Config: sshConfig,
		Local:  localEndpoint,
		Server: serverEndpoint,
		Remote: remoteEndpoint,
	}

	tunnel.Start()
}
