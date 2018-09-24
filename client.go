// Package sshclient provides simple wrapper around x/crypto/ssh
// and makes it easely to connect to remote ssh servers and make command calls
package sshclient

import (
	"golang.org/x/crypto/ssh"
	"io"
	"strings"
	"time"
	"fmt"
	"github.com/pkg/errors"
	"github.com/google/goterm/term"
	"regexp"
	"bytes"
	"github.com/sasha-s/go-deadlock"
)

// callbackPattern struct handles callbacks that should be called when corresponding
// regex matches.
type callbackPattern struct {
	Re			*regexp.Regexp
	Cb			func()
	SkipLine	bool
}

// SshClient is ssh client struct itself
type SshClient struct {
	User		string
	Password	string
	prompt		string
	Timeout		int
	TimeoutGlobal	int

	sshClient	*ssh.Client
	sshSession	*ssh.Session
	outPipe		io.Reader
	inPipe		io.WriteCloser
	errPipe		io.Reader

	reading		bool
	buf			bytes.Buffer

	patterns	[]callbackPattern
	mx			deadlock.Mutex
}

// New returns new instance of SshClient. Arguments are: connection timeout, username, password, prompt.
// Returns pointer to the instance of SshClient
func New(tout int, user string, password string, prompt string) *SshClient {
	if tout < 1 {
		tout = 1
	}

	c := SshClient{
		Timeout:tout,
		User:user,
		Password:password,
		prompt: `(?msi:[\$%#>]$)`,
		patterns: make([]callbackPattern, 0),
	}

	if prompt != "" {
		c.prompt = prompt
	}

	c.TimeoutGlobal = c.Timeout * 2

	return &c
}

// SetLoginPrompt - just dummy for interface matching
func (c *SshClient) SetLoginPrompt(s string) {
	//
}

// SetLogin
func (c *SshClient) SetLogin(login string) {
	c.User = login
}

// You may need to change password for enable (because prompt is same as login)
func (c *SshClient) SetPassword(pw string) {
	c.mx.Lock()
	c.Password = pw
	c.mx.Unlock()
}

// SetPrompt allows you to change prompt without re-creating ssh client
func (c *SshClient) SetPrompt(prompt string) {
	c.mx.Lock()
	c.prompt = prompt
	c.mx.Unlock()
}

// GlobalTimeout sets timeout for app operations, where net.Conn deadline could not be useful.
// For example stucking in pagination, while some network devices refreshing their telnet screen - so
// we cannot reach read timeout.
func (c *SshClient) GlobalTimeout(t int) {
	c.mx.Lock()
	c.TimeoutGlobal = t
	c.mx.Unlock()
}

// Close disconnects ssh session and closes all connections.
// You can use it in defer
func (c *SshClient) Close() {
	c.sshSession.Close()
	c.sshClient.Close()
	c.inPipe.Close()
}

// Open establishes ssh connection with given host:port
func (c *SshClient) Open(host string, port int) error {
	var err error

	challenge := func(user string, instruction string, questions []string, echos []bool) ([]string, error) {
		if len(questions) == 0 {
			return []string{}, nil
		}

		return []string{c.Password}, nil
	}

	config := ssh.ClientConfig{
		User:				c.User,
		Auth:				[]ssh.AuthMethod{
								ssh.PasswordCallback(func()(string, error){ return c.Password, nil }),
								ssh.KeyboardInteractive(challenge),
								ssh.Password(c.Password),
							},
		HostKeyCallback:	ssh.InsecureIgnoreHostKey(),
		Timeout:			time.Second * time.Duration(c.TimeoutGlobal),
	}
	config.Ciphers = append(config.Ciphers, "aes128-ctr", "aes192-ctr", "aes256-ctr", "chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com")

	c.sshClient, err = ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), &config )
	if err != nil {
		if strings.Contains(err.Error(), "no common algorithm") {
			config.Ciphers = []string{"aes128-cbc", "3des-cbc", "aes192-cbc", "aes256-cbc"}
			c.sshClient, err = ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), &config )
			if err != nil {
				return errors.Wrap(err, "SSH dial failed")
			}
		} else {
			return errors.Wrap(err, "SSH dial failed")
		}
	}


	// Setup terminal
	terminal := term.Termios{}
	terminal.Raw()
	terminal.Wz.WsCol, terminal.Wz.WsRow = 132, 100

	// start/request session
	c.sshSession, err = c.sshClient.NewSession()
	if err != nil {
		return err
	}

	// setup some session params
	modes := ssh.TerminalModes{
		ssh.ECHO:				0,
		ssh.TTY_OP_ISPEED:		14400000,
		ssh.TTY_OP_OSPEED:		14400000,
	}
	if err = c.sshSession.RequestPty("xterm", 132, 100, modes); err != nil {
		return errors.Wrap(err, "Failed to request SSH PTY")
	}

	c.inPipe, err = c.sshSession.StdinPipe()
	if err != nil {
		return errors.Wrap(err, "Failed to request stdin pipe")
	}
	c.outPipe, err = c.sshSession.StdoutPipe()
	if err != nil {
		return errors.Wrap(err, "Failed to request stdout pipe")
	}
	c.errPipe, err = c.sshSession.StderrPipe()
	if err != nil {
		return errors.Wrap(err, "Failed to request stderr pipe")
	}

	err = c.sshSession.Shell()
	if err !=  nil {
		return errors.Wrap(err, "Failed to request ssh shell")
	}

	// Wait for prompt just after login
	_, err = c.ReadUntil(c.prompt)
	
	return err
}

// RegisterCallback registers new callback based on regex string. When current output string matches given
// regex, callback is called. Returns error if regex cannot be compiled.
func (c *SshClient) RegisterCallback(pattern string, callback func()) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	c.mx.Lock()
	c.patterns = append(c.patterns, callbackPattern{
		Cb:callback,
		Re:re,
	})
	c.mx.Unlock()

	return nil
}

// GetBuffer returns current buffer from reader as a string
func (c *SshClient) GetBuffer() string {
	c.mx.Lock()
	str := c.buf.String()
	c.mx.Unlock()
	return str
}
