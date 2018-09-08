package sshclient

import (
	"time"
	"fmt"
	"regexp"
	"strings"
)

// ReadUntil reads tcp stream until given prompt (should be valid regex string) catched.
// All ESC-sequences are cutted out.
func (c *SshClient) ReadUntil(waitfor string) (string, error) {
	defer func() {
		c.mx.Lock()
		c.reading = false
		c.mx.Unlock()
	}()

	c.mx.Lock()
	tout := c.TimeoutGlobal
	c.reading = true
	c.mx.Unlock()

	time.AfterFunc(time.Second * time.Duration(tout), func() {
		c.mx.Lock()
		if c.reading {
			c.reading = false
			c.Close()
		}
		c.mx.Unlock()
	})

	//var result bytes.Buffer
	c.buf.Reset()

	//result := make([]byte, 0)
	temp := make([]byte, 0)
	tbuf := make([]byte, 81920)
	totalBytes := 0

	if waitfor == "" {
		return c.buf.String(), fmt.Errorf(`Empty "waitfor" string given`)
	}
	rePrompt, err := regexp.Compile(waitfor)
	if err != nil {
		return c.buf.String(), fmt.Errorf(`Cannot compile "waitfor" regexp`)
	}

	inSequence := false
	c.mx.Lock()
	globalTout := time.After(time.Second * time.Duration(c.TimeoutGlobal))
	c.mx.Unlock()
	for {
		select {
		case <- globalTout:
			return c.buf.String(), fmt.Errorf("Operation timeout reached during read")
		default:
			n, err := c.outPipe.Read(tbuf)
			totalBytes += n

			if err != nil {
				return c.buf.String(), err
			}

			for i := 0; i < totalBytes; i++ {
				// cut \r's
				if tbuf[i] == 13 {
					continue
				}

				// cut out escape sequences
				if tbuf[i] == 27 {
					inSequence = true
					continue
				}
				if inSequence {
					// 2) 0-?, @-~, ' ' - / === 48-63, 32-47, finish with 64-126
					if tbuf[i] == 91 {
						continue
					}
					if tbuf[i] >= 32 && tbuf[i] <= 63 {
						// just skip it
						continue
					}
					if tbuf[i] >= 64 && tbuf[i] <= 126 {
						// finish sequence
						inSequence = false
						continue
					}
				}

				c.buf.WriteByte(tbuf[i])
				if len(c.patterns) > 0 {
					temp = append(temp, tbuf[i])
				}
			}

			// catch possible patterns
			if len(c.patterns) > 0 {
				for i := range c.patterns {
					if c.patterns[i].Re.Match(temp) {
						c.patterns[i].Cb()
						temp = make([]byte, 0)
						// remove last line from buffer
						lines := strings.Split(c.buf.String(), "\n")
						lines = lines[:len(lines)-1]
						c.buf.Reset()
						c.buf.WriteString(strings.Join(lines, "\n"))
					}
				}
			}

			if rePrompt.Match(c.buf.Bytes()) {
				return c.buf.String(), nil
			}

			tbuf = make([]byte, 81920)
			totalBytes = 0
		}
	}

	return c.buf.String(), nil
}

