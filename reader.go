package sshclient

import (
	"time"
	"fmt"
	"regexp"
	)

// ReadUntil reads tcp stream until given prompt (should be valid regex string) catched.
// All ESC-sequences are cutted out.
func (c *SshClient) ReadUntil(waitfor string) (string, error) {
	// Implement handy global timeout, since x/crypto/ssh does not has one :(
	c.reading = true
	defer func() { c.reading = false }()
	time.AfterFunc(time.Second * time.Duration(c.TimeoutGlobal), func() {
		if c.reading {
			c.reading = false
			c.Close()
		}
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
	globalTout := time.After(time.Second * time.Duration(c.TimeoutGlobal))
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

				//result = append(result, tbuf[i])
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

