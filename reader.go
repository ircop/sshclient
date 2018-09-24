package sshclient

import (
	"fmt"
	"regexp"
	"time"
)

// ReadUntil reads tcp stream until given prompt (should be valid regex string) catched.
// All ESC-sequences are cutted out.
func (c *SshClient) ReadUntil(waitfor string) (string, error) {
//fmt.Printf("Reading until '%s'\n", waitfor)
	// Implement handy global timeout, since x/crypto/ssh does not has one :(
	c.mx.Lock()
	c.reading = true
	tout := c.TimeoutGlobal
	c.mx.Unlock()
	defer func() {
		c.mx.Lock()
		c.reading = false
		c.mx.Unlock()
	}()
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


	// escape sequences stuff
	inSequence := false
	lastSeq := ""
	reW, err := regexp.Compile(`^\[\d+D$`)
	if err != nil {
		return c.buf.String(), err
	}
	/////////////////////////

	globalTout := time.After(time.Second * time.Duration(c.TimeoutGlobal))
	for {
		select {
		case <- globalTout:
			return c.buf.String(), fmt.Errorf("Operation timeout reached during read")
		default:
			n, err := c.outPipe.Read(tbuf)
			totalBytes += n

//fmt.Printf("%s", string(tbuf))
			//for i := range tbuf {
			//	fmt.Printf("%s | %d\n", string(tbuf[i]), tbuf[i])
			//}
			if err != nil {
				return c.buf.String(), err
			}

			// TODO: catch '27[XXD' ; this is something like ^W ; remove all until previous \n
			for i := 0; i < totalBytes; i++ {
				//fmt.Printf("%s | %d\n", string(tbuf[i]), tbuf[i])
				// cut \r's
				if tbuf[i] == 13 {
					continue
				}

				// cut out escape sequences
				if tbuf[i] == 27 {
					inSequence = true
					lastSeq = ""
					continue
				}
				if inSequence {
					// 2) 0-?, @-~, ' ' - / === 48-63, 32-47, finish with 64-126
					if tbuf[i] == 91 {
						lastSeq += string(tbuf[i])
						continue
					}
					if tbuf[i] >= 32 && tbuf[i] <= 63 {
						lastSeq += string(tbuf[i])
						// just skip it
						continue
					}
					if tbuf[i] >= 64 && tbuf[i] <= 126 {
						lastSeq += string(tbuf[i])
						// finish sequence
						inSequence = false

						if reW.Match([]byte(lastSeq)) {
							// remove all chars backwards up to first '\n'
							bts := c.buf.Bytes()
							if len(bts) > 0 {
								jj := 0
								for j := len(bts)-1; j >= 0; j-- {
									if bts[j] == '\n' {
										c.buf.Truncate(c.buf.Len()-jj)
										break
									}
									jj++
								}
							}
						}

						lastSeq = ""
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
						// remove next stuff due to valid handling ^W and backspaces:
						// remove last line from buffer
						//lines := strings.Split(c.buf.String(), "\n")
						/*fmt.Printf("LINES:\n")
						for _, l := range lines {
							fmt.Printf("'%s'\n", l)
						}*/

						//lines = lines[:len(lines)-1]
						//c.buf.Reset()
						//c.buf.WriteString(strings.Join(lines, "\n"))
						//c.buf.WriteString("\n")
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

