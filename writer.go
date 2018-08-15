package sshclient

// Write command/text to ssh pipe
func (c *SshClient) Write(bytes []byte) error {
	bytes = append(bytes, '\n')
	_, err := c.inPipe.Write(bytes)
	if err != nil {
		return err
	}

	return nil
}

// WriteRaw is the same as write, but without adding '\n' at end of string
func (c *SshClient) WriteRaw(bytes []byte) error {
	_, err := c.inPipe.Write(bytes)
	if err != nil {
		return err
	}

	return nil
}

// Cmd is simple wrapper for "send command + read output until default prompt catched".
// Returns output and error if any.
func (c *SshClient) Cmd(cmd string) (string, error) {
	if err := c.Write([]byte(cmd)); err != nil {
		return "", err
	}

	return c.ReadUntil(c.prompt)
}