# sshclient

Simple ssh client, wrapped around x/crypto/ssh.

Allows simple execute commands and wait for prompt or catch something, given as regexp.

Sample usage:

```
  c := sshclient.New(2, "login", "password", `(?msi:(~ \$|#)\s+$)`)
  err := c.Open("10.10.10.40", 22)
	if err != nil {
		panic(err)
	}
	defer c.Close()

	c.GlobalTimeout(5)
  
  // wait for first prompt
  out, err := c.ReadUntil(`(?msi:(~ \$|#)\s+$)`)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", out)
  
  // get ls -l
  err = c.Write("ls -l /")
	if err != nil {
		panic(err)
	}
  
  // wait for prompt again. Output between command and prompt is the 'ls -l' output.
  out, err = c.ReadUntil(`(?msi:(~ \$|#)\s+$)`)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s:\n%s\n", "ls -l", out)
  
  
  // Ooor, you may just call 'Cmd()' - it will write command, catch default prompt (passed to New()), and 
  // return output and error, if any
  out, err = c.Cmd("date")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s:\n%s\n", "date", out)
```
