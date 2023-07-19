package internal

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/antonio-alexander/go-blog-https/internal/client"
)

func Main(pwd string, args []string, envs map[string]string, osSignal chan os.Signal) error {
	//print version
	fmt.Printf("go-blog-https %s(%s@%s)\n", Version, GitCommit, GitBranch)

	//create client and configure
	c := client.New()
	config := client.NewConfiguration()
	if len(args) > 0 {
		config.FromCli(args)
	}
	config.FromEnvs(envs)
	c.Configure(config)

	//attempt hello-world
	message, err := c.HelloWorld()
	if err != nil {
		return err
	}
	bytes, err := json.MarshalIndent(message, "", " ")
	if err != nil {
		return err
	}
	fmt.Println(string(bytes))
	return nil
}
