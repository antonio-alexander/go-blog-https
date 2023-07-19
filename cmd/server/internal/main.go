package internal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/antonio-alexander/go-blog-https/internal/data"
	"github.com/antonio-alexander/go-blog-https/internal/server"
)

func Main(pwd string, args []string, envs map[string]string, osSignal chan os.Signal) error {
	var wg sync.WaitGroup

	//print version
	fmt.Printf("go-blog-https v%s(%s@%s)\n", Version, GitCommit, GitBranch)

	//get configuration
	config := server.NewConfiguration()
	config.FromEnvs(envs)
	server := server.New()
	if err := server.Configure(config); err != nil {
		return err
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		//KIM: this is a bad practice, but only done for simplification
		bytes, _ := json.Marshal(&data.Message{Message: "Hello, World!"})
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(bytes)
	})

	//start server
	fmt.Printf("starting web server on %s:%s\n", config.Address, config.Port)
	chErr := make(chan error, 1)
	defer close(chErr)
	stopped := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(stopped)

		switch {
		default:
			if err := server.ListenAndServe(); err != nil {
				chErr <- err
			}
		case config.HttpsEnabled:
			if err := server.ListenAndServeTLS(config.CertFile, config.KeyFile); err != nil {
				chErr <- err
			}
		}
	}()
	select {
	case <-stopped:
	case err := <-chErr:
		return err
	case <-osSignal:
		return server.Close()
	}
	wg.Wait()
	return nil
}
