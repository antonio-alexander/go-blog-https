package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/antonio-alexander/go-blog-https/internal/data"

	"github.com/pkg/errors"
)

type client struct {
	*http.Client
	address string
}

func New() interface {
	HelloWorld() (*data.Message, error)
	Configure(*Configuration) error
} {
	return &client{
		Client: &http.Client{
			Transport: &http.Transport{},
		},
	}
}

func (c *client) doRequest(uri, method string, data []byte) ([]byte, int, error) {
	request, err := http.NewRequest(method, uri, bytes.NewBuffer(data))
	if err != nil {
		return nil, -1, err
	}
	response, err := c.Client.Do(request)
	if err != nil {
		return nil, -1, err
	}
	data, err = io.ReadAll(response.Body)
	defer response.Body.Close()
	if err != nil {
		return nil, -1, err
	}
	return data, response.StatusCode, nil
}

func (c *client) Configure(config *Configuration) error {
	c.address = config.Address + ":" + config.Port
	if config.Port == "" {
		c.address = config.Address
	}
	switch {
	default:
		c.address = "http://" + c.address
	case config.HttpsEnabled:
		c.address = "https://" + c.address
		tlsConfig, err := getTlsConfig(config)
		if err != nil {
			return err
		}
		c.Client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
	c.Client.Timeout = config.Timeout
	return nil
}

func (c *client) HelloWorld() (*data.Message, error) {
	uri := fmt.Sprintf("%s", c.address)
	bytes, statusCode, err := c.doRequest(uri, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, errors.Errorf("unexpected status code: %d", statusCode)
	}
	message := &data.Message{}
	if err := json.Unmarshal(bytes, message); err != nil {
		return nil, err
	}
	return message, nil
}
