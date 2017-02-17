package ldap

import (
	"crypto/tls"
	"sync"

	"gopkg.in/ldap.v2"

	"github.com/hailooss/service/config"
)

type Conn struct {
	mu sync.RWMutex
	*ldap.Conn

	configHash string

	network string
	host    string
	dnBase  string
}

// Connect creates a new connection for talking to ldap
func Connect() (*ldap.Conn, error) {
	// Load config
	network := config.AtPath("hailo", "service", "ldap", "network").AsString("tcp")
	host := config.AtPath("hailo", "service", "ldap", "host").AsString("")

	// Create connection
	conn, err := ldap.DialTLS(network, host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}

	return conn, nil
}
