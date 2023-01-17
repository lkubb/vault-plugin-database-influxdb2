package influxdb2

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/hashicorp/go-rootcerts"
	"github.com/hashicorp/go-secure-stdlib/tlsutil"
	"github.com/hashicorp/vault/sdk/database/helper/connutil"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/domain"
	"github.com/mitchellh/mapstructure"
	"net"
	"strconv"
	"sync"
	"time"
)

type influxDB2ConnectionProducer struct {
	Host         string `json:"host" structs:"host" mapstructure:"host"`
	Port         int    `json:"port" structs:"port" mapstructure:"port"`
	Organization string `json:"organization" structs:"organization" mapstructure:"organization"`
	// We need to use "password" as config name, otherwise reading the connection leaks the token
	Token             string      `json:"password" structs:"password" mapstructure:"password"`
	TLS               bool        `json:"tls" structs:"tls" mapstructure:"tls"`
	InsecureTLS       bool        `json:"insecure_tls" structs:"insecure_tls" mapstructure:"insecure_tls"`
	CACert            string      `json:"ca_cert" structs:"ca_cert" mapstructure:"ca_cert"`
	CAPath            string      `json:"ca_path" structs:"ca_path" mapstructure:"ca_path"`
	ClientCert        string      `json:"client_cert" structs:"client_cert" mapstructure:"client_cert"`
	ClientKey         string      `json:"client_key" structs:"client_key" mapstructure:"client_key"`
	TLSMinVersion     string      `json:"tls_min_version" structs:"tls_min_version" mapstructure:"tls_min_version"`
	ConnectTimeoutRaw interface{} `json:"connect_timeout" structs:"connect_timeout" mapstructure:"connect_timeout"`

	connectTimeout time.Duration
	rawConfig      map[string]interface{}

	Initialized bool
	Type        string
	client      influxdb2.Client
	sync.Mutex
}

func (c *influxDB2ConnectionProducer) Init(ctx context.Context, conf map[string]interface{}, verifyConnection bool) (map[string]interface{}, error) {
	c.Lock()
	defer c.Unlock()

	// Rotating the root credentials otherwise returns
	// unable to rotate root credentials: no username in configuration
	conf["username"] = "token"
	c.rawConfig = conf

	err := mapstructure.WeakDecode(conf, c)
	if err != nil {
		return nil, err
	}

	if c.ConnectTimeoutRaw == nil {
		c.ConnectTimeoutRaw = "5s"
	}
	if c.Port == 0 {
		c.Port = 8086
	}
	c.connectTimeout, err = parseutil.ParseDurationSecond(c.ConnectTimeoutRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid connect_timeout: %w", err)
	}

	switch {
	case len(c.Host) == 0:
		return nil, fmt.Errorf("host cannot be empty")
	case len(c.Organization) == 0:
		return nil, fmt.Errorf("organization cannot be empty")
	case len(c.Token) == 0:
		return nil, fmt.Errorf("token cannot be empty")
	}

	c.Initialized = true

	if verifyConnection {
		if _, err := c.Connection(ctx); err != nil {
			return nil, fmt.Errorf("error verifying connection: %w", err)
		}
	}

	return conf, nil
}

func (c *influxDB2ConnectionProducer) Close() error {
	c.Lock()
	defer c.Unlock()

	if c.client != nil {
		c.client.Close()
	}

	c.client = nil

	return nil
}

func (c *influxDB2ConnectionProducer) Connection(ctx context.Context) (interface{}, error) {
	if !c.Initialized {
		return nil, connutil.ErrNotInitialized
	}

	if c.client != nil {
		return c.client, nil
	}

	client, err := c.buildClient(ctx)
	if err != nil {
		return nil, err
	}

	c.client = client
	return client, nil
}

func (c *influxDB2ConnectionProducer) buildClient(ctx context.Context) (influxdb2.Client, error) {
	var client influxdb2.Client
	var scheme string
	options := influxdb2.DefaultOptions()
	options.SetHTTPRequestTimeout(uint(c.connectTimeout / time.Second))

	if c.TLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: c.InsecureTLS,
		}
		if c.ClientCert != "" && c.ClientKey != "" {
			clientCertificate, err := tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
			if err != nil {
				return nil, err
			}
			tlsConfig.Certificates = append(tlsConfig.Certificates, clientCertificate)
		}
		if c.CACert != "" || c.CAPath != "" {
			rootConfig := &rootcerts.Config{
				CAFile: c.CACert,
				CAPath: c.CAPath,
			}
			if err := rootcerts.ConfigureTLS(tlsConfig, rootConfig); err != nil {
				return nil, err
			}
		}
		if c.TLSMinVersion != "" {
			var ok bool
			tlsConfig.MinVersion, ok = tlsutil.TLSLookup[c.TLSMinVersion]
			if !ok {
				return nil, fmt.Errorf("invalid 'tls_min_version' in config")
			}
		} else {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
		options.SetTLSConfig(tlsConfig)
		scheme = "https://"
	} else {
		scheme = "http://"
	}
	client = influxdb2.NewClientWithOptions(scheme+net.JoinHostPort(c.Host, strconv.Itoa(c.Port)), c.Token, options)

	// Check server status
	_, err := client.Ping(ctx)
	if err != nil {
		return nil, fmt.Errorf("Error checking cluster status: %w", err)
	}

	// Verify necessary authorizations
	err = checkTokenAuthorizations(ctx, client, c.Token)
	if err != nil {
		return nil, fmt.Errorf("Error inquiring if the provided token posesses the required authorizations: %w", err)
	}

	return client, nil
}

func checkTokenAuthorizations(ctx context.Context, client influxdb2.Client, token string) error {
	rootUser, err := client.UsersAPI().Me(ctx)
	if err != nil {
		return fmt.Errorf("Failed to lookup root user: %w", err)
	}

	rootAuths, err := client.AuthorizationsAPI().FindAuthorizationsByUserID(ctx, *rootUser.Id)
	if err != nil {
		return fmt.Errorf("Failed to lookup root authorizations: %w", err)
	}

	var rootAuth *domain.Authorization
	for _, auth := range *rootAuths {
		if *auth.Token == token {
			rootAuth = &auth
		}
	}
	if rootAuth == nil {
		return fmt.Errorf("Failed to find authorization")
	}

	checkAuthRead := false
	checkAuthWrite := false
	checkOrgRead := false
	checkOrgWrite := false
	checkUserRead := false
	checkUserWrite := false

	for _, perm := range *rootAuth.Permissions {
		// Check required permissions.
		// They must not be scoped to a specific resource or organization.
		if !(perm.Resource.Id == nil && perm.Resource.OrgID == nil) {
			continue
		}
		if perm.Action == "read" {
			switch perm.Resource.Type {
			// this does not really need to be checked since it
			// is a prerequisite to get to here
			case "authorizations":
				checkAuthRead = true
			case "orgs":
				checkOrgRead = true
			case "users":
				checkUserRead = true
			}
		} else if perm.Action == "write" {
			switch perm.Resource.Type {
			case "authorizations":
				checkAuthWrite = true
			case "orgs":
				checkOrgWrite = true
			case "users":
				checkUserWrite = true
			}
		}
	}

	if checkAuthRead && checkAuthWrite && checkOrgRead && checkOrgWrite && checkUserRead && checkUserWrite {
		return nil
	}
	return fmt.Errorf("The provided token is missing required authorizations: read/auth %t read/org %t read/user %t write/auth %t write/org %t write/user %t", checkAuthRead, checkOrgRead, checkUserRead, checkAuthWrite, checkOrgWrite, checkUserWrite)
}

func (c *influxDB2ConnectionProducer) secretValues() map[string]interface{} {
	return map[string]interface{}{
		c.Token:     "[token]",
		c.ClientKey: "[client_key]",
	}
}
