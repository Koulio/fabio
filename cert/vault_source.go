package cert

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"time"

	"github.com/hashicorp/vault/api"
)

// VaultSource implements a certificate source which loads
// TLS and client authorization certificates from a Vault server.
// The Vault token should be set through the VAULT_TOKEN environment
// variable.
//
// The TLS certificates are updated automatically when Refresh
// is not zero. Refresh cannot be less than one second to prevent
// busy loops.
type VaultSource struct {
	Addr         string
	CertPath     string
	ClientCAPath string
	Refresh      time.Duration

	token string
}

func (s VaultSource) client() (*api.Client, error) {
	c, err := api.NewClient(&api.Config{Address: s.Addr})
	if err != nil {
		return nil, err
	}
	c.SetToken(s.token)
	return c, nil
}

func (s VaultSource) LoadClientCAs() (*x509.CertPool, error) {
	return newCertPool(s.ClientCAPath, s.load)
}

func (s VaultSource) Certificates() chan []tls.Certificate {
	ch := make(chan []tls.Certificate, 1)
	go watch(ch, s.Refresh, s.CertPath, s.load)
	return ch
}

func (s VaultSource) load(path string) (pemBlocks map[string][]byte, err error) {
	pemBlocks = map[string][]byte{}

	// get will read a key=value pair from the secret
	// and store it as <name>-{cert,key}.pem so that
	// they are recognized by the post-processing function
	// which assembles the certificates.
	// The value can be stored either as string or []byte.
	get := func(name, typ string, secret *api.Secret) {
		v := secret.Data[typ]
		if v == nil {
			return
		}

		var b []byte
		switch v.(type) {
		case string:
			b = []byte(v.(string))
		case []byte:
			b = v.([]byte)
		default:
			log.Printf("[WARN] cert: key %s has type %T", name, v)
			return
		}

		pemBlocks[name+"-"+typ+".pem"] = []byte(b)
	}

	c, err := s.client()
	if err != nil {
		return nil, err
	}

	// get the subkeys under 'path'.
	// Each subkey refers to a certificate.
	certs, err := c.Logical().List(path)
	if certs == nil || err != nil {
		return nil, err
	}

	for _, s := range certs.Data["keys"].([]interface{}) {
		name := s.(string)
		p := path + "/" + name
		secret, err := c.Logical().Read(p)
		if err != nil {
			log.Printf("[WARN] cert: Failed to read %s from Vault: %s", p, err)
			continue
		}
		get(name, "cert", secret)
		get(name, "key", secret)
	}

	return pemBlocks, nil
}
