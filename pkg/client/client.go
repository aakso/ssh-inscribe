package client

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/aakso/ssh-inscribe/pkg/server/signapi/objects"
	"github.com/bgentry/speakeasy"
	"github.com/go-resty/resty"
	"github.com/pkg/errors"
	"github.com/skratchdot/open-golang/open"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	CredentialTypeUser     = "username"
	CredentialTypePassword = "password"
	CredentialTypePin      = "pin"

	CurrentApiVersion = "v1"

	// Comment to use for keys on agent
	AgentComment = "ssh-inscribe managed"

	FederatedAuthenticatorPollInterval = 3
)

const spinner = `\|/-`

type ignoreRedirects struct{}

func (ir *ignoreRedirects) Apply(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

type Client struct {
	Config          *Config
	rest            *resty.Client
	restSRV         *resty.SRVRecord
	agentClient     agent.Agent
	agentConn       net.Conn
	credentialInput func(name, realm, credentialType string) []byte

	ca             ssh.PublicKey
	userPrivateKey interface{}
	userCert       *ssh.Certificate
	signerToken    []byte
}

func (c *Client) getCredential(name, realm, credentialType string) []byte {
	if c.credentialInput == nil {
		c.credentialInput = interactiveCredentialsPrompt
	}
	return c.credentialInput(name, realm, credentialType)
}

func (c *Client) AddCA() error {
	if err := c.initREST(); err != nil {
		return errors.Wrap(err, "could not add ca")
	}
	if err := c.authenticate(); err != nil {
		return errors.Wrap(err, "could not add ca")
	}
	return c.addCAKey()
}

func (c *Client) GetCA() (ssh.PublicKey, error) {
	if err := c.initREST(); err != nil {
		return nil, errors.Wrap(err, "could not get ca")
	}
	if err := c.discoverCA(); err != nil {
		return nil, errors.Wrap(err, "could not get ca")
	}
	return c.ca, nil
}

func (c *Client) GetAuthenticators() ([]objects.DiscoverResult, error) {
	if err := c.initREST(); err != nil {
		return nil, errors.Wrap(err, "could not get ca")
	}
	return c.discoverAuthenticators()
}

func (c *Client) Logout() error {
	if err := c.initREST(); err != nil {
		return errors.Wrap(err, "could not logout")
	}
	if err := c.discoverCA(); err != nil {
		return errors.Wrap(err, "could not logout")
	}
	if c.Config.UseAgent {
		if err := c.connectAgent(); err != nil {
			return errors.Wrap(err, "could not logout")
		}
		if err := c.deleteCertsFromAgent(); err != nil {
			return errors.Wrap(err, "could not logout")
		}
	}
	return nil
}

func (c *Client) Login() error {
	if err := c.initREST(); err != nil {
		return errors.Wrap(err, "could not login")
	}
	if err := c.discoverCA(); err != nil {
		return errors.Wrap(err, "could not login")
	}
	if c.Config.UseAgent {
		if err := c.connectAgent(); err != nil {
			return errors.Wrap(err, "could not login")
		}
		if err := c.discoverCertFromAgent(); err != nil {
			return errors.Wrap(err, "could not login")
		}
		if !c.Config.AlwaysRenew && c.userCert != nil {
			Log.Debug("certificate found on agent and already valid")
			return nil
		}
	}
	if c.Config.IdentityFile != "" && !c.Config.GenerateKeypair {
		if err := c.discoverIdentityFile(); err != nil {
			return errors.Wrap(err, "could not login")
		}
		if !c.Config.AlwaysRenew && c.userCert != nil {
			Log.Debug("certificate found from file and already valid")
			return nil
		}
	}
	// Generate ad-hoc keypair in case no private key is provided
	if c.Config.GenerateKeypair && c.userPrivateKey == nil {
		if err := c.generate(); err != nil {
			return errors.Wrap(err, "could not login")
		}
	}
	if c.userPrivateKey == nil {
		return errors.New("could not continue. No private key")
	}
	if err := c.authenticate(); err != nil {
		return errors.Wrap(err, "could not login")
	}
	if err := c.sign(); err != nil {
		return errors.Wrap(err, "could not login")
	}
	if c.Config.UseAgent {
		if err := c.storeInAgent(); err != nil {
			return errors.Wrap(err, "could not store certificate to an agent")
		}
	}
	if c.Config.IdentityFile != "" && c.Config.WriteCert {
		if err := c.storeInFile(); err != nil {
			return errors.Wrap(err, "could not store certificate to a file")
		}
	}
	if !c.Config.UseAgent && !c.Config.WriteCert {
		fmt.Printf("%s", ssh.MarshalAuthorizedKey(c.userCert))
	}
	if !c.Config.Quiet {
		c.printCertificate()
	}
	return nil
}

// Add CA key to server from file
func (c *Client) addCAKey() error {
	log := Log.WithField("action", "addCAKey")
	log.Debug("reading ca key file")
	content, err := ioutil.ReadFile(c.Config.CAKeyFile)
	if err != nil {
		return errors.Wrap(err, "could not open ca key file")
	}
	dec, _ := pem.Decode(content)
	if dec == nil {
		return errors.New("could not parse ca key file")
	}
	if strings.Contains(dec.Headers["Proc-Type"], "ENCRYPTED") {
		secret := c.getCredential("ca private key", c.Config.CAKeyFile, CredentialTypePassword)
		dec.Bytes, err = x509.DecryptPEMBlock(dec, secret)
		if err != nil {
			return errors.Wrap(err, "could not decrypt ca key")
		}
		delete(dec.Headers, "Proc-Type")
		content = pem.EncodeToMemory(dec)
	} else {
		log.Warn("WARNING: CA Key file is unencrypted!")
	}
	log.Debug("sending ca key to the server")
	res, err := c.newReq().
		SetHeader("X-Auth", fmt.Sprintf("Bearer %s", c.signerToken)).
		SetBody(content).
		Post(c.urlFor("ca"))
	if err != nil {
		return errors.Wrap(err, "could not send key")
	}
	if res.StatusCode() != http.StatusAccepted {
		return errors.Errorf("could not send key, got code %d and message: %s", res.StatusCode(), res.Body())
	}
	log.Debug("sent ca key to the server")
	return nil
}

// Generate ad-hoc keypair
// TODO: add ec key support
func (c *Client) generate() error {
	log := Log.WithField("action", "generate")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return errors.Wrap(err, "could not generate key")
	}
	c.userPrivateKey = key
	log.Debug("generated keypair")
	return nil
}

// Store signed key to a ssh-agent, remove all other instances of certificates
// signed by the CA
func (c *Client) storeInAgent() error {
	log := Log.WithField("action", "storeInAgent")
	log.Debug("cleaning up old certificates")
	err := c.deleteCertsFromAgent()
	if err != nil {
		return err
	}

	// Find out if our private key is already in the agent. In that case let us not
	// add time constraint to it
	keyInAgent := false
	err = iterAgentKeys(c.agentClient, func(key ssh.PublicKey, comment string) error {
		if bytes.Equal(key.Marshal(), c.userCert.Key.Marshal()) {
			log.Debug("private key already in agent")
			keyInAgent = true
		}
		return nil
	})
	if err != nil {
		return errors.Wrap(err, "could not add to agent")
	}

	var lifetime uint32
	if c.userCert.ValidBefore != 0 {
		lifetime = uint32(time.Until(time.Unix(int64(c.userCert.ValidBefore), 0)).Seconds())
	}
	addedKey := agent.AddedKey{
		PrivateKey:   c.userPrivateKey,
		Certificate:  c.userCert,
		Comment:      AgentComment,
		LifetimeSecs: lifetime,
	}
	if err := c.agentClient.Add(addedKey); err != nil {
		return errors.Wrap(err, "could not add to agent")
	}
	log.WithField("keyid", c.userCert.KeyId).
		WithField("lifetime_secs", addedKey.LifetimeSecs).Debug("added certificate")

	if !keyInAgent {
		addedKey = agent.AddedKey{
			PrivateKey:   c.userPrivateKey,
			Comment:      AgentComment,
			LifetimeSecs: lifetime,
		}
		if err := c.agentClient.Add(addedKey); err != nil {
			return errors.Wrap(err, "could not add to agent")
		}
		log.WithField("lifetime_secs", addedKey.LifetimeSecs).Debug("added private key")
	}
	return nil
}
func (c *Client) storeInFile() error {
	log := Log.WithField("action", "storeInFile")
	certFile := c.Config.IdentityFile + "-cert.pub"
	if abs, _ := filepath.Abs(certFile); abs != "" {
		certFile = abs
	}
	log.WithField("file", certFile).Debug("saving to file")
	fh, err := os.Create(certFile)
	if err != nil {
		return errors.Wrap(err, "could not save to file")
	}
	defer fh.Close()
	if _, err := fh.Write(ssh.MarshalAuthorizedKey(c.userCert)); err != nil {
		return errors.Wrap(err, "could not save to file")
	}
	fmt.Println(certFile)
	// If we have been requested to generate a keypair, also save it
	if c.Config.GenerateKeypair {
		privFile := c.Config.IdentityFile
		if abs, _ := filepath.Abs(privFile); abs != "" {
			privFile = abs
		}
		// Save private
		log.WithField("file", privFile).Debug("saving to file")
		rsaKey, _ := c.userPrivateKey.(*rsa.PrivateKey)
		if rsaKey == nil {
			return errors.New("not a rsa key")
		}
		pemBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		}
		fhPriv, err := os.OpenFile(c.Config.IdentityFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return errors.Wrap(err, "could not save to file")
		}
		defer fhPriv.Close()
		pem.Encode(fhPriv, pemBlock)
		fmt.Println(privFile)
		log.WithField("file", privFile).Debug("saved to file")

		// Save public
		pubFile := c.Config.IdentityFile + ".pub"
		if abs, _ := filepath.Abs(pubFile); abs != "" {
			pubFile = abs
		}
		log.WithField("file", pubFile).Debug("saving to file")
		fhPub, err := os.Create(pubFile)
		if err != nil {
			return errors.Wrap(err, "could not save to file")
		}
		defer fhPub.Close()
		pub, err := ssh.NewPublicKey(rsaKey.Public())
		if err != nil {
			return errors.Wrap(err, "unexpected error")
		}
		fhPub.Write(ssh.MarshalAuthorizedKey(pub))
		fmt.Println(pubFile)
		log.WithField("file", pubFile).Debug("saved to file")
	}
	log.WithField("file", certFile).Debug("saved to file")
	return nil
}

// Request signed certificate from the server
func (c *Client) sign() error {
	log := Log.WithField("action", "sign")
	log.Debug("requesting certificate")
	signer, err := ssh.NewSignerFromKey(c.userPrivateKey)
	if err != nil {
		return errors.Wrap(err, "unexpected error")
	}
	req := c.newReq().
		SetHeader("X-Auth", fmt.Sprintf("Bearer %s", c.signerToken)).
		SetBody(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	if c.Config.CertLifetime != 0 {
		expires := time.Now().Add(c.Config.CertLifetime).Format(time.RFC3339)
		req.SetQueryParam("expires", expires)
	}
	if c.Config.IncludePrincipals != "" {
		req.SetQueryParam("include_principals", c.Config.IncludePrincipals)
	}
	if c.Config.ExcludePrincipals != "" {
		req.SetQueryParam("exclude_principals", c.Config.ExcludePrincipals)
	}

	res, err := req.Post(c.urlFor("sign"))
	if err != nil {
		return errors.Wrap(err, "could not sign")
	}
	if res.StatusCode() != http.StatusOK {
		return errors.Errorf("could not sign got code %d and message: %s", res.StatusCode(), res.Body())
	}

	key, _, _, _, err := ssh.ParseAuthorizedKey(res.Body())
	if err != nil {
		return errors.Wrap(err, "could not parse certificate")
	}
	cert, _ := key.(*ssh.Certificate)
	if cert == nil {
		return errors.Errorf("could not parse certificate. Unknown type %T", key)
	}
	log.WithField("keyid", cert.KeyId).Debug("certificate received")
	c.userCert = cert
	return nil
}

func (c *Client) authenticateFederated(authName, authRealm string) error {
	log := Log.WithField("action", "authenticateFederated").
		WithField("authenticator", authName)
	log.Debug("making initial authentication request to get the auth url")
	initial := true
	req := c.newReq()
	for i := 0; true; i++ {
		if c.signerToken != nil {
			req.SetHeader("X-Auth", fmt.Sprintf("Bearer %s", c.signerToken))
		}
		res, err := req.Post(c.urlFor("auth/" + authName))
		if err != nil {
			return errors.Wrap(err, "could not authenticate")
		}
		switch res.StatusCode() {
		case http.StatusSeeOther:
			c.signerToken = res.Body()
			if initial {
				url := res.Header().Get("Location")
				openFederatedAuthURL(url)
			}
			fmt.Printf("\rWaiting for authentication to complete for %q (%s) %s ",
				authName,
				authRealm,
				string(spinner[i%4]))
			time.Sleep(FederatedAuthenticatorPollInterval * time.Second)
			initial = false
		case http.StatusOK:
			fmt.Println()
			c.signerToken = res.Body()
			log.Debug("authentication successful")
			return nil
		case http.StatusUnauthorized:
			return errors.New("authentication failed")
		default:
			return errors.Errorf("unknown federated auth response: %d", res.StatusCode())
		}
	}
	return errors.New("could not authenticate")
}

func (c *Client) discoverAuthenticators() ([]objects.DiscoverResult, error) {
	log := Log.WithField("action", "discoverAuthenticators")
	log.Debug("discovering authenticators")
	res, err := c.newReq().
		SetResult([]objects.DiscoverResult{}).
		Get(c.urlFor("auth"))
	if err != nil {
		return nil, errors.Wrap(err, "could not discover authenticators")
	}
	discoverResult, _ := res.Result().(*[]objects.DiscoverResult)
	if discoverResult == nil {
		return nil, errors.New("could not parse auth discovery result")
	}
	return *discoverResult, nil
}

// Do authentication discovery and login
func (c *Client) authenticate() error {
	log := Log.WithField("action", "authenticate")
	log.Debug("discovering authenticators")

	discoverResult, err := c.discoverAuthenticators()
	if err != nil {
		return err
	}

	// Make the final authenticator list based on user request or the
	// default setting in server configuration
	var (
		defaultAuthenticators []objects.DiscoverResult
		finalAuthenticators   []objects.DiscoverResult
	)
	availableAuthenticators := map[string]objects.DiscoverResult{}
	for _, au := range discoverResult {
		if au.Default {
			defaultAuthenticators = append(defaultAuthenticators, au)
		}
		availableAuthenticators[au.AuthenticatorName] = au
	}
	switch {
	case len(c.Config.LoginAuthEndpoints) > 0:
		for _, v := range c.Config.LoginAuthEndpoints {
			if au, ok := availableAuthenticators[v]; !ok {
				return errors.Errorf("unknown auth endpoint name: %s", v)
			} else {
				finalAuthenticators = append(finalAuthenticators, au)
			}
		}
	case len(defaultAuthenticators) > 0:
		finalAuthenticators = defaultAuthenticators
	case len(discoverResult) > 0:
		finalAuthenticators = append(finalAuthenticators, discoverResult[0])
	default:
		return errors.New("cannot continue, no authenticators returned from the server")
	}
	log.WithField("authenticator_list", finalAuthenticators).Debug("begin authentication")

	for _, au := range finalAuthenticators {
		var user, secret string
		switch au.AuthenticatorCredentialType {
		case auth.CredentialUserPassword:
			user = string(c.getCredential(au.AuthenticatorName, au.AuthenticatorRealm, CredentialTypeUser))
			secret = string(c.getCredential(au.AuthenticatorName, au.AuthenticatorRealm, CredentialTypePassword))
		case auth.CredentialPin:
			secret = string(c.getCredential(au.AuthenticatorName, au.AuthenticatorRealm, CredentialTypePin))
		case auth.CredentialFederated:
			c.authenticateFederated(au.AuthenticatorName, au.AuthenticatorRealm)
			continue
		default:
			return errors.Errorf("unknown credential type %s", au.AuthenticatorCredentialType)
		}
		log.WithField("authenticator", au.AuthenticatorName).Debug("authenticating")
		// Send Credentials
		req := c.newReq().SetBasicAuth(user, secret)
		if c.signerToken != nil {
			req.SetHeader("X-Auth", fmt.Sprintf("Bearer %s", c.signerToken))
		}
		res, err := req.Post(c.urlFor("auth/" + au.AuthenticatorName))
		if err != nil {
			return errors.Wrap(err, "could not authenticate")
		}
		if res.StatusCode() != http.StatusOK {
			return errors.New("authentication failed")
		}
		c.signerToken = res.Body()
		log.WithField("authenticator", au.AuthenticatorName).Debug("authentication successful")
	}
	return nil
}

// Discover users private key and certificate from file
func (c *Client) discoverIdentityFile() error {
	log := Log.WithField("action", "discoverIdentityFile")
	log.Debug("reading identity file")
	content, err := ioutil.ReadFile(c.Config.IdentityFile)
	if err != nil {
		return errors.Wrap(err, "could not open identity file")
	}
	dec, _ := pem.Decode(content)
	if dec == nil {
		return errors.New("could not parse identity file")
	}
	if strings.Contains(dec.Headers["Proc-Type"], "ENCRYPTED") {
		log.Debug("encrypted identity file")
		secret := c.getCredential("private key", c.Config.IdentityFile, CredentialTypePassword)
		dec.Bytes, err = x509.DecryptPEMBlock(dec, secret)
		if err != nil {
			return errors.Wrap(err, "could not decrypt private key")
		}
		delete(dec.Headers, "Proc-Type")
		content = pem.EncodeToMemory(dec)
	}
	key, err := ssh.ParseRawPrivateKey(content)
	if err != nil {
		return errors.Wrap(err, "could not parse private key")
	}
	c.userPrivateKey = key
	log.Debug("parsed identity file")

	// Certificate
	content, err = ioutil.ReadFile(c.Config.IdentityFile + "-cert.pub")
	if os.IsNotExist(err) {
		log.Debug("no certificate file found")
		return nil
	} else if err != nil {
		return errors.Wrap(err, "could not open certificate file")
	}
	log.Debug("found certificate")

	parsed, _, _, _, err := ssh.ParseAuthorizedKey(content)
	cert, _ := parsed.(*ssh.Certificate)
	if cert == nil {
		return errors.New("could not parse certificate")
	}
	if !shallowCertChecker(cert, c.ca) {
		log.WithField("keyid", cert.KeyId).Debug("invalid or expired certificate, skipping")
		return nil
	}
	log.WithField("keyid", cert.KeyId).Debug("parsed certificate")
	c.userCert = cert
	return nil
}

// Discover signing ca from remote server
func (c *Client) discoverCA() error {
	log := Log.WithField("action", "discoverCA")
	if c.ca != nil {
		return nil
	}
	log.Debug("discovering ca")
	res, err := c.newReq().Get(c.urlFor("ca"))
	if err != nil {
		return errors.Wrap(err, "could not discover CA")
	}
	if res.StatusCode() != http.StatusOK {
		return errors.Errorf("could not discover CA, got code %d and message: %s", res.StatusCode(), res.Body())
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(res.Body())
	if err != nil {
		return errors.Wrap(err, "could not parse CA key")
	}
	log.WithField("fingerprint", ssh.FingerprintSHA256(key)).Debug("discovered ca")
	c.ca = key
	return nil
}

// Connect to ssh-agent if possible
func (c *Client) connectAgent() error {
	sock := os.Getenv("SSH_AUTH_SOCK")
	Log.WithField("socket", sock).Debug("connecting to ssh-agent")
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return errors.Wrap(err, "could not connect to ssh-agent")
	}
	c.agentConn = conn
	agentClient := agent.NewClient(c.agentConn)
	if _, err := agentClient.List(); err != nil {
		return errors.Wrap(err, "could not connect to ssh-agent")
	}
	c.agentClient = agentClient
	Log.WithField("socket", sock).Debug("connected to ssh-agent")
	return nil
}

// Discover certificates from agent
func (c *Client) discoverCertFromAgent() error {
	log := Log.WithField("action", "discoverCertFromAgent")
	log.Debug("discovering certificates from the agent")
	err := iterAgentKeys(c.agentClient, func(key ssh.PublicKey, comment string) error {
		cert, _ := key.(*ssh.Certificate)
		if cert == nil {
			return nil
		}
		log := log.WithField("keyid", cert.KeyId)
		log.Debug("checking cert")
		if !shallowCertChecker(cert, c.ca) {
			log.Debug("skipping cert, not valid")
			return nil
		}
		c.userCert = cert
		log.Debug("found cert")
		return nil
	})
	if err != nil {
		return errors.Wrap(err, "could not discover certificate")
	}
	return nil
}

func (c *Client) deleteCertsFromAgent() error {
	log := Log.WithField("action", "deleteCertsFromAgent")
	log.Debug("deleting certificates from the agent")
	err := iterAgentKeys(c.agentClient, func(key ssh.PublicKey, comment string) error {
		cert, _ := key.(*ssh.Certificate)
		if cert == nil {
			return nil
		}
		if !bytes.Equal(cert.SignatureKey.Marshal(), c.ca.Marshal()) {
			return nil
		}
		log.WithField("keyid", cert.KeyId).Debug("removing certificate")
		if err := c.agentClient.Remove(cert); err != nil {
			return errors.Wrap(err, "could not remove from agent")
		}
		// Also remove key for the certificate if it is managed by us
		err := iterAgentKeys(c.agentClient, func(key ssh.PublicKey, comment string) error {
			if bytes.Equal(key.Marshal(), cert.Key.Marshal()) && comment == AgentComment {
				if err := c.agentClient.Remove(key); err != nil {
					return err
				}
				log.WithField("key", ssh.FingerprintSHA256(key)).Debug("removing associated key")
			}
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return errors.Wrap(err, "could not delete certs")
	}
	return nil
}

func (c *Client) initREST() error {
	log := Log.WithField("action", "initREST")
	if c.Config.URL == "" {
		return errors.New("empty server URL")
	}
	parsed, err := url.Parse(c.Config.URL)
	if err != nil {
		errors.Wrap(err, "cannot parse url")
	}
	if c.Config.Retries < 0 {
		return errors.New("retries cannot be negative")
	}
	rest := resty.New().
		SetRESTMode().
		SetDisableWarn(true).
		SetHostURL(c.Config.URL).
		SetTimeout(c.Config.Timeout).
		SetRetryCount(int(c.Config.Retries)).
		SetLogger(ioutil.Discard).
		SetRedirectPolicy(&ignoreRedirects{})

	if parsed.Scheme == "https" {
		rest.SetScheme("https")
		rest.SetTLSClientConfig(&tls.Config{
			ServerName:         parsed.Hostname(),
			InsecureSkipVerify: c.Config.Insecure,
		})
	} else {
		rest.SetScheme("http")
		log.Warn("You should really not use unencrypted connection")
	}

	if name, _, err := net.LookupSRV(parsed.Scheme, "tcp", parsed.Hostname()); err == nil {
		c.restSRV = &resty.SRVRecord{
			Service: parsed.Scheme,
			Domain:  parsed.Hostname(),
		}
		log.WithField("SRV", name).Debug("discovering with SRV records")
	}

	rest.Header.Set("User-Agent", "ssh-inscribe")
	if c.Config.Debug {
		rest.SetDebug(true).
			SetLogger(os.Stderr)
	}
	c.rest = rest
	return nil
}

func (c *Client) printCertificate() {
	validFrom := time.Unix(int64(c.userCert.ValidAfter), 0)
	validTo := time.Unix(int64(c.userCert.ValidBefore), 0)
	fmt.Print("CERT DETAILS:")
	fmt.Printf("\n%20s: %s (%s)", "Fingerprint",
		ssh.FingerprintSHA256(c.userCert.Key),
		ssh.FingerprintLegacyMD5(c.userCert.Key))
	fmt.Printf("\n%20s: %s (%s)", "CA Fingerprint",
		ssh.FingerprintSHA256(c.ca),
		ssh.FingerprintLegacyMD5(c.ca))
	fmt.Printf("\n%20s: %s", "KeyId", c.userCert.KeyId)
	fmt.Printf("\n%20s: %s", "Valid from", validFrom)
	fmt.Printf("\n%20s: %s", "Valid to", validTo)
	if validTo.After(time.Now()) {
		fmt.Printf(" (expires in %s)", validTo.Sub(time.Now()))
	}
	fmt.Printf("\n%20s:", "Principals")
	for _, p := range c.userCert.ValidPrincipals {
		fmt.Printf("\n%20s  %s", " ", p)
	}
	fmt.Printf("\n%20s:", "Critical Options")
	for k, v := range c.userCert.CriticalOptions {
		fmt.Printf("\n%20s  %s %s", " ", k, v)
	}
	fmt.Printf("\n%20s:", "Extensions")
	for k, v := range c.userCert.Extensions {
		fmt.Printf("\n%20s  %s %s", " ", k, v)
	}
	fmt.Println()
}

func (c *Client) newReq() *resty.Request {
	r := c.rest.R()
	if c.restSRV != nil {
		r.SetSRV(c.restSRV)
	}
	return r
}

// Return versioned url, not ideal but lets do this statically for now
func (c *Client) urlFor(s string) string {
	if !strings.HasSuffix(c.rest.HostURL, fmt.Sprintf("/%s", CurrentApiVersion)) {
		return fmt.Sprintf("%s/%s", CurrentApiVersion, s)
	}
	return s
}

func (c *Client) Close() {
	if c.agentClient != nil {
		c.agentConn.Close()
	}
}

func openFederatedAuthURL(url string) {
	fmt.Printf("Attempting to open browser to URL: %s\n", url)
	fmt.Println("If the browser doesn't open, navigate to the URL manually")
	if err := open.Start(url); err != nil {
		Log.WithError(err).Warning("cannot open browser")
	}
}

func interactiveCredentialsPrompt(name, realm, credentialType string) []byte {
	prompt := fmt.Sprintf("Enter %s for %q (%s): ",
		strings.Title(credentialType),
		name,
		realm,
	)
	switch credentialType {
	case CredentialTypePassword:
		if ret, err := speakeasy.FAsk(os.Stderr, prompt); err == nil {
			return []byte(ret)
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: cannot do password prompt: %s\n", err)
		}
		fallthrough
	default:
		fmt.Fprint(os.Stderr, prompt)
		reader := bufio.NewReader(os.Stdin)
		ret, _ := reader.ReadBytes('\n')
		ret = ret[:len(ret)-1]
		return ret
	}
}

func iterAgentKeys(agentClient agent.Agent, fn func(key ssh.PublicKey, comment string) error) error {
	keys, err := agentClient.List()
	if err != nil {
		return err
	}
	for _, key := range keys {
		tmp, err := ssh.ParsePublicKey(key.Marshal())
		if err != nil {
			return errors.Wrap(err, "unexpected error")
		}
		if err := fn(tmp, key.Comment); err != nil {
			return err
		}
	}
	return nil
}

func shallowCertChecker(cert *ssh.Certificate, authority ssh.PublicKey) bool {
	// from ssh.bytesForSigning()
	c2 := *cert
	c2.Signature = nil
	out := c2.Marshal()
	// Drop trailing signature length.
	bytesForSigning := out[:len(out)-4]

	if !bytes.Equal(cert.SignatureKey.Marshal(), authority.Marshal()) {
		return false
	}

	unixNow := time.Now().Unix()
	if after := int64(cert.ValidAfter); after < 0 || unixNow < int64(cert.ValidAfter) {
		return false
	}
	if before := int64(cert.ValidBefore); cert.ValidBefore != uint64(ssh.CertTimeInfinity) && (unixNow >= before || before < 0) {
		return false
	}
	if err := cert.SignatureKey.Verify(bytesForSigning, cert.Signature); err != nil {
		return false
	}
	return true
}
