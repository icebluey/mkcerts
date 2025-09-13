package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// Certificate validity periods (in days)
	DAYS_ROOT         = 10950 // 30 years for root CA
	DAYS_INTERMEDIATE = 7300  // 20 years for intermediate CA
	DAYS_SERVER       = 825   // ~2.25 years for server (CAB Forum limit)

	// Default cryptographic parameters
	DEFAULT_KEY_ALGO = "ec"
	DEFAULT_EC_CURVE = "prime256v1"
	DEFAULT_RSA_BITS = 3072

	// Digest algorithms for different certificate types
	DEFAULT_DIGEST_ROOT         = "sha384"
	DEFAULT_DIGEST_INTERMEDIATE = "sha384"
	DEFAULT_DIGEST_SERVER       = "sha256"
)

type Config struct {
	KeyAlgo           string
	ECCurve           string
	RSABits           int
	DigestRoot        string
	DigestIntermediate string
	DigestServer      string
	Domains           []string
	ServerCN          string
	RootSubj          string
	IntermediateSubj  string
	ServerSubj        string
	WorkDir           string
	ScriptName        string
}

type CertificateData struct {
	PrivateKey  interface{}
	Certificate *x509.Certificate
	CertPEM     []byte
	KeyPEM      []byte
}

func main() {
	// Force UTC timezone
	os.Setenv("TZ", "UTC")
	
	config := parseArgs()
	
	if err := checkRequirements(); err != nil {
		die("Requirements check failed: %v", err)
	}

	if err := setupDirectories(config.WorkDir); err != nil {
		die("Failed to setup directories: %v", err)
	}

	// Generate Root CA
	rootCA, err := generateRootCA(config)
	if err != nil {
		die("Failed to generate Root CA: %v", err)
	}

	// Generate Intermediate CA
	intermediateCA, err := generateIntermediateCA(config, rootCA)
	if err != nil {
		die("Failed to generate Intermediate CA: %v", err)
	}

	// Generate Server Certificate
	serverCert, err := generateServerCert(config, intermediateCA)
	if err != nil {
		die("Failed to generate Server Certificate: %v", err)
	}

	if err := verifyChain(config.WorkDir, rootCA, intermediateCA, serverCert); err != nil {
		die("Certificate chain verification failed: %v", err)
	}

	if err := installCertificates(config.WorkDir, rootCA, intermediateCA, serverCert); err != nil {
		die("Failed to install certificates: %v", err)
	}

	showSummary(config, rootCA, intermediateCA, serverCert)
}

func parseArgs() *Config {
	config := &Config{
		KeyAlgo:           getEnvDefault("KEY_ALGO", DEFAULT_KEY_ALGO),
		ECCurve:           getEnvDefault("EC_CURVE", DEFAULT_EC_CURVE),
		RSABits:           getEnvIntDefault("RSA_BITS", DEFAULT_RSA_BITS),
		DigestRoot:        getEnvDefault("DIGEST_ROOT", DEFAULT_DIGEST_ROOT),
		DigestIntermediate: getEnvDefault("DIGEST_INTERMEDIATE", DEFAULT_DIGEST_INTERMEDIATE),
		DigestServer:      getEnvDefault("DIGEST_SERVER", DEFAULT_DIGEST_SERVER),
		ScriptName:        filepath.Base(os.Args[0]),
	}

	var help bool
	var domains stringSlice

	flag.BoolVar(&help, "h", false, "Show help and exit")
	flag.BoolVar(&help, "help", false, "Show help and exit")
	flag.StringVar(&config.KeyAlgo, "algo", config.KeyAlgo, "Choose key algorithm: ec | rsa")
	flag.Var(&domains, "d", "Add one SAN entry; repeatable. Accepts DNS names (incl. wildcards) or IPv4")
	flag.Var(&domains, "domain", "Add one SAN entry; repeatable. Accepts DNS names (incl. wildcards) or IPv4")
	flag.StringVar(&config.ServerCN, "scn", "", "Set Server Certificate CN (subject CN)")
	flag.StringVar(&config.RootSubj, "sr", "", "Set Root CA subject components")
	flag.StringVar(&config.IntermediateSubj, "si", "", "Set Intermediate CA subject components")
	flag.StringVar(&config.ServerSubj, "ss", "", "Set Server certificate subject components")

	flag.Parse()

	if help {
		showUsage(config)
		os.Exit(0)
	}

	// Validate algorithm
	if config.KeyAlgo != "ec" && config.KeyAlgo != "rsa" {
		die("Invalid -algo value: %s (expected: ec | rsa)", config.KeyAlgo)
	}

	config.Domains = []string(domains)
	
	// Set work directory
	scriptDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		die("Failed to get script directory: %v", err)
	}
	config.WorkDir = filepath.Join(scriptDir, "pki")

	return config
}

type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func getEnvDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func showUsage(config *Config) {
	fmt.Printf(`%s - Generate a simple PKI: Root CA -> Intermediate CA -> Server cert

USAGE:
  %s [options]

OPTIONS:
  -h, -help               Show this help and exit
  -algo VALUE             Choose key algorithm: ec | rsa (default: ec)
  -d, -domain VALUE       Add one SAN entry; repeatable. Accepts DNS names (incl. wildcards) or IPv4.
                          e.g. -d example.com -d '*.example.com' -d localhost -d 127.0.0.1
  -scn VALUE              Set Server Certificate CN (subject CN). If omitted, defaults to the "root domain"
                          derived from the SAN list (e.g., example.com from -d example.com / -d *.example.com).
  -sr VALUE               Set Root CA subject components (default: C=US, no O, CN=Root CA)
  -si VALUE               Set Intermediate CA subject components (default: C=US, no O, CN=SHA2 Extended Validation Server CA)
  -ss VALUE               Set Server certificate subject components (default: C=US, no O, CN always from -scn/domains)

OUTPUT:
  Creates keys/certs under: %s/
    - rootCA.{key,crt}
    - intermediateCA.{key,crt}  (plus intermediate/ca-chain.crt)
    - server.{key,crt}          (plus server/fullchain.crt)

CUSTOMIZATION:
  # Prefer -algo to choose algorithm. The following env vars remain supported:
  EC_CURVE=prime256v1|secp384r1   (current default: %s)
  RSA_BITS=3072|4096              (current default: %d)

  # Digests
  DIGEST_ROOT=sha256|sha384         (current: %s)
  DIGEST_INTERMEDIATE=sha256|sha384 (current: %s)
  DIGEST_SERVER=sha256|sha384       (current: %s)

EXAMPLES:
  # RSA instead of EC
  ./%s -algo rsa

  # Provide SANs and CN via CLI
  ./%s -algo ec -d example.com -d '*.example.com' -d localhost -d 127.0.0.1 -scn www.example.com

  # Let CN default to the root domain from SANs
  ./%s -d example.com -d '*.example.com' -d localhost -d 127.0.0.1

  # Custom certificate subjects (CN for server is always from -scn)
  ./%s -sr "O=My Company" -si "O=My Company" -ss "O=My Company" -scn "api.example.com"

`, config.ScriptName, config.ScriptName, config.WorkDir, config.ECCurve, config.RSABits,
		config.DigestRoot, config.DigestIntermediate, config.DigestServer,
		config.ScriptName, config.ScriptName, config.ScriptName, config.ScriptName)
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}

func info(format string, args ...interface{}) {
	fmt.Printf("INFO: "+format+"\n", args...)
}

func checkRequirements() error {
	// Go has built-in crypto support, so no external dependencies needed
	info("Using Go built-in cryptographic libraries")
	return nil
}

func setupDirectories(workDir string) error {
	if _, err := os.Stat(workDir); err == nil {
		fmt.Printf("Directory %s exists. Remove and recreate? [y/N]: ", workDir)
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) == "y" || strings.ToLower(response) == "yes" {
			if err := os.RemoveAll(workDir); err != nil {
				return fmt.Errorf("failed to remove %s: %v", workDir, err)
			}
		} else {
			return fmt.Errorf("aborting. Please backup or remove %s", workDir)
		}
	}

	dirs := []string{
		workDir,
		filepath.Join(workDir, "root"),
		filepath.Join(workDir, "intermediate"),
		filepath.Join(workDir, "server"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	return nil
}

func generateKey(keyType string, config *Config) (interface{}, error) {
	switch config.KeyAlgo {
	case "ec":
		var curve elliptic.Curve
		switch keyType {
		case "root":
			curve = elliptic.P384() // secp384r1 for root
		case "intermediate":
			curve = elliptic.P256() // prime256v1 for intermediate
		default: // server
			if config.ECCurve == "secp384r1" {
				curve = elliptic.P384()
			} else {
				curve = elliptic.P256() // default to prime256v1
			}
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case "rsa":
		bits := config.RSABits
		if keyType == "root" {
			bits = 4096 // Always use 4096 for root
		}
		return rsa.GenerateKey(rand.Reader, bits)
	default:
		return nil, fmt.Errorf("unknown key algorithm: %s", config.KeyAlgo)
	}
}

func algoFor(keyType string, config *Config) string {
	if config.KeyAlgo == "rsa" {
		bits := config.RSABits
		if keyType == "root" {
			bits = 4096
		}
		return fmt.Sprintf("RSA-%d", bits)
	} else {
		// EC curves per level
		switch keyType {
		case "root":
			return "P-384"
		case "intermediate":
			return "P-256"
		default: // server
			if config.ECCurve == "secp384r1" {
				return "P-384"
			} else {
				return "P-256"
			}
		}
	}
}

func isIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

func generateRootCA(config *Config) (*CertificateData, error) {
	info("Using algorithm for Root CA: %s", algoFor("root", config))
	info("Generating Root CA with %s digest...", config.DigestRoot)

	// Generate private key
	privateKey, err := generateKey("root", config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate root key: %v", err)
	}

	// Build subject using smart defaults
	subjectStr := buildSubject(config.RootSubj, "Root CA", false)
	subject := parseSubjectString(subjectStr)

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, DAYS_ROOT),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          getSubjectKeyID(privateKey),
	}

	// Set signature algorithm based on digest
	template.SignatureAlgorithm = getSignatureAlgorithm(config.KeyAlgo, config.DigestRoot)

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, getPublicKey(privateKey), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create root certificate: %v", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root certificate: %v", err)
	}

	// Create PEM blocks
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := encodePrivateKeyPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode root private key: %v", err)
	}

	// Save files
	keyFile := filepath.Join(config.WorkDir, "root", "rootCA.key")
	certFile := filepath.Join(config.WorkDir, "root", "rootCA.crt")

	if err := writeFileSecure(keyFile, keyPEM, 0400); err != nil {
		return nil, err
	}
	if err := writeFileSecure(certFile, certPEM, 0644); err != nil {
		return nil, err
	}

	info("Root CA generated: %s", certFile)

	return &CertificateData{
		PrivateKey:  privateKey,
		Certificate: cert,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

func generateIntermediateCA(config *Config, rootCA *CertificateData) (*CertificateData, error) {
	info("Using algorithm for Intermediate CA: %s", algoFor("intermediate", config))
	info("Generating Intermediate CA with %s digest...", config.DigestIntermediate)

	// Generate private key
	privateKey, err := generateKey("intermediate", config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate intermediate key: %v", err)
	}

	// Build subject using smart defaults
	subjectStr := buildSubject(config.IntermediateSubj, "SHA2 Extended Validation Server CA", false)
	subject := parseSubjectString(subjectStr)

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, DAYS_INTERMEDIATE),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          getSubjectKeyID(privateKey),
		AuthorityKeyId:        rootCA.Certificate.SubjectKeyId,
	}

	// Set signature algorithm based on digest
	template.SignatureAlgorithm = getSignatureAlgorithm(config.KeyAlgo, config.DigestIntermediate)

	// Sign with Root CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCA.Certificate, getPublicKey(privateKey), rootCA.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate certificate: %v", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse intermediate certificate: %v", err)
	}

	// Create PEM blocks
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := encodePrivateKeyPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode intermediate private key: %v", err)
	}

	// Save files
	keyFile := filepath.Join(config.WorkDir, "intermediate", "intermediateCA.key")
	certFile := filepath.Join(config.WorkDir, "intermediate", "intermediateCA.crt")
	chainFile := filepath.Join(config.WorkDir, "intermediate", "ca-chain.crt")

	if err := writeFileSecure(keyFile, keyPEM, 0400); err != nil {
		return nil, err
	}
	if err := writeFileSecure(certFile, certPEM, 0644); err != nil {
		return nil, err
	}

	// Create certificate chain
	chainPEM := append(certPEM, rootCA.CertPEM...)
	if err := writeFileSecure(chainFile, chainPEM, 0644); err != nil {
		return nil, err
	}

	info("Intermediate CA generated: %s", certFile)

	return &CertificateData{
		PrivateKey:  privateKey,
		Certificate: cert,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

func generateServerCert(config *Config, intermediateCA *CertificateData) (*CertificateData, error) {
	info("Using algorithm for Server: %s", algoFor("server", config))
	info("Generating Server Certificate with %s digest...", config.DigestServer)

	// Build SANs from domains (or use sensible defaults)
	domains := config.Domains
	if len(domains) == 0 {
		domains = []string{"example.com", "*.example.com", "localhost", "127.0.0.1"}
	}

	// Derive CN if not provided
	serverCN := config.ServerCN
	if serverCN == "" {
		// Find first non-IP, non-localhost, non-wildcard domain
		for _, d := range domains {
			if !isIPv4(d) && d != "localhost" && !strings.HasPrefix(d, "*.") {
				serverCN = d
				break
			}
		}
		// If not found, try wildcards
		if serverCN == "" {
			for _, d := range domains {
				if strings.HasPrefix(d, "*.") {
					serverCN = d[2:]
					break
				}
			}
		}
		// Last resort
		if serverCN == "" {
			serverCN = domains[0]
		}
	}

	// Generate private key
	privateKey, err := generateKey("server", config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key: %v", err)
	}

	// Build SAN list
	var dnsNames []string
	var ipAddresses []net.IP
	for _, d := range domains {
		if isIPv4(d) {
			ipAddresses = append(ipAddresses, net.ParseIP(d))
		} else {
			dnsNames = append(dnsNames, d)
		}
	}

	// Build subject using smart defaults (force CN to use serverCN)
	subjectStr := buildSubject(config.ServerSubj, serverCN, true)
	subject := parseSubjectString(subjectStr)

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, DAYS_SERVER),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          getSubjectKeyID(privateKey),
		AuthorityKeyId:        intermediateCA.Certificate.SubjectKeyId,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	// Set signature algorithm based on digest
	template.SignatureAlgorithm = getSignatureAlgorithm(config.KeyAlgo, config.DigestServer)

	// Sign with Intermediate CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, intermediateCA.Certificate, getPublicKey(privateKey), intermediateCA.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %v", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server certificate: %v", err)
	}

	// Create PEM blocks
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := encodePrivateKeyPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode server private key: %v", err)
	}

	// Save files
	keyFile := filepath.Join(config.WorkDir, "server", "server.key")
	certFile := filepath.Join(config.WorkDir, "server", "server.crt")
	fullchainFile := filepath.Join(config.WorkDir, "server", "fullchain.crt")

	if err := writeFileSecure(keyFile, keyPEM, 0400); err != nil {
		return nil, err
	}
	if err := writeFileSecure(certFile, certPEM, 0644); err != nil {
		return nil, err
	}

	// Create full certificate chain (server + intermediate, not root)
	intermediateCertFile := filepath.Join(config.WorkDir, "intermediate", "intermediateCA.crt")
	
	intermediatePEM, err := os.ReadFile(intermediateCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read intermediate cert: %v", err)
	}

	fullchainPEM := append(certPEM, intermediatePEM...)
	if err := writeFileSecure(fullchainFile, fullchainPEM, 0644); err != nil {
		return nil, err
	}

	info("Server certificate generated: %s", certFile)

	return &CertificateData{
		PrivateKey:  privateKey,
		Certificate: cert,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

func verifyChain(workDir string, rootCA, intermediateCA, serverCert *CertificateData) error {
	info("Verifying certificate chain...")

	// Create certificate pools
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCA.Certificate)

	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(intermediateCA.Certificate)

	// Verify intermediate against root
	opts := x509.VerifyOptions{
		Roots: rootPool,
	}
	if _, err := intermediateCA.Certificate.Verify(opts); err != nil {
		return fmt.Errorf("intermediate certificate verification failed: %v", err)
	}

	// Verify server against chain
	opts = x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
	}
	if _, err := serverCert.Certificate.Verify(opts); err != nil {
		return fmt.Errorf("server certificate verification failed: %v", err)
	}

	info("Certificate chain verified successfully")
	return nil
}

func installCertificates(workDir string, rootCA, intermediateCA, serverCert *CertificateData) error {
	info("Installing certificates...")

	// Read fullchain.crt from server directory
	fullchainPEM, err := os.ReadFile(filepath.Join(workDir, "server", "fullchain.crt"))
	if err != nil {
		return fmt.Errorf("failed to read fullchain.crt: %v", err)
	}

	files := map[string][]byte{
		"rootCA.key":         rootCA.KeyPEM,
		"rootCA.crt":         rootCA.CertPEM,
		"intermediateCA.key": intermediateCA.KeyPEM,
		"intermediateCA.crt": intermediateCA.CertPEM,
		"server.key":         serverCert.KeyPEM,
		"server.crt":         serverCert.CertPEM,
		"fullchain.crt":      fullchainPEM,
	}

	for filename, content := range files {
		destFile := filepath.Join(workDir, filename)
		var perm os.FileMode = 0644
		if strings.HasSuffix(filename, ".key") {
			perm = 0400
		}
		if err := writeFileSecure(destFile, content, perm); err != nil {
			return err
		}
	}

	info("Certificates installed to %s/", workDir)
	return nil
}

func showSummary(config *Config, rootCA, intermediateCA, serverCert *CertificateData) {
	fmt.Printf(`

========================================
Certificate Chain Generation Complete
========================================

Algorithms used:
  Root CA:         %s
  Intermediate CA: %s
  Server:          %s

Digest algorithms used:
  Root CA:         %s
  Intermediate CA: %s
  Server:          %s

Generated files:
  Root CA:
    Private Key: %s/rootCA.key
    Certificate: %s/rootCA.crt

  Intermediate CA:
    Private Key: %s/intermediateCA.key
    Certificate: %s/intermediateCA.crt
    Chain:       %s/intermediate/ca-chain.crt

  Server:
    Private Key: %s/server.key
    Certificate: %s/server.crt
    Full Chain:  %s/server/fullchain.crt

To view certificate details:
  openssl x509 -text -noout -in %s/server.crt

To test with curl:
  curl --cacert %s/rootCA.crt https://localhost

(For customization examples, run: %s -help)

`, algoFor("root", config), algoFor("intermediate", config), algoFor("server", config),
		config.DigestRoot, config.DigestIntermediate, config.DigestServer,
		config.WorkDir, config.WorkDir,
		config.WorkDir, config.WorkDir, config.WorkDir,
		config.WorkDir, config.WorkDir, config.WorkDir,
		config.WorkDir, config.WorkDir, config.ScriptName)
}

// Helper functions

// Build certificate subject with smart defaults
func buildSubject(inputSubj, defaultCN string, forceCN bool) string {
	// Default values
	country := "US"
	organization := ""
	commonName := defaultCN
	
	if inputSubj != "" {
		// Extract existing components using regex
		if match := regexp.MustCompile(`C=([^/,]+)`).FindStringSubmatch(inputSubj); match != nil {
			country = match[1]
		}
		if match := regexp.MustCompile(`O=([^/,]+)`).FindStringSubmatch(inputSubj); match != nil {
			organization = match[1]
		}
		// Only use CN from input if not forced to use default
		if !forceCN {
			if match := regexp.MustCompile(`CN=([^/,]+)`).FindStringSubmatch(inputSubj); match != nil {
				commonName = match[1]
			}
		}
	}
	
	// Build result
	result := "/C=" + country
	if organization != "" {
		result += "/O=" + organization
	}
	result += "/CN=" + commonName
	
	return result
}

// Parse subject string into pkix.Name
func parseSubjectString(subjectStr string) pkix.Name {
	subject := pkix.Name{}
	
	// Extract C
	if match := regexp.MustCompile(`C=([^/,]+)`).FindStringSubmatch(subjectStr); match != nil {
		subject.Country = []string{match[1]}
	}
	
	// Extract O
	if match := regexp.MustCompile(`O=([^/,]+)`).FindStringSubmatch(subjectStr); match != nil {
		subject.Organization = []string{match[1]}
	}
	
	// Extract CN
	if match := regexp.MustCompile(`CN=([^/,]+)`).FindStringSubmatch(subjectStr); match != nil {
		subject.CommonName = match[1]
	}
	
	return subject
}

func getPublicKey(privateKey interface{}) interface{} {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	default:
		return nil
	}
}

func getSubjectKeyID(privateKey interface{}) []byte {
	publicKey := getPublicKey(privateKey)
	
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		// For RSA: hash the modulus N using SHA-1 (RFC 5280 method)
		hash := sha1.Sum(pub.N.Bytes())
		return hash[:]
	case *ecdsa.PublicKey:
		// For ECDSA: hash the uncompressed point (0x04 + X + Y) using SHA-1
		x := pub.X.Bytes()
		y := pub.Y.Bytes()
		
		// Pad to curve size
		curveSize := (pub.Curve.Params().BitSize + 7) / 8
		if len(x) < curveSize {
			padded := make([]byte, curveSize)
			copy(padded[curveSize-len(x):], x)
			x = padded
		}
		if len(y) < curveSize {
			padded := make([]byte, curveSize)
			copy(padded[curveSize-len(y):], y)
			y = padded
		}
		
		// Create uncompressed point: 0x04 + X + Y
		uncompressed := append([]byte{0x04}, x...)
		uncompressed = append(uncompressed, y...)
		
		hash := sha1.Sum(uncompressed)
		return hash[:]
	default:
		// Fallback
		hash := sha1.Sum([]byte("fallback"))
		return hash[:]
	}
}

func getSignatureAlgorithm(keyAlgo, digest string) x509.SignatureAlgorithm {
	if keyAlgo == "rsa" {
		switch digest {
		case "sha256":
			return x509.SHA256WithRSA
		case "sha384":
			return x509.SHA384WithRSA
		default:
			return x509.SHA384WithRSA
		}
	} else { // EC
		switch digest {
		case "sha256":
			return x509.ECDSAWithSHA256
		case "sha384":
			return x509.ECDSAWithSHA384
		default:
			return x509.ECDSAWithSHA384
		}
	}
}

func encodePrivateKeyPEM(privateKey interface{}) ([]byte, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes := x509.MarshalPKCS1PrivateKey(key)
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}), nil
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), nil
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

func writeFileSecure(filename string, data []byte, perm os.FileMode) error {
	if err := os.WriteFile(filename, data, perm); err != nil {
		return fmt.Errorf("failed to write %s: %v", filename, err)
	}
	return nil
}

