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
	"runtime"
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
	KeyAlgo            string
	ECCurve            string
	RSABits            int
	DigestRoot         string
	DigestIntermediate string
	DigestServer       string
	Domains            []string
	IPAddresses        []string
	ServerCN           string
	RootSubj           string
	IntermediateSubj   string
	ServerSubj         string
	WorkDir            string
	ScriptName         string
	Force              bool
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

	// Display platform information
	info("Running on: %s/%s", runtime.GOOS, runtime.GOARCH)

	config := parseArgs()

	if err := checkRequirements(); err != nil {
		die("Requirements check failed: %v", err)
	}

	if err := setupDirectories(config.WorkDir, config.Force); err != nil {
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
		KeyAlgo:            getEnvDefault("KEY_ALGO", DEFAULT_KEY_ALGO),
		ECCurve:            getEnvDefault("EC_CURVE", DEFAULT_EC_CURVE),
		RSABits:            getEnvIntDefault("RSA_BITS", DEFAULT_RSA_BITS),
		DigestRoot:         getEnvDefault("DIGEST_ROOT", DEFAULT_DIGEST_ROOT),
		DigestIntermediate: getEnvDefault("DIGEST_INTERMEDIATE", DEFAULT_DIGEST_INTERMEDIATE),
		DigestServer:       getEnvDefault("DIGEST_SERVER", DEFAULT_DIGEST_SERVER),
		ScriptName:         filepath.Base(os.Args[0]),
	}

	var help bool
	var domains stringSlice
	var ipAddresses stringSlice

	flag.BoolVar(&help, "h", false, "Show help and exit")
	flag.BoolVar(&help, "help", false, "Show help and exit")
	flag.StringVar(&config.KeyAlgo, "algo", config.KeyAlgo, "Choose key algorithm: ec | rsa")
	flag.Var(&domains, "d", "Add one DNS SAN entry; repeatable. Accepts DNS names (incl. wildcards)")
	flag.Var(&domains, "domain", "Add one DNS SAN entry; repeatable. Accepts DNS names (incl. wildcards)")
	flag.Var(&ipAddresses, "ip", "Add one IP SAN entry; repeatable. Accepts IPv4 and IPv6 addresses")
	flag.StringVar(&config.ServerCN, "scn", "", "Set Server Certificate CN (subject CN)")
	flag.StringVar(&config.RootSubj, "sr", "", "Set Root CA subject components")
	flag.StringVar(&config.IntermediateSubj, "si", "", "Set Intermediate CA subject components")
	flag.StringVar(&config.ServerSubj, "ss", "", "Set Server certificate subject components")
	flag.BoolVar(&config.Force, "force", false, "Force removal of existing directory without prompting")
	flag.BoolVar(&config.Force, "y", false, "Force removal of existing directory without prompting (alias for -force)")

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
	config.IPAddresses = []string(ipAddresses)

	// Set work directory to current working directory
	cwd, err := os.Getwd()
	if err != nil {
		die("Failed to get current working directory: %v", err)
	}
	config.WorkDir = filepath.Join(cwd, "pki")

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
	// Safer invocation for copy or paste.
	// On Windows PowerShell you typically need .\program.exe to run from the current directory.
	self := filepath.Join(".", config.ScriptName)

	// Relative paths shown in help output.
	intermediateChainRel := filepath.Join("intermediate", "ca-chain.crt")
	serverFullchainRel := filepath.Join("server", "fullchain.crt")

	windowsTip := ""
	if runtime.GOOS == "windows" {
		windowsTip = fmt.Sprintf("Windows tip:\n  PowerShell: %s ... (note the .\\ prefix)\n  cmd.exe:     %s ... (often works without .\\)\n\n", self, config.ScriptName)
	}

	fmt.Printf(`%s - Generate a simple PKI: Root CA -> Intermediate CA -> Server cert

USAGE:
  %s [options]

OPTIONS:
  -h, -help               Show this help and exit
  -algo VALUE             Choose key algorithm: ec | rsa (default: ec)
  -d, -domain VALUE       Add one DNS SAN entry; repeatable. Accepts DNS names (incl. wildcards).
                          e.g. -d example.com -d '*.example.com' -d localhost
  -ip VALUE               Add one IP SAN entry; repeatable. Accepts IPv4 and IPv6 addresses.
                          e.g. -ip 127.0.0.1 -ip ::1
  -scn VALUE              Set Server Certificate CN (subject CN). If omitted, defaults to the "root domain"
                          derived from the SAN list (e.g., example.com from -d example.com / -d *.example.com).
  -sr VALUE               Set Root CA subject components in OpenSSL slash format, e.g. /C=US/ST=CA/L=SF/O=My Org/OU=IT/CN=Root CA (default: /CN=Root CA)
  -si VALUE               Set Intermediate CA subject components in OpenSSL slash format, e.g. /C=US/ST=CA/L=SF/O=My Org/OU=IT/CN=My Intermediate CA (default: /CN=SHA2 Extended Validation Server CA)
  -ss VALUE               Set Server certificate subject components in OpenSSL slash format. CN is always from -scn/domains (default: /CN=<from -scn>)
  -force, -y              Force removal of existing directory without prompting

OUTPUT:
  Creates keys/certs under: %s
    - rootCA.{key,crt}
    - intermediateCA.{key,crt}  (plus %s)
    - server.{key,crt}          (plus %s)

CUSTOMIZATION:
  # Prefer -algo to choose algorithm. The following env vars remain supported:
  EC_CURVE=prime256v1|secp384r1   (current default: %s)
  RSA_BITS=3072|4096              (current default: %d)

  # Digests
  DIGEST_ROOT=sha256|sha384         (current: %s)
  DIGEST_INTERMEDIATE=sha256|sha384 (current: %s)
  DIGEST_SERVER=sha256|sha384       (current: %s)

EXAMPLES:
%s  # RSA instead of EC
  %s -algo rsa

  # Provide SANs and CN via CLI
  %s -algo ec -d example.com -d '*.example.com' -d localhost -ip 127.0.0.1 -ip ::1 -scn www.example.com

  # Let CN default to the root domain from SANs
  %s -d example.com -d '*.example.com' -ip 127.0.0.1

  # Custom certificate subjects (CN for server is always from -scn)
  %s -sr "/C=US/ST=CA/L=SF/O=My Company/OU=DevOps/CN=My Root CA" -si "/C=US/ST=CA/L=SF/O=My Company/OU=DevOps/CN=My Intermediate CA" -ss "/C=US/ST=CA/L=SF/O=My Company/OU=DevOps" -scn "api.example.com"

  # Force mode (non-interactive)
  %s -force -d example.com
  %s -y -d example.com

PLATFORM:
  Current OS: %s

`, config.ScriptName, config.ScriptName,
		config.WorkDir,
		intermediateChainRel,
		serverFullchainRel,
		config.ECCurve, config.RSABits,
		config.DigestRoot, config.DigestIntermediate, config.DigestServer,
		windowsTip,
		self, self, self, self,
		self, self,
		runtime.GOOS)
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

func setupDirectories(workDir string, force bool) error {
	if _, err := os.Stat(workDir); err == nil {
		if force {
			info("Force mode: removing existing directory: %s", workDir)
			if err := os.RemoveAll(workDir); err != nil {
				return fmt.Errorf("failed to remove %s: %v", workDir, err)
			}
		} else {
			fmt.Printf("Directory %s exists. Remove and recreate? [y/N]: ", workDir)
			var response string
			fmt.Scanln(&response)
			response = strings.TrimSpace(strings.ToLower(response))
			if response == "y" || response == "yes" {
				info("Removing existing directory: %s", workDir)
				if err := os.RemoveAll(workDir); err != nil {
					return fmt.Errorf("failed to remove %s: %v", workDir, err)
				}
			} else {
				return fmt.Errorf("aborting. Please backup or remove %s", workDir)
			}
		}
	}

	dirs := []string{
		workDir,
		filepath.Join(workDir, "root"),
		filepath.Join(workDir, "intermediate"),
		filepath.Join(workDir, "server"),
	}

	for _, dir := range dirs {
		info("Creating directory: %s", dir)
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

func randomSerialNumber128FixedLen() (*big.Int, error) {
	// Generate a positive 128-bit serial number with a fixed 16-octet length.
	// We force the first octet into [0x40..0x7f] so that
	// 1) the DER INTEGER stays positive without a leading 0x00, and
	// 2) OpenSSL prints exactly 16 octets (no leading-zero truncation).
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	b[0] &= 0x7f
	b[0] |= 0x40
	return new(big.Int).SetBytes(b), nil
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
	serialNumber, err := randomSerialNumber128FixedLen()
	if err != nil {
		return nil, fmt.Errorf("failed to generate root serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
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
	serialNumber, err := randomSerialNumber128FixedLen()
	if err != nil {
		return nil, fmt.Errorf("failed to generate intermediate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
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

	// Build SANs from domains and IP addresses (or use sensible defaults)
	domains := config.Domains
	ipAddresses := config.IPAddresses

	// If no domains or IPs specified, use defaults
	if len(domains) == 0 && len(ipAddresses) == 0 {
		domains = []string{"example.com", "*.example.com", "localhost"}
		ipAddresses = []string{"127.0.0.1"}
	}

	// Derive CN if not provided
	serverCN := config.ServerCN
	if serverCN == "" {
		// First try to find a non-wildcard domain
		for _, d := range domains {
			if d != "localhost" && !strings.HasPrefix(d, "*.") {
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
		// Last resort: use first domain or first IP
		if serverCN == "" {
			if len(domains) > 0 {
				serverCN = domains[0]
			} else if len(ipAddresses) > 0 {
				serverCN = ipAddresses[0]
			}
		}
	}

	// Generate private key
	privateKey, err := generateKey("server", config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key: %v", err)
	}

	// Build SAN lists
	var dnsNames []string
	var ipAddrs []net.IP

	// Add DNS names
	for _, d := range domains {
		dnsNames = append(dnsNames, d)
	}

	// Add IP addresses
	for _, ipStr := range ipAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		}
	}

	// Build subject using smart defaults (force CN to use serverCN)
	subjectStr := buildSubject(config.ServerSubj, serverCN, true)
	subject := parseSubjectString(subjectStr)

	// Create certificate template
	serialNumber, err := randomSerialNumber128FixedLen()
	if err != nil {
		return nil, fmt.Errorf("failed to generate server serial number: %v", err)
	}

	// Set KeyUsage based on algorithm
	var keyUsage x509.KeyUsage
	if config.KeyAlgo == "ec" {
		keyUsage = x509.KeyUsageDigitalSignature
	} else {
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, DAYS_SERVER),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          getSubjectKeyID(privateKey),
		AuthorityKeyId:        intermediateCA.Certificate.SubjectKeyId,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
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
	info("Installing certificates to %s...", workDir)

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

	info("Certificates installed successfully")
	return nil
}

func showSummary(config *Config, rootCA, intermediateCA, serverCert *CertificateData) {
	// Build display paths using filepath.Join for correct separators on each OS.
	rootKey := filepath.Join(config.WorkDir, "rootCA.key")
	rootCrt := filepath.Join(config.WorkDir, "rootCA.crt")

	intermediateKey := filepath.Join(config.WorkDir, "intermediateCA.key")
	intermediateCrt := filepath.Join(config.WorkDir, "intermediateCA.crt")
	chainCrt := filepath.Join(config.WorkDir, "intermediate", "ca-chain.crt")

	serverKey := filepath.Join(config.WorkDir, "server.key")
	serverCrt := filepath.Join(config.WorkDir, "server.crt")
	fullchainCrt := filepath.Join(config.WorkDir, "server", "fullchain.crt")

	self := filepath.Join(".", config.ScriptName)

	fmt.Printf(`

========================================
Certificate Chain Generation Complete
========================================

Platform: %s/%s

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
    Private Key: %s
    Certificate: %s

  Intermediate CA:
    Private Key: %s
    Certificate: %s
    Chain:       %s

  Server:
    Private Key: %s
    Certificate: %s
    Full Chain:  %s

To view certificate details:
  openssl x509 -text -noout -in "%s"

To test with curl:
  curl --cacert "%s" https://localhost

(For customization examples, run: %s -help)

`, runtime.GOOS, runtime.GOARCH,
		algoFor("root", config), algoFor("intermediate", config), algoFor("server", config),
		config.DigestRoot, config.DigestIntermediate, config.DigestServer,
		rootKey, rootCrt,
		intermediateKey, intermediateCrt, chainCrt,
		serverKey, serverCrt, fullchainCrt,
		serverCrt,
		rootCrt,
		self)
}

// Helper functions

// parseSubjectSlashKV parses an OpenSSL-style subject string like:
//
//	/C=US/O=DigiCert, Inc./CN=example.com
//
// Values may be quoted with single or double quotes.
// Note: the / character is used as a separator in this format. Unescaped / inside values is not supported.
func parseSubjectSlashKV(s string) map[string]string {
	s = strings.TrimSpace(s)
	if s == "" {
		return map[string]string{}
	}
	if !strings.HasPrefix(s, "/") {
		die("Subject must use OpenSSL slash format, e.g. /C=US/O=My Org/CN=Name. Got: %s", s)
	}
	parts := strings.Split(s, "/")
	kv := make(map[string]string)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		k = strings.ToUpper(strings.TrimSpace(k))
		v = unquoteAndUnescape(strings.TrimSpace(v))
		if k != "" && v != "" {
			kv[k] = v
		}
	}
	return kv
}

func unquoteAndUnescape(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
	}
	return v
}

// Build certificate subject with smart defaults
// inputSubj, when provided, must be OpenSSL slash format, e.g. /C=US/ST=CA/L=SF/O=My Org/OU=IT/CN=Root CA
func buildSubject(inputSubj, defaultCN string, forceCN bool) string {
	// Default values
	country := ""
	state := ""
	locality := ""
	organization := ""
	orgUnit := ""
	commonName := defaultCN

	if inputSubj != "" {
		kv := parseSubjectSlashKV(inputSubj)
		if v, ok := kv["C"]; ok {
			country = v
		}
		if v, ok := kv["ST"]; ok {
			state = v
		}
		if v, ok := kv["L"]; ok {
			locality = v
		}
		if v, ok := kv["O"]; ok {
			organization = v
		}
		if v, ok := kv["OU"]; ok {
			orgUnit = v
		}
		if !forceCN {
			if v, ok := kv["CN"]; ok {
				commonName = v
			}
		}
	}

	// Build result in OpenSSL conventional order:
	// C, ST, L, O, OU, CN
	result := ""
	if country != "" {
		result += "/C=" + country
	}
	if state != "" {
		result += "/ST=" + state
	}
	if locality != "" {
		result += "/L=" + locality
	}
	if organization != "" {
		result += "/O=" + organization
	}
	if orgUnit != "" {
		result += "/OU=" + orgUnit
	}
	result += "/CN=" + commonName

	return result
}

// Parse subject string into pkix.Name
func parseSubjectString(subjectStr string) pkix.Name {
	subject := pkix.Name{}
	kv := parseSubjectSlashKV(subjectStr)

	if v, ok := kv["C"]; ok {
		subject.Country = []string{v}
	}
	if v, ok := kv["ST"]; ok {
		subject.Province = []string{v}
	}
	if v, ok := kv["L"]; ok {
		subject.Locality = []string{v}
	}
	if v, ok := kv["O"]; ok {
		subject.Organization = []string{v}
	}
	if v, ok := kv["OU"]; ok {
		subject.OrganizationalUnit = []string{v}
	}
	if v, ok := kv["CN"]; ok {
		subject.CommonName = v
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
