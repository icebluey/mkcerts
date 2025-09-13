#!/bin/bash
# Certificate Chain Generator
# Generates: Root CA -> Intermediate CA -> Server Certificate
# Following UNIX philosophy: Do one thing well, fail loudly, be composable

TZ='UTC'; export TZ

set -euo pipefail  # Fail fast, fail hard - Linus approves
IFS=$'\n\t'        # Proper IFS handling

# --- Constants ---
readonly SCRIPT_NAME="${0##*/}"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly WORK_DIR="$(pwd)/pki"

# Certificate validity periods (in days)
readonly DAYS_ROOT=10950        # 30 years for root CA
readonly DAYS_INTERMEDIATE=7300 # 20 years for intermediate CA
readonly DAYS_SERVER=825        # ~2.25 years for server (CAB Forum limit)

# Cryptographic parameters
# NOTE: Default to EC; can be overridden by -algo (preferred) or env KEY_ALGO for backward compatibility.
KEY_ALGO="${KEY_ALGO:-ec}"         # 'rsa' or 'ec'
readonly EC_CURVE="${EC_CURVE:-prime256v1}" # P-256
readonly RSA_BITS="${RSA_BITS:-3072}"

# Digest algorithms for different certificate types
readonly DIGEST_ROOT="${DIGEST_ROOT:-sha384}"
readonly DIGEST_INTERMEDIATE="${DIGEST_INTERMEDIATE:-sha384}"
readonly DIGEST_SERVER="${DIGEST_SERVER:-sha256}"

# --- CLI opts ---
declare -a DOMAINS=()   # values for SAN: -d/--domain (repeatable) e.g. example.com, *.example.com, 127.0.0.1
SERVER_SCN=""           # -scn value (server CN). If empty, derive from DOMAINS.
ROOT_SUBJ=""            # -sr value (root CA subject)
INTERMEDIATE_SUBJ=""    # -si value (intermediate CA subject)
SERVER_SUBJ=""          # -ss value (server certificate subject)

# --- Functions ---

die() {
    echo "ERROR: $*" >&2
    exit 1
}

info() {
    echo "INFO: $*"
}

cleanup_on_error() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo "ERROR: Script failed with exit code $exit_code" >&2
        echo "ERROR: Partial files may remain in ${WORK_DIR}" >&2
    fi
}

trap cleanup_on_error EXIT

usage() {
    cat <<-EOF
	${SCRIPT_NAME} - Generate a simple PKI: Root CA -> Intermediate CA -> Server cert

	USAGE:
	  ${SCRIPT_NAME} [options]

	OPTIONS:
	  -h, --help              Show this help and exit
	  -algo VALUE             Choose key algorithm: ec | rsa (default: ec)
	  -d, --domain VALUE      Add one SAN entry; repeatable. Accepts DNS names (incl. wildcards) or IPv4.
	                          e.g. -d example.com -d '*.example.com' -d localhost -d 127.0.0.1
	  -scn VALUE              Set Server Certificate CN (subject CN). If omitted, defaults to the "root domain"
	                          derived from the SAN list (e.g., example.com from -d example.com / -d *.example.com).
	  -sr VALUE               Set Root CA subject components (default: C=US, no O, CN=Root CA)
	  -si VALUE               Set Intermediate CA subject components (default: C=US, no O, CN=SHA2 Extended Validation Server CA)
	  -ss VALUE               Set Server certificate subject components (default: C=US, no O, CN always from -scn/domains)

	OUTPUT:
	  Creates keys/certs under: ${WORK_DIR}/
	    - rootCA.{key,crt}
	    - intermediateCA.{key,crt}  (plus intermediate/ca-chain.crt)
	    - server.{key,crt}          (plus server/fullchain.crt)

	CUSTOMIZATION:
	  # Prefer -algo to choose algorithm. The following env vars remain supported:
	  EC_CURVE=prime256v1|secp384r1   (current default: ${EC_CURVE})
	  RSA_BITS=3072|4096              (current default: ${RSA_BITS})

	  # Digests
	  DIGEST_ROOT=sha256|sha384         (current: ${DIGEST_ROOT})
	  DIGEST_INTERMEDIATE=sha256|sha384 (current: ${DIGEST_INTERMEDIATE})
	  DIGEST_SERVER=sha256|sha384       (current: ${DIGEST_SERVER})

	EXAMPLES:
	  # RSA instead of EC
	  ./${SCRIPT_NAME} -algo rsa

	  # Provide SANs and CN via CLI
	  ./${SCRIPT_NAME} -algo ec -d example.com -d '*.example.com' -d localhost -d 127.0.0.1 -scn www.example.com

	  # Let CN default to the root domain from SANs
	  ./${SCRIPT_NAME} -d example.com -d '*.example.com' -d localhost -d 127.0.0.1

	  # Custom certificate subjects (CN for server is always from -scn)
	  ./${SCRIPT_NAME} -sr "O=My Company" -si "O=My Company" -ss "O=My Company" -scn "api.example.com"

	EOF
}

# Validate environment
check_requirements() {
    command -v openssl >/dev/null 2>&1 || die "openssl not found in PATH"

    local openssl_version
    openssl_version=$(openssl version | awk '{print $2}')
    info "Using OpenSSL version: ${openssl_version}"

    # Check for minimum OpenSSL version (1.1.1)
    if ! openssl version | grep -qE "OpenSSL (1\.(1\.[1-9]|[2-9])|[2-9]|3\.)"; then
        die "OpenSSL 1.1.1 or later required"
    fi
}

# Setup directory structure
setup_directories() {
    if [ -d "${WORK_DIR}" ]; then
        read -rp "Directory ${WORK_DIR} exists. Remove and recreate? [y/N]: " response
        case "$response" in
            [yY][eE][sS]|[yY])
                rm -rf "${WORK_DIR}" || die "Failed to remove ${WORK_DIR}"
                ;;
            *)
                die "Aborting. Please backup or remove ${WORK_DIR}"
                ;;
        esac
    fi

    mkdir -p "${WORK_DIR}"/{root,intermediate,server} || die "Failed to create directories"

    # Set restrictive permissions on private key directories
    chmod 700 "${WORK_DIR}"/{root,intermediate,server}
}

# Generate private key based on algorithm choice
generate_key() {
    local key_file="$1"
    local key_type="${2:-server}"  # root, intermediate, or server

    case "${KEY_ALGO}" in
        ec)
            # Use different curves for different levels (defense in depth)
            local curve="${EC_CURVE}"
            if [ "${key_type}" = "root" ]; then
                curve="secp384r1"  # P-384 for root
            elif [ "${key_type}" = "intermediate" ]; then
                curve="prime256v1"  # P-256 for intermediate
            fi

            openssl ecparam -genkey -noout -name "${curve}" -out "${key_file}" || \
                die "Failed to generate EC key for ${key_type}"
            ;;
        rsa)
            local bits="${RSA_BITS}"
            if [ "${key_type}" = "root" ]; then
                bits=4096  # Always use 4096 for root
            fi

            openssl genrsa -out "${key_file}" "${bits}" || \
                die "Failed to generate RSA key for ${key_type}"
            ;;
        *)
            die "Unknown key algorithm: ${KEY_ALGO}"
            ;;
    esac

    # Secure the private key
    chmod 400 "${key_file}"
}

# Return human-readable algorithm label for a given key type
# Usage: algo_for root|intermediate|server  ->  "RSA-4096" | "P-384" | etc.
algo_for() {
    local key_type="$1"
    if [ "${KEY_ALGO}" = "rsa" ]; then
        local bits="${RSA_BITS}"
        [ "${key_type}" = "root" ] && bits=4096
        echo "RSA-${bits}"
    else
        # EC curves per level mirror generate_key()
        local curve="${EC_CURVE}"
        [ "${key_type}" = "root" ] && curve="secp384r1"
        [ "${key_type}" = "intermediate" ] && curve="prime256v1"
        case "${curve}" in
            prime256v1|secp256r1) echo "P-256" ;;
            secp384r1)            echo "P-384" ;;
            *)                    echo "${curve}" ;;
        esac
    fi
}

# Build certificate subject with smart defaults
build_subject() {
    local input_subj="$1"
    local default_cn="$2"
    local force_cn="${3:-}"  # If set, ignore CN in input_subj
    local result=""
    
    # Parse input subject into components
    local c_val="US" o_val="" cn_val="${default_cn}"
    
    if [ -n "${input_subj}" ]; then
        # Extract existing components
        if [[ "${input_subj}" =~ C=([^/,]+) ]]; then
            c_val="${BASH_REMATCH[1]}"
        fi
        if [[ "${input_subj}" =~ O=([^/,]+) ]]; then
            o_val="${BASH_REMATCH[1]}"
        fi
        # Only use CN from input if not forced to use default
        if [ -z "${force_cn}" ] && [[ "${input_subj}" =~ CN=([^/,]+) ]]; then
            cn_val="${BASH_REMATCH[1]}"
        fi
    fi
    
    # Build result
    result="/C=${c_val}"
    [ -n "${o_val}" ] && result="${result}/O=${o_val}"
    result="${result}/CN=${cn_val}"
    
    echo "${result}"
}

_is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

# Generate Root CA
generate_root_ca() {
    info "Using algorithm for Root CA: $(algo_for root)"
    info "Generating Root CA with ${DIGEST_ROOT} digest..."

    local key_file="${WORK_DIR}/root/rootCA.key"
    local cert_file="${WORK_DIR}/root/rootCA.crt"

    # Generate private key
    generate_key "${key_file}" "root"

    # Generate self-signed root certificate
    local root_subj
    root_subj=$(build_subject "${ROOT_SUBJ}" "Root CA")
    openssl req -new -x509 \
        -"${DIGEST_ROOT}" \
        -key "${key_file}" \
        -days "${DAYS_ROOT}" \
        -out "${cert_file}" \
        -subj "${root_subj}" \
        -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "subjectKeyIdentifier=hash" || \
        die "Failed to generate root certificate"

    info "Root CA generated: ${cert_file}"
}

# Generate Intermediate CA
generate_intermediate_ca() {
    info "Using algorithm for Intermediate CA: $(algo_for intermediate)"
    info "Generating Intermediate CA with ${DIGEST_INTERMEDIATE} digest..."

    local key_file="${WORK_DIR}/intermediate/intermediateCA.key"
    local csr_file="${WORK_DIR}/intermediate/intermediateCA.csr"
    local cert_file="${WORK_DIR}/intermediate/intermediateCA.crt"
    local root_key="${WORK_DIR}/root/rootCA.key"
    local root_cert="${WORK_DIR}/root/rootCA.crt"

    [ -f "${root_key}" ] || die "Root CA key not found"
    [ -f "${root_cert}" ] || die "Root CA certificate not found"

    # Generate private key
    generate_key "${key_file}" "intermediate"

    # Generate CSR
    local intermediate_subj
    intermediate_subj=$(build_subject "${INTERMEDIATE_SUBJ}" "SHA2 Extended Validation Server CA")
    openssl req -new \
        -"${DIGEST_INTERMEDIATE}" \
        -key "${key_file}" \
        -out "${csr_file}" \
        -subj "${intermediate_subj}" || \
        die "Failed to generate intermediate CSR"

    # Sign with Root CA
    openssl x509 -req \
        -"${DIGEST_INTERMEDIATE}" \
        -in "${csr_file}" \
        -CA "${root_cert}" \
        -CAkey "${root_key}" \
        -CAcreateserial \
        -days "${DAYS_INTERMEDIATE}" \
        -out "${cert_file}" \
        -extfile <(cat <<-EOF
			basicConstraints=critical,CA:TRUE,pathlen:0
			keyUsage=critical,digitalSignature,keyCertSign,cRLSign
			subjectKeyIdentifier=hash
			authorityKeyIdentifier=keyid:always,issuer
		EOF
        ) || die "Failed to sign intermediate certificate"

    # Clean up CSR
    rm -f "${csr_file}"

    # Create certificate chain
    cat "${cert_file}" "${root_cert}" > "${WORK_DIR}/intermediate/ca-chain.crt"

    info "Intermediate CA generated: ${cert_file}"
}

# Generate Server Certificate
generate_server_cert() {
    info "Using algorithm for Server: $(algo_for server)"
    info "Generating Server Certificate with ${DIGEST_SERVER} digest..."

    local key_file="${WORK_DIR}/server/server.key"
    local csr_file="${WORK_DIR}/server/server.csr"
    local cert_file="${WORK_DIR}/server/server.crt"
    local int_key="${WORK_DIR}/intermediate/intermediateCA.key"
    local int_cert="${WORK_DIR}/intermediate/intermediateCA.crt"

    [ -f "${int_key}" ] || die "Intermediate CA key not found"
    [ -f "${int_cert}" ] || die "Intermediate CA certificate not found"

    # Build SANs from -d/--domain flags (or use sensible defaults)
    local domains=("${DOMAINS[@]}")
    if [ ${#domains[@]} -eq 0 ]; then
        domains=( "example.com" "*.example.com" "localhost" "127.0.0.1" )
    fi

    # Derive CN if not provided
    local server_cn="${SERVER_SCN}"
    if [ -z "${server_cn}" ]; then
        for d in "${domains[@]}"; do
            if ! _is_ipv4 "$d" && [[ "$d" != localhost ]] && [[ "$d" != \*.* ]]; then
                server_cn="$d"; break
            fi
        done
        if [ -z "${server_cn}" ]; then
            for d in "${domains[@]}"; do
                if [[ "$d" == \*.* ]]; then
                    server_cn="${d#*.}"; break
                fi
            done
        fi
        if [ -z "${server_cn}" ]; then
            server_cn="${domains[0]}"
        fi
    fi

    # Compose subjectAltName string (comma-separated, no spaces)
    local san_entries=()
    for d in "${domains[@]}"; do
        if _is_ipv4 "$d"; then
            san_entries+=( "IP:${d}" )
        else
            san_entries+=( "DNS:${d}" )
        fi
    done
    local server_san
    server_san="$(printf '%s,' "${san_entries[@]}")"
    server_san="${server_san%,}"

    # Generate private key
    generate_key "${key_file}" "server"

    # Generate CSR
    local server_subj
    server_subj=$(build_subject "${SERVER_SUBJ}" "${server_cn}" "force")
    openssl req -new \
        -"${DIGEST_SERVER}" \
        -key "${key_file}" \
        -out "${csr_file}" \
        -subj "${server_subj}" || \
        die "Failed to generate server CSR"

    # Sign with Intermediate CA
    openssl x509 -req \
        -"${DIGEST_SERVER}" \
        -in "${csr_file}" \
        -CA "${int_cert}" \
        -CAkey "${int_key}" \
        -CAcreateserial \
        -days "${DAYS_SERVER}" \
        -out "${cert_file}" \
        -extfile <(cat <<-EOF
			basicConstraints=CA:FALSE
			keyUsage=critical,digitalSignature,keyEncipherment
			extendedKeyUsage=serverAuth,clientAuth
			subjectKeyIdentifier=hash
			authorityKeyIdentifier=keyid,issuer
			subjectAltName=${server_san}
		EOF
        ) || die "Failed to sign server certificate"

    # Clean up CSR
    rm -f "${csr_file}"

    # Create full certificate chain
    cat "${cert_file}" \
        "${WORK_DIR}/intermediate/intermediateCA.crt" > "${WORK_DIR}/server/fullchain.crt"

    info "Server certificate generated: ${cert_file}"
}

# Verify certificate chain
verify_chain() {
    info "Verifying certificate chain..."

    # Verify intermediate against root
    openssl verify \
        -CAfile "${WORK_DIR}/root/rootCA.crt" \
        "${WORK_DIR}/intermediate/intermediateCA.crt" || \
        die "Intermediate certificate verification failed"

    # Verify server against chain
    openssl verify \
        -CAfile "${WORK_DIR}/intermediate/ca-chain.crt" \
        "${WORK_DIR}/server/server.crt" || \
        die "Server certificate verification failed"

    info "Certificate chain verified successfully"
}

# Copy certificates to standard locations
install_certificates() {
    info "Installing certificates..."

    # Copy to PKI root for easy access
    cp "${WORK_DIR}/root/rootCA.key" "${WORK_DIR}/"
    cp "${WORK_DIR}/root/rootCA.crt" "${WORK_DIR}/"
    cp "${WORK_DIR}/intermediate/intermediateCA.key" "${WORK_DIR}/"
    cp "${WORK_DIR}/intermediate/intermediateCA.crt" "${WORK_DIR}/"
    cp "${WORK_DIR}/server/server.key" "${WORK_DIR}/"
    cp "${WORK_DIR}/server/server.crt" "${WORK_DIR}/"
    cp "${WORK_DIR}/server/fullchain.crt" "${WORK_DIR}/"

    info "Certificates installed to ${WORK_DIR}/"
}

# Display summary (moved customization tips to --help)
show_summary() {
    cat <<-EOF

	========================================
	Certificate Chain Generation Complete
	========================================

	Algorithms used:
	  Root CA:         $(algo_for root)
	  Intermediate CA: $(algo_for intermediate)
	  Server:          $(algo_for server)

	Digest algorithms used:
	  Root CA:         ${DIGEST_ROOT}
	  Intermediate CA: ${DIGEST_INTERMEDIATE}
	  Server:          ${DIGEST_SERVER}

	Generated files:
	  Root CA:
	    Private Key: ${WORK_DIR}/rootCA.key
	    Certificate: ${WORK_DIR}/rootCA.crt

	  Intermediate CA:
	    Private Key: ${WORK_DIR}/intermediateCA.key
	    Certificate: ${WORK_DIR}/intermediateCA.crt
	    Chain:       ${WORK_DIR}/intermediate/ca-chain.crt

	  Server:
	    Private Key: ${WORK_DIR}/server.key
	    Certificate: ${WORK_DIR}/server.crt
	    Full Chain:  ${WORK_DIR}/server/fullchain.crt

	To view certificate details:
	  openssl x509 -text -noout -in ${WORK_DIR}/server.crt

	To test with curl:
	  curl --cacert ${WORK_DIR}/rootCA.crt https://localhost

	(For customization examples, run: ${SCRIPT_NAME} --help)

	EOF
}

parse_args() {
    # Parse -algo, -d/--domain (repeatable) and -scn; keep -h/--help; fail on unknown options
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            -algo|--algo)
                shift
                [ $# -gt 0 ] || die "Option -algo requires a value: ec | rsa"
                case "$1" in
                    ec|rsa) KEY_ALGO="$1" ;;
                    *) die "Invalid -algo value: $1 (expected: ec | rsa)";;
                esac
                ;;
            -d|--domain)
                shift
                [ $# -gt 0 ] || die "Option -d|--domain requires a value"
                DOMAINS+=("$1")
                ;;
            -scn)
                shift
                [ $# -gt 0 ] || die "Option -scn requires a value"
                SERVER_SCN="$1"
                ;;
            -sr)
                shift
                [ $# -gt 0 ] || die "Option -sr requires a value"
                ROOT_SUBJ="$1"
                ;;
            -si)
                shift
                [ $# -gt 0 ] || die "Option -si requires a value"
                INTERMEDIATE_SUBJ="$1"
                ;;
            -ss)
                shift
                [ $# -gt 0 ] || die "Option -ss requires a value"
                SERVER_SUBJ="$1"
                ;;
            --)
                shift; break
                ;;
            -*)
                die "Unknown option: $1 (use -h for help)"
                ;;
            *)
                die "Unexpected argument: $1 (use -h for help)"
                ;;
        esac
        shift || true
    done
}

# --- Main ---

main() {
    parse_args "$@"
    check_requirements
    setup_directories
    generate_root_ca
    generate_intermediate_ca
    generate_server_cert
    verify_chain
    install_certificates
    show_summary
}

# Only run main if not being sourced
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi

