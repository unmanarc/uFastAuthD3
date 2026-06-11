# uFastAuthD3 X.509 Certificate Management

## 📖 Table of Contents

- [Overview](#overview)
- [Certificate Directory Structure](#certificate-directory-structure)
- [Service Overview](#service-overview)
- [Development Setup: Easy-RSA PKI](#development-setup-easy-rsa-pki)
  - [Installing Easy-RSA](#installing-easy-rsa)
  - [Initializing the PKI](#initializing-the-pki)
  - [Building the Certificate Authority (CA)](#building-the-certificate-authority-ca)
  - [Generating Server Certificates](#generating-server-certificates)
  - [Installing Certificates](#installing-certificates)
- [Updating Service Configuration](#updating-service-configuration)
- [Production Certificates](#production-certificates)
- [Troubleshooting](#troubleshooting)
- [References](#references)

---

## Overview

This guide covers X.509 certificate generation and installation for uFastAuthD3. It supports two approaches:

- **Easy-RSA PKI** — Full Certificate Authority (CA) for development deployments
- **External CA** — Production certificates from a trusted external authority

uFastAuthD3 requires TLS certificates for all public-facing web services. Each service runs under its own domain and requires a **dedicated certificate** with the correct Common Name (CN). All certificates are signed by a shared Certificate Authority (CA) and stored in per-service subdirectories under `/etc/ufastauthd3/tls/`.

**Note:** All commands in this guide should be run as **root**.

---

## ⚠️ CRITICAL: Unique Certificate per Service — Cookie Isolation Requirement

**Every service in uFastAuthD3 requires its own dedicated TLS certificate with a distinct Common Name (CN).** This is a mandatory architectural requirement, not a recommendation.

### The Problem: Cookie Confusion with Shared Domains

uFastAuthD3 relies heavily on HTTP cookies to manage authentication sessions across its services (Login Portal, Admin Portal, User Portal, AppSync). Browsers scope cookies by **domain**. When multiple services share the same domain (same CN in their certificate), the following critical failures occur:

| Failure Mode | Description |
|--------------|-------------|
| **Session Collision** | Cookies set by one service are sent to all other services on the same domain. The receiving service interprets incorrect session data, causing authentication failures or unauthorized access. |
| **Redirect Loops** | The authentication flow uses cookie-based state tracking across redirects between services. Shared domains cause cookies to overwrite each other, breaking the redirect chain and producing infinite login loops. |
| **Cookie Corruption** | `Set-Cookie` headers from one service inadvertently overwrite cookies from another service on the same domain, making the entire authentication system unreliable and inoperable. |
| **CORS Breakdown** | Origin-based access controls fail when multiple services share a domain, potentially exposing admin endpoints to user-level requests. |

**The bottom line:** If two or more services run on the same domain with the same certificate CN, cookie confusion will make the system **impossible to operate correctly.** Each service must have a unique domain and a certificate with a matching CN.

### Required Configuration

| Service | Certificate Subdirectory | Required CN | Domain |
|---------|-------------------------|-------------|--------|
| Login Portal | `tls/login/` | `login.localhost` | `login.localhost:8443` |
| Admin Portal | `tls/iamadmin/` | `iamadmin.localhost` | `iamadmin.localhost:9443` |
| User Portal | `tls/iamuser/` | `iamuser.localhost` | `iamuser.localhost:11443` |
| AppSync | `tls/appsync/` | `appsync.localhost` | `appsync.localhost:7081` |

When generating certificates, ensure each `build-server-full` command uses a **different** Common Name corresponding to its service domain. Never reuse a single certificate across multiple services.

---

## Certificate Directory Structure

```
/etc/ufastauthd3/tls/
├── ca.crt                        # CA public certificate (shared across all services)
├── ca.key                        # CA private key (keep secure!)
│
├── login/                        # Login Portal certificates
│   ├── server.crt                # CN = login.localhost (or your domain)
│   └── server.key                # Private key (permissions: 0600)
│
├── iamadmin/                     # Admin Portal certificates
│   ├── server.crt                # CN = iamadmin.localhost (or your domain)
│   └── server.key
│
├── iamuser/                      # User Portal certificates
│   ├── server.crt                # CN = iamuser.localhost (or your domain)
│   └── server.key
│
└── appsync/                      # AppSync service certificates
    ├── server.crt                # CN = appsync.localhost (or your domain)
    └── server.key
```

**Important:** The `SessionAuthHandler` service listens on `127.0.0.1:7080` with `UseTLS false` by default, so it does **not** require a certificate.

---

## Service Overview

Each web service in uFastAuthD3 has its own domain and must use a certificate with a matching Common Name (CN).

| Service | Config File | Default Domain | Port | Certificate Path |
|---|---|---|---|---|
| **Login Portal** | `web_portal_login.conf` | `login.localhost` | 8443 | `tls/login/server.crt` |
| **Admin Portal** | `web_portal_admin.conf` | `iamadmin.localhost` | 9443 | `tls/iamadmin/server.crt` |
| **User Portal** | `web_portal_user.conf` | `iamuser.localhost` | 11443 | `tls/iamuser/server.crt` |
| **AppSync** | `web_appsync.conf` | `appsync.localhost` | 7081 | `tls/appsync/server.crt` |

When generating certificates, use the domain name that matches your deployment. The examples in this guide use the default domains shown above.

---

## Development Setup: Easy-RSA PKI

Easy-RSA provides a complete PKI (Public Key Infrastructure) with a private Certificate Authority for signing server certificates. All services share the same CA but have their own signed certificate. This setup is suitable for **development and testing**.

### Installing Easy-RSA

```bash
# Debian/Ubuntu
apt install easy-rsa

# RHEL/CentOS/Fedora
dnf install easy-rsa

# Or install from GitHub
git clone https://github.com/OpenVPN/easy-rsa.git
cd easy-rsa/easyrsa3
make install
```

Verify the installation:

```bash
easyrsa --version
```

### Initializing the PKI

Create a dedicated directory for your PKI and initialize it:

```bash
# Create PKI working directory
mkdir -p /etc/ufastauthd3/pki

cd /etc/ufastauthd3/pki

# Initialize the PKI structure
easyrsa init-pki
```

This creates the `pki/` directory with the necessary structure for key management.

### Building the Certificate Authority (CA)

```bash
cd /etc/ufastauthd3/pki

# Build the CA (interactive — will prompt for passphrase and distinguished name)
easyrsa build-ca
```

You will be prompted for:
1. **CA Private Key passphrase** — Choose a strong passphrase and store it securely
2. **Common Name** — Enter a name for your CA, e.g., `uFastAuthD3 CA`

This generates:
- `pki/ca.crt` — The CA public certificate (distributed to clients)
- `pki/ca.key` — The CA private key (keep this secure, never share)

### Generating Server Certificates

Generate a certificate for each service using its domain as the Common Name:

```bash
cd /etc/ufastauthd3/pki

# Generate a certificate for each service
easyrsa build-server-full login.localhost nopass
easyrsa build-server-full iamadmin.localhost nopass
easyrsa build-server-full iamuser.localhost nopass
easyrsa build-server-full appsync.localhost nopass
```

Parameters explained:
- `build-server-full` — Generates a CSR, signs it with the CA, and produces the final certificate
- `<domain>` — The Common Name (CN) for the service certificate (must match the service domain)
- `nopass` — No passphrase on the private key (required for daemon auto-start)

This generates per-service files:
- `pki/issued/<domain>.crt` — The signed server certificate
- `pki/private/<domain>.key` — The server private key

### Installing Certificates

Copy each certificate to its service-specific subdirectory:

```bash
# Create service directories
mkdir -p /etc/ufastauthd3/tls/{login,iamadmin,iamuser,appsync}

# Copy CA certificate (shared)
cp /etc/ufastauthd3/pki/ca.crt /etc/ufastauthd3/tls/ca.crt

# Copy each service certificate and key
cp /etc/ufastauthd3/pki/issued/login.localhost.crt /etc/ufastauthd3/tls/login/server.crt
cp /etc/ufastauthd3/pki/private/login.localhost.key /etc/ufastauthd3/tls/login/server.key

cp /etc/ufastauthd3/pki/issued/iamadmin.localhost.crt /etc/ufastauthd3/tls/iamadmin/server.crt
cp /etc/ufastauthd3/pki/private/iamadmin.localhost.key /etc/ufastauthd3/tls/iamadmin/server.key

cp /etc/ufastauthd3/pki/issued/iamuser.localhost.crt /etc/ufastauthd3/tls/iamuser/server.crt
cp /etc/ufastauthd3/pki/private/iamuser.localhost.key /etc/ufastauthd3/tls/iamuser/server.key

cp /etc/ufastauthd3/pki/issued/appsync.localhost.crt /etc/ufastauthd3/tls/appsync/server.crt
cp /etc/ufastauthd3/pki/private/appsync.localhost.key /etc/ufastauthd3/tls/appsync/server.key

# Set restrictive permissions on all private keys
chmod 0600 /etc/ufastauthd3/tls/*/server.key
chmod 0600 /etc/ufastauthd3/pki/ca.key
chmod 0600 /etc/ufastauthd3/pki/private/*.key

# Restrict PKI directory access
chmod 0700 /etc/ufastauthd3/pki
```

---

## Updating Service Configuration

After installing the certificates, each web service configuration must be updated to point to its dedicated certificate and key. Below are the exact changes for each service.

### Login Portal (`web_portal_login.conf`)

```ini
# Before (default):
TLS
{
    CertFile "etc/ufastauthd3/tls/snakeoil.crt"
    KeyFile  "etc/ufastauthd3/tls/snakeoil.key"
}

# After (Login Portal):
TLS
{
    CertFile "etc/ufastauthd3/tls/login/server.crt"
    KeyFile  "etc/ufastauthd3/tls/login/server.key"
}
```

### Admin Portal (`web_portal_admin.conf`)

```ini
# Before (default):
TLS
{
    CertFile "etc/ufastauthd3/tls/snakeoil.crt"
    KeyFile  "etc/ufastauthd3/tls/snakeoil.key"
}

# After (Admin Portal):
TLS
{
    CertFile "etc/ufastauthd3/tls/iamadmin/server.crt"
    KeyFile  "etc/ufastauthd3/tls/iamadmin/server.key"
}
```

### User Portal (`web_portal_user.conf`)

```ini
# Before (default):
TLS
{
    CertFile "etc/ufastauthd3/tls/snakeoil.crt"
    KeyFile  "etc/ufastauthd3/tls/snakeoil.key"
}

# After (User Portal):
TLS
{
    CertFile "etc/ufastauthd3/tls/iamuser/server.crt"
    KeyFile  "etc/ufastauthd3/tls/iamuser/server.key"
}
```

### AppSync (`web_appsync.conf`)

```ini
# Before (default):
TLS
{
    CertFile "etc/ufastauthd3/tls/snakeoil.crt"
    KeyFile  "etc/ufastauthd3/tls/snakeoil.key"
}

# After (AppSync):
TLS
{
    CertFile "etc/ufastauthd3/tls/appsync/server.crt"
    KeyFile  "etc/ufastauthd3/tls/appsync/server.key"
}
```

### Restart Services

After updating the configuration, restart the uFastAuthD3 service:

```bash
systemctl restart ufastauthd3.service
```

---

## Production Certificates

For production deployments, you should use certificates issued by a trusted external Certificate Authority (CA) such as Let's Encrypt, commercial CAs, or your organization's internal PKI. The exact procedure depends on your infrastructure.

**Important:** For production, **TLS must be enabled on ALL web services** (Login Portal, Admin Portal, User Portal, and AppSync). Every public-facing service must use valid certificates.

### Domain Configuration

Before obtaining production certificates, ensure your service domains are properly configured in your public DNS:

- `login.yourdomain.com` → Points to your server's IP
- `iamadmin.yourdomain.com` → Points to your server's IP
- `iamuser.yourdomain.com` → Points to your server's IP
- `appsync.yourdomain.com` → Points to your server's IP

Each certificate must have a **Common Name (CN)** matching its configured public DNS name.

### Obtaining Certificates

Depending on your CA:

- **Let's Encrypt / certbot** — Use `certbot certonly -d login.yourdomain.com -d iamadmin.yourdomain.com ...` to obtain certificates for each service domain
- **Commercial CA** — Generate a CSR per service with `openssl req -new`, submit it to your CA, and install the returned certificate
- **Internal Enterprise PKI** — Follow your organization's certificate enrollment process

### Installing Production Certificates

Regardless of the source, once you have your certificates:

1. Copy each certificate and key to its service subdirectory (`tls/login/`, `tls/iamadmin/`, etc.)
2. Ensure proper file permissions (`0600` on private keys)
3. Update each service configuration file as described in [Updating Service Configuration](#updating-service-configuration)
4. Ensure `UseTLS true` is set in **every** service configuration
5. Restart the service: `systemctl restart ufastauthd3.service`

---

## Troubleshooting

### Verifying Certificate and Key Match

Each TLS certificate must have a matching private key. Verify they match by comparing their modulus:

```bash
# Example for Login Portal
openssl x509 -noout -modulus -in /etc/ufastauthd3/tls/login/server.crt | md5sum
openssl rsa -noout -modulus -in /etc/ufastauthd3/tls/login/server.key | md5sum
```

The two MD5 hashes must be identical. If they differ, the certificate and key do not belong together.

Repeat this check for each service:

```bash
# Admin Portal
openssl x509 -noout -modulus -in /etc/ufastauthd3/tls/iamadmin/server.crt | md5sum
openssl rsa -noout -modulus -in /etc/ufastauthd3/tls/iamadmin/server.key | md5sum

# User Portal
openssl x509 -noout -modulus -in /etc/ufastauthd3/tls/iamuser/server.crt | md5sum
openssl rsa -noout -modulus -in /etc/ufastauthd3/tls/iamuser/server.key | md5sum

# AppSync
openssl x509 -noout -modulus -in /etc/ufastauthd3/tls/appsync/server.crt | md5sum
openssl rsa -noout -modulus -in /etc/ufastauthd3/tls/appsync/server.key | md5sum
```

### Checking Certificate Expiration

Verify when a certificate expires:

```bash
# Check Login Portal certificate expiration
openssl x509 -enddate -noout -in /etc/ufastauthd3/tls/login/server.crt

# Check all service certificates
for svc in login iamadmin iamuser appsync; do
    echo "=== $svc ==="
    openssl x509 -enddate -noout -in /etc/ufastauthd3/tls/$svc/server.crt
done
```

To see full certificate details including issuer, subject, and SANs:

```bash
openssl x509 -in /etc/ufastauthd3/tls/login/server.crt -noout -text
```

### Verifying Key File Permissions

Private keys must have restrictive permissions (`0600`) to prevent unauthorized access:

```bash
# Check permissions on all private keys
ls -l /etc/ufastauthd3/tls/*/server.key

# Fix permissions if needed
chmod 0600 /etc/ufastauthd3/tls/*/server.key
chmod 0600 /etc/ufastauthd3/tls/ca.key
```

### Common Issues

| Problem | Possible Cause | Solution |
|---------|----------------|----------|
| TLS handshake fails | Certificate and key don't match | Regenerate or obtain correct matching pair |
| Service refuses to start | Private key has loose permissions | Set `chmod 0600` on the key file |
| Browser shows certificate warning | Self-signed cert or CN mismatch | Use proper CN or install CA cert in browser trust store |
| "certificate has expired" error | Certificate past expiry date | Generate/renew the certificate |
| "unable to load certificate" error | Incorrect file path in config | Verify `CertFile` and `KeyFile` paths in service config |

---

## References

- [Initial Setup Guide](INIT.md) — First-time installation and configuration
- [Configuration Guide](CONFIG.md) — TLS configuration reference
- [Operation Guide](OPERATION.md) — Service management and maintenance
- [Security Documentation](SECURITY.md) — Security best practices
- [Easy-RSA Documentation](https://github.com/OpenVPN/easy-rsa) — Official Easy-RSA docs