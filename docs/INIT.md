# uFastAuthD3 Initial Setup Guide

## 📖 Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure /etc/hosts for Local DNS](#step-1-configure-etchosts-for-local-dns)
- [Step 2: Generate and Install TLS/SSL Certificates](#step-2-generate-and-install-tlssl-certificates)
- [Step 3: Configure Internal URLs](#step-3-configure-internal-urls)
- [Step 4: Create Required Directories](#step-4-create-required-directories)
- [Step 5: Configure the Firewall](#step-5-configure-the-firewall)
- [Step 6: First Service Startup](#step-6-first-service-startup)
- [Step 7: Retrieve the Super-User Password](#step-7-retrieve-the-super-user-password)
- [Step 8: First Admin Login](#step-8-first-admin-login)
- [Verification](#verification)
- [Next Steps](#next-steps)

---

## Prerequisites

Ensure the following tools are installed on your system:

| Tool | Purpose | Install Command (Ubuntu/Debian) | Install Command (RHEL/CentOS) |
|------|---------|--------------------------------|-------------------------------|
| `openssl` | Crypto operations | `apt install openssl` | `dnf install openssl` |
| `systemd` | Service management | Pre-installed | Pre-installed |
| `ufw` or `firewalld` | Firewall configuration | `apt install ufw` | `dnf install firewalld` |
| `sqlite3` | Database verification | `apt install sqlite3` | `dnf install sqlite` |

For certificate generation, `easy-rsa` is recommended but optional — see [docs/CERTIFICATES.md](CERTIFICATES.md) for full details.

---

## Step 1: Configure /etc/hosts for Local DNS

If you do not have a DNS server configured for the uFastAuthD3 hostnames, use `/etc/hosts` on your machine (both the server and any client that will access the portals) to map the required hostnames to the server's IP address.

Edit `/etc/hosts` as root:

```bash
sudo editor /etc/hosts
```

Add the following lines, replacing `<server-ip>` with your server's actual IP address:

```
<server-ip>   login.localhost   admin.localhost   user.localhost
```

**Example:**

```
192.168.1.100   login.localhost   admin.localhost   user.localhost
```

---

## Step 2: Generate and Install TLS/SSL Certificates

For complete instructions on generating and installing TLS/SSL certificates, see **[docs/CERTIFICATES.md](CERTIFICATES.md)**.

---

## Step 3: Configure Internal URLs

uFastAuthD3 uses internal URLs for redirects, CORS origins, and proxy configurations. All references to `localhost` must be updated to match your deployment hostnames or IP addresses.

Define your base URLs:

```bash
# Example values — replace with your actual hostnames/IPs
LOGIN_URL="https://login.localhost:8443"
ADMIN_URL="https://admin.localhost:9443"
USER_URL="https://user.localhost:11443"
```

### 3.1 Main Configuration (`ufastauthd3.conf`)

Edit `/etc/ufastauthd3/ufastauthd3.conf`:

```ini
AppVars {
    LoginPortalURL "https://login.localhost:8443"
}
```

Update `LoginPortalURL` to your Login Portal URL.

### 3.2 Login Portal (`web_portal_login.conf`)

Edit `/etc/ufastauthd3/web_portal_login.conf`:

```ini
API {
    Origins "https://login.localhost:8443"
}
```

Update `Origins` to your Login Portal URL. Multiple origins can be comma-separated.

### 3.3 Admin Portal (`web_portal_admin.conf`)

Edit `/etc/ufastauthd3/web_portal_admin.conf`:

```ini
Redirections {
    "/login" "https://login.localhost:8443/?app=IAM_ADMPORTAL"
}
```

Update the Login URL in the redirection rule.

### 3.4 User Portal (`web_portal_user.conf`)

Edit `/etc/ufastauthd3/web_portal_user.conf`:

```ini
Redirections {
    "/login" "https://login.localhost:8443/?app=IAM_USRPORTAL"
}
```

Update the Login URL in the redirection rule.

### 3.5 Auth Handler (`web_authhandler.conf`)

Edit `/etc/ufastauthd3/web_authhandler.conf`:

```ini
Login {
    Origins "https://login.localhost:8443"
}
```

Update `Origins` to your Login Portal URL.

---

## Step 4: Create Required Directories

Ensure the runtime directories exist and have the correct permissions:

```bash
# Create the database directory
sudo mkdir -p /var/lib/ufastauthd3

# Create the logs directory
sudo mkdir -p /var/log/ufastauthd3

# Set ownership (adjust user/group as needed for your deployment)
sudo chown root:root /var/lib/ufastauthd3
sudo chown root:root /var/log/ufastauthd3

# Set directory permissions
sudo chmod 0755 /var/lib/ufastauthd3
sudo chmod 0755 /var/log/ufastauthd3
```

---

## Step 5: Configure the Firewall

Open the required ports for public-facing services. Internal services (AppSync on 7081, AuthHandler on 7080) bind to localhost and do not require firewall rules.

### Required Ports

| Port | Protocol | Service | Direction | Required |
|------|----------|---------|-----------|----------|
| 8443 | TCP | Login Portal | Inbound | Yes |
| 9443 | TCP | Admin Portal | Inbound | Yes |
| 11443 | TCP | User Portal | Inbound | Yes |

### UFW (Ubuntu/Debian)

```bash
# Enable UFW if not already enabled
sudo ufw enable

# Allow Login Portal
sudo ufw allow 8443/tcp comment 'uFastAuthD3 Login Portal'

# Allow Admin Portal
sudo ufw allow 9443/tcp comment 'uFastAuthD3 Admin Portal'

# Allow User Portal
sudo ufw allow 11443/tcp comment 'uFastAuthD3 User Portal'

# Optional: Restrict Admin Portal to specific IP ranges
# sudo ufw delete allow 9443/tcp comment 'uFastAuthD3 Admin Portal'
# sudo ufw allow from 192.168.1.0/24 to any port 9443 proto tcp comment 'uFastAuthD3 Admin Portal (restricted)'

# Verify rules
sudo ufw status verbose
```

### FirewallD (RHEL/CentOS/Fedora)

```bash
# Allow required ports
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --permanent --add-port=9443/tcp
sudo firewall-cmd --permanent --add-port=11443/tcp

# Apply changes
sudo firewall-cmd --reload

# Verify rules
sudo firewall-cmd --list-ports
```

---

## Step 6: First Service Startup

Enable+Start the uFastAuthD3 service:

```bash
sudo systemctl enable --now ufastauthd3.service
```

Check the service status:

```bash
sudo systemctl status ufastauthd3.service
```

Expected output should show `active (running)`.

View the startup logs:

```bash
sudo journalctl -xefu ufastauthd3 --no-pager -n 50
```

Verify all ports are listening:

```bash
ss -tlnp | grep -E '(8443|9443|11443|7080|7081)'
```

Expected output:

```
tcp  0  0  0.0.0.0:8443    0.0.0.0:*   LISTEN  .../ufastauthd3
tcp  0  0  0.0.0.0:9443    0.0.0.0:*   LISTEN  .../ufastauthd3
tcp  0  0  0.0.0.0:11443   0.0.0.0:*   LISTEN  .../ufastauthd3
tcp  0  0  127.0.0.1:7080  0.0.0.0:*   LISTEN  .../ufastauthd3
tcp  0  0  127.0.0.1:7081  0.0.0.0:*   LISTEN  .../ufastauthd3
```

---

## Step 7: Retrieve the Super-User Password

On the very first startup, uFastAuthD3 automatically generates a temporary super-user password for the `admin` account. The password is written to a temporary file, and the path is logged to the systemd journal.

### Find the Temporary Password File

```bash
sudo journalctl -xefu ufastauthd3 | grep "super-user password"
```

You will see a message similar to:

```
File '/tmp/syspwd-98ZAisMO' created with the super-user password. Login and change it immediately.
```

### Read the Temporary Password

```bash
cat /tmp/syspwd-98ZAisMO
```

**Security Warning:** This temporary file is automatically deleted after a certain period. If the file is no longer available, use the admin password reset procedure:

```bash
sudo systemctl stop ufastauthd3.service
ufastauthd3 -r
# Check logs for the new password
sudo journalctl -xefu ufastauthd3 | grep "super-user password"
```

---

## Step 8: First Admin Login

Access the Login Portal in your web browser:

```
https://login.localhost:8443
```

Since the certificates are self-signed (issued by your local CA), your browser may display a security warning, if so, install your CA certificate in the browser's trust store.

Log in with the following credentials:

| Field | Value |
|-------|-------|
| **Username** | `admin` |
| **Password** | (The temporary password retrieved in Step 7) |

During the first logging in, you will be asked to change the admin password.

And after logging in, you will be redirected to the User Portal.

---

## Verification

After completing all steps, verify your installation:

### Service Status

```bash
systemctl is-active ufastauthd3.service    # Expected: active
systemctl is-enabled ufastauthd3.service   # Expected: enabled
```

### Ports Listening

```bash
ss -tlnp | grep -E '(8443|9443|11443|7080|7081)'
```

### Database Integrity

```bash
sqlite3 /var/lib/ufastauthd3/main.db "PRAGMA integrity_check;"
# Expected: ok
```

### Web Portals Access

| Portal | URL | Expected |
|--------|-----|----------|
| Login Portal | `https://login.localhost:8443` | Login page loads |
| Admin Portal | `https://admin.localhost:9443/admin` | Redirects to login, then admin dashboard |
| User Portal | `https://user.localhost:11443/user` | Redirects to login, then user dashboard |

### Log Files

```bash
# Verify log files are being created
ls -l /var/log/ufastauthd3/
# Expected: main.db, logs.db, and .log files for each service
```

---

## Next Steps

Once uFastAuthD3 is running, refer to the following documents:

- **[docs/OPERATION.md](OPERATION.md)** — Daily operations, logging, backups, and maintenance
- **[docs/CERTIFICATES.md](CERTIFICATES.md)** — X.509 certificate generation, renewal, and maintenance
- **[docs/CONFIG.md](CONFIG.md)** — Detailed configuration reference for all web services
- **[docs/SECURITY.md](SECURITY.md)** — Security hardening guidelines
- **[docs/ARCHITECTURE.md](ARCHITECTURE.md)** — System architecture and component overview

---

## References

- [Architecture Documentation](ARCHITECTURE.md)
- [Build Instructions](BUILD.md)
- [Certificate Management](CERTIFICATES.md) — X.509 certificate generation, renewal, revocation
- [Configuration Guide](CONFIG.md)
- [Operation Guide](OPERATION.md)
- [Security Documentation](SECURITY.md)
- [Main README](../README.md)