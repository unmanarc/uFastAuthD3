# Build and Installation Guide

This guide provides detailed instructions for building and installing uFastAuthD3 from source.

---

## ⚙️ System Requirements

### Operating System
- systemd-enabled Linux distribution (Ubuntu, CentOS, Fedora, Debian, etc.)

### Compiler
- GCC or Clang with **C++20** support

### Build Dependencies
- **CMake** >= 3.12
- **libMantids30** (development and SQLite packages)
- **SQLite3** (development headers)
- **OpenSSL** (development headers)
- **jsoncpp** (development headers)
- **Boost** (regex, thread components)
- **pthread**
- **zlib** (development headers)

### Runtime Dependencies
- systemd (service management)
- libMantids30 runtime libraries
- OpenSSL runtime libraries

---

## 🔧 Installation & Build

### Step 1: Install Prerequisites

**Debian/Ubuntu:**
```bash
sudo apt-get install build-essential cmake libsqlite3-dev libssl-dev libjsoncpp-dev libboost-dev libboost-regex-dev libboost-thread-dev zlib1g-dev pkg-config
```

**Red Hat/CentOS/Fedora:**
```bash
sudo yum install gcc-c++ cmake sqlite-devel openssl-devel jsoncpp-devel boost-devel zlib-devel pkg-config
```

### Step 2: Clone and Build

```bash
cd /root
git clone https://github.com/unmanarc/uFastAuthD3
cmake -B../builds/uFastAuthD3 ./uFastAuthD3 -DCMAKE_VERBOSE_MAKEFILE=ON
cd ../builds/uFastAuthD3
make -j12 install
```

### Step 3: Install Configuration Files

```bash
cp -a ~/uFastAuthD3/etc/ufastauthd3 /etc/
chmod 600 /etc/ufastauthd3/snakeoil.key
mkdir -p /var/www
mkdir -p /var/lib/ufastauthd3
rm -rf /var/www/ufastauthd3
cp -a ~/uFastAuthD3/var/www/ufastauthd3 /var/www
```

> **⚠️ Security Alert:** Replace the default snakeoil X.509 certificates with your own production certificates. Failure to do so may allow communication to be eavesdropped or tampered with.

## 📖 Additional Documentation

- **[Initial Setup Guide](INIT.md)** — One-time initial configuration, including TLS certificates, JWT keys, first startup, and super-user login
- **[Configuration Guide](CONFIG.md)** — Detailed configuration instructions for all services, TLS setup, command-line options, best practices, and troubleshooting
- **[Architecture Documentation](ARCHITECTURE.md)** — System architecture and component overview
- **[Security Documentation](SECURITY.md)** — Security considerations and best practices
