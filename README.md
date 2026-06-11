# uFastAuthD3 (Unmanarc Fast Authentication Daemon 3)

**Author:** Aaron Mizrachi (unmanarc) <dev@unmanarc.com>
**License:** [SSPL-1.0](https://spdx.org/licenses/SSPL-1.0.html) (Dual Licensing Available)
**Version:** 3.0.0

---

A lightweight **Identity and Access Management (IAM)** system designed for secure, stateless authentication in resource-constrained environments. Built in **C++20**, uFastAuthD3 provides fast and reliable authentication services for web applications, microservices, and IoT devices, even on platforms like the **Raspberry Pi**.

---

## 📖 Table of Contents

- [✨ Overview](#-overview)
- [🚀 Key Features](#-key-features)
- [🏗️ Architecture & Components](#️-architecture--components)
- [📦 Build & Installation](#-build--installation)
- [🚀 Initial Setup](#-initial-setup)
- [📁 Configuration](#-configuration)
- [🔒 Certificate Management](#-certificate-management)
- [🌐 Web Portals](#-web-portals)
- [🔐 Security](#-security)
- [🏃 Running the Service](#-running-the-service)
- [📄 License](#-license)
- [👤 Author](#-author)
- [🔗 Links](#-links)

---

## ✨ Overview

uFastAuthD3 is a full-featured IAM daemon that handles user identity, authentication, authorization, and session management through a modular architecture. It uses **SQLite3** as its local database backend and **JWT (JSON Web Tokens)** for secure, stateless token-based authentication.

The system is composed of multiple web services, each running on a dedicated port, providing:

- **Single Sign-On (SSO)** across multiple applications
- **Role-Based Access Control (RBAC)** with configurable scopes
- **Self-service user portals** for account management
- **Administrator portals** for full system control
- **Direct application integration** via HTTP API

The architecture is designed to minimize token consumption while preserving full functionality and security, allowing easy integration with any client-side application via proxy or direct API calls.

---

## 🚀 Key Features

- **🔑 JWT Authentication** — Stateless JSON Web Tokens for secure, token-based authentication with short-lived access tokens and refresh tokens
- **🧩 Microservices Architecture** — Modular design with independent web services for seamless integration with distributed systems
- **💾 Local SQLite3 Database** — Thread-safe database access using read-write mutexes, reducing external dependencies
- **🔒 Secure Authentication** — Passwords are hashed and sessions are encrypted using SSL/TLS
- **📱 Two-Factor Authentication (2FA)** — Optional 2FA via TOTP for heightened security
- **🏢 Multi-Application Support** — Manage multiple applications, user roles, and scopes within a single instance
- **🎯 Role-Based Access Control** — Fine-grained permissions using scopes and roles per application
- **📉 Ultra-Low Footprint** — Optimized for minimal resource usage (RAM, CPU, storage)
- **🖥️ Cross-Platform** — Works on Linux (Ubuntu, CentOS, Fedora, Raspbian)
- **🔌 Proxy-Based Integration** — Inject tokens as cookies into your applications with no additional coding required

---

## 🏗️ Architecture & Components

For a detailed overview of the system architecture, including backend modules, web services, database structure, and endpoint configuration, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 📦 Build & Installation

For detailed build and installation instructions, see [docs/BUILD.md](docs/BUILD.md).

---

## 🚀 Initial Setup

For a complete, step-by-step guide to configuring uFastAuthD3 for the first time, see **[docs/INIT.md](docs/INIT.md)**. This guide covers:

- Configuring `/etc/hosts` for local DNS resolution
- Generating TLS/SSL certificates with Easy-RSA
- Installing certificates and generating the JWT HMAC secret key
- Configuring internal URLs across all configuration files
- Creating required directories and enabling the systemd service
- Firewall configuration
- First service startup and retrieving the temporary super-user password

---

## 🔒 Certificate Management

For a comprehensive guide on X.509 certificate generation, renewal, revocation, and maintenance using Easy-RSA PKI, see **[docs/CERTIFICATES.md](docs/CERTIFICATES.md)**. This guide covers:

- Building a local Certificate Authority (CA) with Easy-RSA
- Generating server and client certificates
- Installing certificates for uFastAuthD3
- Certificate renewal and revocation procedures
- Importing CA certificates into browser trust stores
- Multi-server deployment strategies

---

## 📁 Configuration

uFastAuthD3 uses a modular configuration system with the main configuration file located at `/etc/ufastauthd3/ufastauthd3.conf`. For detailed configuration instructions, including all web service configurations, TLS setup, command-line options, best practices, and troubleshooting, see **[docs/CONFIG.md](docs/CONFIG.md)**.

---

## 🌐 Web Portals

For detailed information on the web portals (Admin, Login, User) and shared resources, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) under the "Website Structure" section.

---

## 🔐 Security

For detailed security information including architecture design, cookie handling, AppSync API security, and password management policies, see [docs/SECURITY.md](docs/SECURITY.md).

---

## 🏃 Running the Service

For detailed operational guidance including service management, logging, daily operations, maintenance tasks, and troubleshooting, see [docs/OPERATION.md](docs/OPERATION.md).

---

## 📄 License

**SPDX-License-Identifier:** SSPL-1.0 OR LicenseRef-Commercial

This software is offered under a **dual-licensing model**:

1. **Server Side Public License, version 1 (SSPL v1)** — As published by MongoDB, Inc.
2. **Commercial/Proprietary License** — Granted directly by the copyright holder

You may choose and comply with either license. For commercial licensing options, contact:

**Aaron Mizrachi** <dev@unmanarc.com>

See the [LICENSE](LICENSE) file for full details.

**OpenSSL Linking Exception:** A special exception permits linking this program with the OpenSSL library under specific conditions. See the LICENSE file for details.

---

## 👤 Author

**Aaron Mizrachi (unmanarc)**
- Email: [dev@unmanarc.com](mailto:dev@unmanarc.com)

---

## 🔗 Links

- **Repository:** [github.com/unmanarc/uFastAuthD3](https://github.com/unmanarc/uFastAuthD3)
- **License:** [SSPL-1.0 on SPDX](https://spdx.org/licenses/SSPL-1.0.html)
- **SSPL Full Text:** [mongodb.com/licensing/server-side-public-license](https://www.mongodb.com/licensing/server-side-public-license)