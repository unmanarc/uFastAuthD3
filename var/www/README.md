# Managing Web Resource Dependencies

## Update Packages
This command updates the specified npm packages to their latest versions available in the registry, modifying the `package-lock.json` and updating the `node_modules` directory accordingly.

```bash
npm install -D browserify terser
npm update jquery bootstrap datatables.net datatables.net-bs5 @fortawesome/fontawesome-free jssha qrcode otplib
```

## Install files into the project

This command executes the build process defined in the project's `package.json` file, which compiles, processes, and copies the downloaded resources into the `ufastauthd3/global/assets/` directory structure for direct use in the application.

```bash
npm run build-assets
```

### 📦 Managed Dependencies
| Package | Purpose |
| :--- | :--- |
| `jquery` & `bootstrap` | Core UI framework & JavaScript utilities |
| `datatables.net` & `datatables.net-dt` | Advanced table sorting, searching, and pagination |
| `@fortawesome/fontawesome-free` | Icon library |
| `jssha` | Client-side SHA cryptographic hashing |
| `qrcodejs` (`^1.5.6`) | QR code generation for 2FA setup *(replaces `qrcode-generator`)* |
| `otplib` (`^13.4.0`) | TOTP generation & verification for Two-Factor Authentication |
