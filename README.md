# **SafeKeeping**

*A simple C++ library for securely storing secrets using the operating system's or desktop manager's vault.*

## **Why?**

I started working on a new command-line tool in **C++20** that connects to various servers using **gRPC** and **HTTPS**.
All these servers require authentication, using different methods:

* **HTTP Basic Authentication**
* **API keys**
* **X.509 certificate/key pairs**

Since this tool is meant for **production environments**, I don't want credentials to be stored **in plain text on disk**.
I needed a simple, cross-platform way to handle secrets securely.

On **Linux**, the library uses a native **KWallet** backend when running in a KDE session, and falls back to `libsecret` on other desktops.

## **Status**

Beta

## **Supported Platforms**

| Platform          | Status                                     |
| ----------------- | ------------------------------------------ |
| **Linux (KDE)**   | ✅ Works with native KWallet                  |
| **Linux (GNOME)** | ✅ Works with GNOME Keyring (GNOME Desktop) |
| **macOS**         | ✅ Works (Keychain Services)                |
| **Windows 10**    | ✅ Works (Credential Manager)               |
| **Windows 11**    | ✅ Works (Credential Manager)               |

## Storage Model

Each namespace lives under the user’s application data directory as:

* Linux: `~/.local/share/safekeeping/<namespace>/vault.db` unless `XDG_DATA_HOME` is set
* macOS: `~/Library/Application Support/safekeeping/<namespace>/vault.db`
* Windows: `%APPDATA%/safekeeping/<namespace>/vault.db`

Originally, the library stored secrets in the system's vault.
However, Windows Credential Manager has a 512-byte limit on secrets, so I was unable to store some PKI certificates, which I normally use for authentication.

In the current version of this library, the actual secrets are stored as encrypted blobs in a local SQLite database.
Only the decryption key is stored (per namespace) in the system’s vault.

On Linux, the current design stores one vault item per namespace unlock slot rather than one vault item per secret. KDE sessions store that item in a native KWallet folder named after the configured Linux vault root, while other Linux desktops store it through `libsecret`.

By default, the Linux vault root name is `com.jgaa.SafeKeeping`. Applications can override it during startup with `SafeKeeping::setLinuxVaultRootName(...)` to avoid collisions or to group entries under an application-specific folder/service name.

This new design also makes it possible to generate a recovery key, as well as use an additional password/passphrase, so data can be extracted from the vault (for example, from a backup) even if the system's secret vault is lost.
These are optional features, but they may prove quite useful.

The SQLite database stores:

* encrypted secret names
* encrypted secret values
* encrypted descriptions
* wrapped copies of the namespace encryption key for each unlock method

## Dependencies

Build-time dependencies:

* C++20 compiler
* CMake
* SQLite3
* libsodium
* GoogleTest (if building tests)

Platform dependencies:

* Linux: `libsecret`
* macOS: Security / CoreFoundation frameworks
* Windows: Credential Manager / `Advapi32`

### Arch Linux

Minimum practical install:

```bash
sudo pacman -S --needed base-devel cmake ninja git sqlite libsodium libsecret gtest
```

For a Linux vault provider, install one of:

```bash
sudo pacman -S --needed gnome-keyring
```

or

```bash
sudo pacman -S --needed kwallet
```

or

```bash
sudo pacman -S --needed keepassxc
```

### Debian

Build dependencies:

```bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build pkg-config git \
    libsqlite3-dev libsodium-dev libsecret-1-dev libgtest-dev
```

For a Linux vault provider at runtime, install one of:

```bash
sudo apt install -y gnome-keyring
```

or

```bash
sudo apt install -y kwalletmanager
```

### Ubuntu

Current Ubuntu LTS releases use the same core development package names as Debian:

```bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build pkg-config git \
    libsqlite3-dev libsodium-dev libsecret-1-dev libgtest-dev
```

For a Linux vault provider at runtime, install one of:

```bash
sudo apt install -y gnome-keyring
```

or

```bash
sudo apt install -y kwalletmanager
```

### Fedora

Build dependencies:

```bash
sudo dnf install -y gcc-c++ cmake ninja-build pkgconf-pkg-config git \
    sqlite-devel libsodium-devel libsecret-devel gtest-devel
```

For a Linux vault provider at runtime, install one of:

```bash
sudo dnf install -y gnome-keyring
```

or

```bash
sudo dnf install -y kwallet
```

## Build

```bash
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

## Public API

The rebooted API is centered around namespace lifecycle and explicit unlock methods.

Core operations:

* `SafeKeeping::createNew(...)`
* `SafeKeeping::open(...)`
* `SafeKeeping::exists(...)`
* `SafeKeeping::removeNamespace(...)`
* `storeSecret(...)`
* `storeSecretWithDescription(...)`
* `retrieveSecret(...)`
* `removeSecret(...)`
* `listSecrets()`

Unlock and slot management:

* `unlockWithSystemVault()`
* `unlockWithPassphrase(...)`
* `unlockWithRecoveryKey(...)`
* `lock()`
* `addSystemVaultSlot()`
* `addPassphrase(...)`
* `changePassphrase(...)`
* `removePassphrase()`
* `rotateRecoveryKey()`
* `removeRecoveryKey()`

See [include/safekeeping/SafeKeeping.h](/home/jgaa/src/SafeKeeping/include/safekeeping/SafeKeeping.h) for the full interface.

## Example

```cpp
// unchanged
```

## Operational Notes

* Secret operations require an unlocked namespace.
* Secret values are limited to 10,240 bytes.
* For binary payloads, use `storeSecret(..., std::span<const std::byte>)` and `retrieveSecretBytes(...)`.
* Instance methods clear `latestError()` before each operation and set it on failure.
* Secret names are validated and used through an encrypted-record model with a keyed lookup hash.
* Recovery keys are generated once and returned once. They are not retrievable later.
* At least one active unlock slot must remain.
* If the vault material is lost, the passphrase or recovery key can still unlock the namespace.
* If all unlock methods are lost, the data is unrecoverable by design.
