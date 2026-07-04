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

On **Linux**, the library uses `libsecret` by default and can optionally use a dedicated `KWallet` backend when built with KDE wallet support.

## **Status**

Beta

## **Supported Platforms**

| Platform          | Status                                     |
| ----------------- | ------------------------------------------ |
| **Linux (KDE)**   | ✅ Works with KWallet or Secret Service     |
| **Linux (GNOME)** | ✅ Works with GNOME Keyring (GNOME Desktop) |
| **macOS**         | ✅ Works (Keychain Services)                |
| **Windows 10**    | ✅ Works (Credential Manager)               |
| **Windows 11**    | ✅ Works (Credential Manager)               |
| **Android**       | ⚠️ First iteration: NDK-only file backend   |

## Storage Model

Each namespace lives under the user’s application data directory as:

* Linux: `~/.local/share/safekeeping/<namespace>/vault.db` unless `XDG_DATA_HOME` is set
* macOS: `~/Library/Application Support/safekeeping/<namespace>/vault.db`
* Windows: `%APPDATA%/safekeeping/<namespace>/vault.db`
* Android: `$SAFEKEEPING_DATA_DIR/<namespace>/...` when set, otherwise `$HOME/files/safekeeping/<namespace>/...`

Originally, the library stored secrets in the system's vault.
However, Windows Credential Manager has a 512-byte limit on secrets, so I was unable to store some PKI certificates, which I normally use for authentication.

In the current version of this library, the actual secrets are stored as encrypted blobs in a local SQLite database.
Only the decryption key is stored (per namespace) in the system’s vault.

On Linux, the current design stores one vault item per namespace unlock slot rather than one vault item per secret. That item is stored through the selected Linux vault backend.

KWallet needs its own backend because KDE Wallet is not just a drop-in `libsecret` target in all deployments. KDE exposes a native wallet API with its own collection and access model, and this library now needs deterministic backend selection so a namespace created under KWallet keeps using KWallet after initialization. Without a dedicated backend, KDE-specific selection and backend pinning would not be reliable.

By default, the Linux vault root name is `com.jgaa.SafeKeeping`. Applications can override it during startup with `SafeKeeping::setLinuxVaultRootName(...)` to avoid collisions or to group entries under an application-specific service name.

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

* Linux: `libsecret` always, plus optional `KF6Wallet` development files when building with `-DSAFEKEEPING_ENABLE_KWALLET=ON` on Linux.
* macOS: Security / CoreFoundation frameworks
* Windows: Credential Manager / `Advapi32`
* Android: NDK only in the current implementation

### Arch Linux

Minimum practical install:

```bash
sudo pacman -S --needed base-devel cmake ninja git sqlite libsodium libsecret gtest
```

If you want to build with `KWallet` support enabled:

```bash
sudo pacman -S --needed kwallet
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

If you want to build with `KWallet` support enabled:

```bash
sudo apt install -y libkf6wallet-dev
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

If you want to build with `KWallet` support enabled:

```bash
sudo apt install -y libkf6wallet-dev
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

If you want to build with `KWallet` support enabled:

```bash
sudo dnf install -y kwallet-devel
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

To disable the optional KDE wallet backend at configure time:

```bash
cmake -S . -B build -G Ninja -DSAFEKEEPING_ENABLE_KWALLET=OFF
```

## Android Notes

The Android target currently builds a separate implementation that avoids `SQLite3`, `libsodium`, `libsecret`, and `KWallet`.

Behavior in this first pass:

* storage is file-based under the app-private area
* secrets are not encrypted at rest in the current Android backend
* passphrase and recovery-slot metadata are also stored locally in the app-private area
* the "system vault" slot is currently backed by a private file, not the Android Keystore
* tests are disabled for Android in CMake

Security properties of the current Android implementation:

* it protects data from ordinary access by other apps because files live in the app's private storage area
* it does not protect data from Android itself, privileged/system-level access, device backups, forensic extraction, or a compromised/rooted device
* it should be treated as an integration/bootstrap target, not as the final Android security model

This keeps the native dependency set to the NDK for now. A later iteration can add a Kotlin/JNI bridge that sources master-key material from the Android Keystore and enables real at-rest encryption.

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
