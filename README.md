# **SafeKeeping**
*A simple C++ library for securely storing secrets using the operating system's or desktop manager's vault.*

## **Why?**
I started working on a new command-line tool in **C++20** that connects to various servers using **gRPC** and **HTTPS**.
All these servers require authentication, using different methods:
- **HTTP Basic Authentication**
- **API keys**
- **X.509 certificate/key pairs**

Since this tool is meant for **production environments**, I don't want credentials to be stored **in plain text on disk**.
I needed a simple, cross-platform way to handle secrets securely.

On **Linux**, I found that `libsecret` provides a **standardized way** to store credentials securely,
working with both **KDE (KWallet)** and **GNOME Keyring**.

## **Status**
🚧 **Initial implementation in progress.** 🚧

## **Supported Platforms**
✅ = Implemented | ❌ = Not yet implemented

| Platform        | Status       |
|----------------|-------------|
| **Linux (KDE)**   | ✅ Works with KWallet (KDE Desktop)|
| **Linux (GNOME)** | ✅ Works with GNOME Keyring (Gnome Desktop) |
| **macOS**         | ❌ Not yet tested (Keychain Services) |
| **Windows 10**    | ❌ Not yet tested (Credential Manager) |
| **Windows 11**    | ❌ Not yet tested (Credential Manager) |

## **Requirements**
- **C++20** compatible compiler
- **CMake** (for building)

## **Dependencies**
📌 **Linux:** `libsecret-1-dev pkgconf libgtest-dev` (for GNOME & KDE support)

