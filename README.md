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

| Platform        | Status       |
|----------------|-------------|
| **Linux (KDE)**   | ✅ Works with KWallet (KDE Desktop)|
| **Linux (GNOME)** | ✅ Works with GNOME Keyring (Gnome Desktop) |
| **macOS**         | ✅ Works (Keychain Services) |
| **Windows 10**    | ✅ Works (Credential Manager) |
| **Windows 11**    | ✅ Works (Credential Manager) |

*Please note*: Windows Credential Manager has a 512 byte limit on its secrets, so we can't store a full PEM encoded 4096 bits X509 cert and it's key there. The test that does this is disabled under Windows. 

## **Requirements**
- **C++20** compatible compiler
- **CMake** (for building)

## **Dependencies**
📌 **Linux:** `libsecret-1-dev pkgconf libgtest-dev` (for GNOME & KDE support)

