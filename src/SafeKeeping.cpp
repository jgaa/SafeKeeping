#include "safekeeping/SafeKeeping.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sqlite3.h>
#include <sodium.h>

#ifdef _WIN32
#include <ShlObj.h>
#include <windows.h>
#include <wincred.h>
#elif defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#elif defined(__linux__) || defined(__unix__)
#include <dbus/dbus.h>
#include <libsecret/secret.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

namespace jgaa::safekeeping {

namespace {

using bytes = std::vector<unsigned char>;
using byte_view = std::span<const std::byte>;

constexpr std::string_view kSchema = R"sql(
CREATE TABLE IF NOT EXISTS metadata (
    schema_version INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    namespace_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS key_slots (
    slot_id TEXT PRIMARY KEY,
    slot_type TEXT NOT NULL,
    status TEXT NOT NULL,
    kdf_name TEXT,
    kdf_salt BLOB,
    kdf_opslimit INTEGER,
    kdf_memlimit INTEGER,
    nonce BLOB NOT NULL,
    wrapped_dek BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    label TEXT
);

CREATE TABLE IF NOT EXISTS secrets (
    name_hash BLOB PRIMARY KEY,
    name_nonce BLOB NOT NULL,
    name_ciphertext BLOB NOT NULL,
    value_nonce BLOB NOT NULL,
    value_ciphertext BLOB NOT NULL,
    description_nonce BLOB,
    description_ciphertext BLOB,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
)sql";

constexpr int kSchemaVersion = 1;
constexpr std::string_view kDbFileName = "vault.db";
constexpr std::string_view kVaultEntryName = "namespace-vault-material";
constexpr std::string_view kSlotStatusActive = "active";
constexpr std::string_view kSlotTypeVault = "vault";
constexpr std::string_view kSlotTypePassphrase = "passphrase";
constexpr std::string_view kSlotTypeRecovery = "recovery";
constexpr std::size_t kMaxSecretSize = 10 * 1024;
constexpr std::string_view kDefaultLinuxVaultRootName = "com.jgaa.SafeKeeping";

class OperationError : public std::runtime_error {
public:
    OperationError(SafeKeeping::Error error, std::string message)
        : std::runtime_error(std::move(message)),
          error_(error) {}

    [[nodiscard]] SafeKeeping::Error error() const noexcept {
        return error_;
    }

private:
    SafeKeeping::Error error_;
};

[[noreturn]] void fail(SafeKeeping::Error error, std::string message) {
    throw OperationError(error, std::move(message));
}

struct StatementDeleter {
    void operator()(sqlite3_stmt* stmt) const noexcept {
        if (stmt != nullptr) {
            sqlite3_finalize(stmt);
        }
    }
};

using statement_ptr = std::unique_ptr<sqlite3_stmt, StatementDeleter>;

struct SqliteDeleter {
    void operator()(sqlite3* db) const noexcept {
        if (db != nullptr) {
            sqlite3_close(db);
        }
    }
};

using sqlite_ptr = std::unique_ptr<sqlite3, SqliteDeleter>;

class Transaction {
public:
    explicit Transaction(sqlite3* db) : db_(db) {
        execute(db_, "BEGIN IMMEDIATE TRANSACTION");
    }

    ~Transaction() {
        if (!committed_) {
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        }
    }

    void commit() {
        execute(db_, "COMMIT");
        committed_ = true;
    }

private:
    static void execute(sqlite3* db, const char* sql) {
        char* error = nullptr;
        if (sqlite3_exec(db, sql, nullptr, nullptr, &error) != SQLITE_OK) {
            const std::string message = error != nullptr ? error : "sqlite error";
            sqlite3_free(error);
            throw std::runtime_error(message);
        }
    }

    sqlite3* db_;
    bool committed_ = false;
};

class VaultBackend {
public:
    virtual ~VaultBackend() = default;

    virtual bool available() const = 0;
    virtual bool store(std::string_view namespaceName,
                       std::string_view key,
                       std::string_view value) = 0;
    virtual std::optional<std::string> load(std::string_view namespaceName,
                                            std::string_view key) = 0;
    virtual bool remove(std::string_view namespaceName, std::string_view key) = 0;
};

[[nodiscard]] int64_t nowSeconds() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

[[nodiscard]] std::string toString(std::string_view value) {
    return std::string(value.begin(), value.end());
}

[[nodiscard]] bytes toBytes(std::string_view value) {
    return bytes(value.begin(), value.end());
}

[[nodiscard]] bytes toBytes(byte_view value) {
    bytes out(value.size());
    std::transform(value.begin(), value.end(), out.begin(), [](std::byte byte) {
        return static_cast<unsigned char>(byte);
    });
    return out;
}

[[nodiscard]] std::vector<std::byte> toByteVector(const bytes& value) {
    std::vector<std::byte> out(value.size());
    std::transform(value.begin(), value.end(), out.begin(), [](unsigned char byte) {
        return static_cast<std::byte>(byte);
    });
    return out;
}

[[nodiscard]] bool envFlagEnabled(const char* name) {
    if (const char* value = std::getenv(name); value != nullptr) {
        const std::string normalized = toString(value);
        return normalized == "1" || normalized == "true" || normalized == "TRUE";
    }
    return false;
}

[[nodiscard]] std::filesystem::path pathFromEnv(const char* name) {
    if (const char* value = std::getenv(name); value != nullptr && *value != '\0') {
        return value;
    }
    return {};
}

void ensureSodium() {
    static const bool initialized = [] {
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium initialization failed");
        }
        return true;
    }();
    (void)initialized;
}

void validateNamespaceOrSecretName(std::string_view name, std::string_view label) {
    static const std::regex validName{R"(^[A-Za-z0-9_.-]{1,128}$)"};

    if (!std::regex_match(name.begin(), name.end(), validName)) {
        fail(SafeKeeping::Error::InvalidArgument,
             toString(label) + " must match [A-Za-z0-9_.-]{1,128}");
    }
}

void validateDescription(std::string_view description) {
    if (description.size() > 4096) {
        fail(SafeKeeping::Error::InvalidArgument, "description is too long");
    }
}

void validateLinuxVaultRootName(std::string_view name) {
    static const std::regex validName{R"(^[A-Za-z0-9_.-]{1,128}$)"};

    if (!std::regex_match(name.begin(), name.end(), validName)) {
        throw std::invalid_argument("linux vault root name must match [A-Za-z0-9_.-]{1,128}");
    }
}

[[nodiscard]] std::string& linuxVaultRootStorage() {
    static std::string value(kDefaultLinuxVaultRootName);
    return value;
}

[[nodiscard]] std::mutex& linuxVaultRootMutex() {
    static std::mutex mutex;
    return mutex;
}

[[nodiscard]] std::string linuxVaultRootName() {
    std::scoped_lock lock(linuxVaultRootMutex());
    return linuxVaultRootStorage();
}

void validateSecretValue(byte_view secret) {
    if (secret.size() > kMaxSecretSize) {
        fail(SafeKeeping::Error::TooLarge, "secret exceeds 10240 bytes");
    }
}

[[nodiscard]] std::filesystem::path userHomePath() {
#ifdef _WIN32
    char path[MAX_PATH]{};
    if (SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path) != S_OK) {
        throw std::runtime_error("failed to get APPDATA path");
    }
    return path;
#else
    if (const char* home = std::getenv("HOME"); home != nullptr) {
        return home;
    }
    throw std::runtime_error("HOME is not set");
#endif
}

[[nodiscard]] std::filesystem::path baseDataPath() {
    if (const auto overridePath = pathFromEnv("SAFEKEEPING_DATA_DIR"); !overridePath.empty()) {
        return overridePath;
    }

#ifdef _WIN32
    return userHomePath() / "safekeeping";
#elif defined(__APPLE__)
    return userHomePath() / "Library" / "Application Support" / "safekeeping";
#else
    if (const char* xdg = std::getenv("XDG_DATA_HOME"); xdg != nullptr && *xdg != '\0') {
        return std::filesystem::path(xdg) / "safekeeping";
    }
    return userHomePath() / ".local" / "share" / "safekeeping";
#endif
}

[[nodiscard]] std::filesystem::path namespacePath(std::string_view namespaceName) {
    validateNamespaceOrSecretName(namespaceName, "namespace");
    return baseDataPath() / toString(namespaceName);
}

[[nodiscard]] std::filesystem::path databasePath(std::string_view namespaceName) {
    return namespacePath(namespaceName) / kDbFileName;
}

void lockDownPath(const std::filesystem::path& path, bool directory) {
#ifndef _WIN32
    if (!std::filesystem::exists(path)) {
        return;
    }

    const auto perms = directory
        ? (std::filesystem::perms::owner_read |
           std::filesystem::perms::owner_write |
           std::filesystem::perms::owner_exec)
        : (std::filesystem::perms::owner_read |
           std::filesystem::perms::owner_write);

    std::filesystem::permissions(path, perms, std::filesystem::perm_options::replace);
#else
    (void)path;
    (void)directory;
#endif
}

void ensurePrivateDirectory(const std::filesystem::path& path) {
    std::filesystem::create_directories(path);
    lockDownPath(path, true);
}

void lockDownDatabaseArtifacts(const std::filesystem::path& dbPath) {
    lockDownPath(dbPath.parent_path(), true);
    lockDownPath(dbPath, false);
    lockDownPath(dbPath.string() + "-wal", false);
    lockDownPath(dbPath.string() + "-shm", false);
    lockDownPath(dbPath.string() + "-journal", false);
}

[[nodiscard]] bytes randomBytes(std::size_t size) {
    ensureSodium();
    bytes out(size);
    randombytes_buf(out.data(), out.size());
    return out;
}

[[nodiscard]] std::string bytesToHex(std::span<const unsigned char> data) {
    if (data.empty()) {
        return {};
    }

    std::string out(data.size() * 2 + 1, '\0');
    sodium_bin2hex(out.data(), out.size(), data.data(), data.size());
    out.pop_back();
    return out;
}

[[nodiscard]] bytes hexToBytes(std::string_view hex) {
    ensureSodium();
    bytes out((hex.size() / 2) + 1);
    std::size_t outLen = 0;
    if (sodium_hex2bin(
            out.data(),
            out.size(),
            hex.data(),
            hex.size(),
            nullptr,
            &outLen,
            nullptr) != 0) {
        throw std::runtime_error("invalid hex input");
    }
    out.resize(outLen);
    return out;
}

[[nodiscard]] bytes makeNonce() {
    return randomBytes(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
}

[[nodiscard]] bytes deriveHashKey(const bytes& dek) {
    bytes hashKey(crypto_generichash_BYTES);
    if (crypto_generichash(
            hashKey.data(),
            hashKey.size(),
            reinterpret_cast<const unsigned char*>("name-hash-v1"),
            std::strlen("name-hash-v1"),
            dek.data(),
            dek.size()) != 0) {
        throw std::runtime_error("failed to derive hash key");
    }
    return hashKey;
}

[[nodiscard]] bytes computeNameHash(const bytes& dek, std::string_view name) {
    const auto hashKey = deriveHashKey(dek);
    bytes hash(crypto_generichash_BYTES);
    if (crypto_generichash(
            hash.data(),
            hash.size(),
            reinterpret_cast<const unsigned char*>(name.data()),
            name.size(),
            hashKey.data(),
            hashKey.size()) != 0) {
        throw std::runtime_error("failed to hash secret name");
    }
    return hash;
}

[[nodiscard]] bytes aeadEncrypt(const bytes& plaintext,
                                const bytes& key,
                                std::string_view ad,
                                bytes& nonceOut) {
    ensureSodium();
    nonceOut = makeNonce();
    bytes ciphertext(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertextLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(),
            &ciphertextLen,
            plaintext.data(),
            plaintext.size(),
            reinterpret_cast<const unsigned char*>(ad.data()),
            ad.size(),
            nullptr,
            nonceOut.data(),
            key.data()) != 0) {
        throw std::runtime_error("encryption failed");
    }
    ciphertext.resize(static_cast<std::size_t>(ciphertextLen));
    return ciphertext;
}

[[nodiscard]] bytes aeadDecrypt(const bytes& ciphertext,
                                const bytes& nonce,
                                const bytes& key,
                                std::string_view ad) {
    ensureSodium();
    bytes plaintext(ciphertext.size());
    unsigned long long plaintextLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(),
            &plaintextLen,
            nullptr,
            ciphertext.data(),
            ciphertext.size(),
            reinterpret_cast<const unsigned char*>(ad.data()),
            ad.size(),
            nonce.data(),
            key.data()) != 0) {
        throw std::runtime_error("ciphertext authentication failed");
    }
    plaintext.resize(static_cast<std::size_t>(plaintextLen));
    return plaintext;
}

[[nodiscard]] bytes derivePassphraseKek(std::string_view passphrase,
                                        const bytes& salt,
                                        unsigned long long opslimit,
                                        std::size_t memlimit) {
    ensureSodium();
    bytes key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    if (crypto_pwhash(
            key.data(),
            key.size(),
            passphrase.data(),
            passphrase.size(),
            salt.data(),
            opslimit,
            memlimit,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("passphrase derivation failed");
    }
    return key;
}

[[nodiscard]] bytes deriveVaultKek(std::string_view vaultMaterial) {
    ensureSodium();
    bytes key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    if (crypto_generichash(
            key.data(),
            key.size(),
            reinterpret_cast<const unsigned char*>(vaultMaterial.data()),
            vaultMaterial.size(),
            reinterpret_cast<const unsigned char*>("vault-kek-v1"),
            std::strlen("vault-kek-v1")) != 0) {
        throw std::runtime_error("vault key derivation failed");
    }
    return key;
}

[[nodiscard]] std::string normalizeRecoveryKey(std::string_view recoveryKey) {
    std::string normalized;
    normalized.reserve(recoveryKey.size());
    for (const unsigned char ch : recoveryKey) {
        if (std::isxdigit(ch) != 0) {
            normalized.push_back(static_cast<char>(std::tolower(ch)));
        }
    }
    return normalized;
}

[[nodiscard]] std::string formatRecoveryKey(std::span<const unsigned char> raw) {
    const std::string hex = bytesToHex(raw);
    std::string formatted;
    formatted.reserve(hex.size() + (hex.size() / 4));
    for (std::size_t i = 0; i < hex.size(); ++i) {
        if (i > 0 && (i % 4) == 0) {
            formatted.push_back('-');
        }
        formatted.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(hex[i]))));
    }
    return formatted;
}

[[nodiscard]] std::pair<std::string, bytes> generateRecoverySecret() {
    const bytes raw = randomBytes(20);
    return {formatRecoveryKey(raw), raw};
}

statement_ptr prepare(sqlite3* db, std::string_view sql) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.data(), static_cast<int>(sql.size()), &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(db));
    }
    return statement_ptr(stmt);
}

void bindBlob(sqlite3_stmt* stmt, int index, const bytes& value) {
    if (sqlite3_bind_blob(stmt, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK) {
        throw std::runtime_error("failed to bind blob");
    }
}

void bindOptionalBlob(sqlite3_stmt* stmt, int index, const std::optional<bytes>& value) {
    if (!value.has_value()) {
        if (sqlite3_bind_null(stmt, index) != SQLITE_OK) {
            throw std::runtime_error("failed to bind null blob");
        }
        return;
    }
    bindBlob(stmt, index, *value);
}

void bindText(sqlite3_stmt* stmt, int index, std::string_view value) {
    if (sqlite3_bind_text(stmt, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK) {
        throw std::runtime_error("failed to bind text");
    }
}

void bindOptionalText(sqlite3_stmt* stmt, int index, const std::optional<std::string>& value) {
    if (!value.has_value()) {
        if (sqlite3_bind_null(stmt, index) != SQLITE_OK) {
            throw std::runtime_error("failed to bind null text");
        }
        return;
    }
    bindText(stmt, index, *value);
}

void bindInt64(sqlite3_stmt* stmt, int index, std::int64_t value) {
    if (sqlite3_bind_int64(stmt, index, value) != SQLITE_OK) {
        throw std::runtime_error("failed to bind int64");
    }
}

void stepDone(sqlite3* db, sqlite3_stmt* stmt) {
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(sqlite3_errmsg(db));
    }
}

[[nodiscard]] bytes columnBlob(sqlite3_stmt* stmt, int index) {
    const auto* data = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, index));
    const int size = sqlite3_column_bytes(stmt, index);
    if (data == nullptr || size < 0) {
        return {};
    }
    return bytes(data, data + size);
}

[[nodiscard]] std::optional<bytes> columnOptionalBlob(sqlite3_stmt* stmt, int index) {
    if (sqlite3_column_type(stmt, index) == SQLITE_NULL) {
        return std::nullopt;
    }
    return columnBlob(stmt, index);
}

[[nodiscard]] std::string columnText(sqlite3_stmt* stmt, int index) {
    const auto* data = reinterpret_cast<const char*>(sqlite3_column_text(stmt, index));
    const int size = sqlite3_column_bytes(stmt, index);
    if (data == nullptr || size < 0) {
        return {};
    }
    return std::string(data, data + size);
}

void execute(sqlite3* db, std::string_view sql) {
    char* error = nullptr;
    if (sqlite3_exec(db, sql.data(), nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string message = error != nullptr ? error : sqlite3_errmsg(db);
        sqlite3_free(error);
        throw std::runtime_error(message);
    }
}

class FileVaultBackend final : public VaultBackend {
public:
    explicit FileVaultBackend(std::filesystem::path root) : root_(std::move(root)) {}

    bool available() const override {
        return !root_.empty();
    }

    bool store(std::string_view namespaceName, std::string_view key, std::string_view value) override {
        ensurePrivateDirectory(root_);
        const auto path = entryPath(namespaceName, key);
        ensurePrivateDirectory(path.parent_path());
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            return false;
        }
        out.write(value.data(), static_cast<std::streamsize>(value.size()));
        out.close();
        lockDownPath(path, false);
        return out.good();
    }

    std::optional<std::string> load(std::string_view namespaceName, std::string_view key) override {
        const auto path = entryPath(namespaceName, key);
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            return std::nullopt;
        }
        std::string value((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        return value;
    }

    bool remove(std::string_view namespaceName, std::string_view key) override {
        const auto path = entryPath(namespaceName, key);
        if (!std::filesystem::exists(path)) {
            return false;
        }
        return std::filesystem::remove(path);
    }

private:
    [[nodiscard]] std::filesystem::path entryPath(std::string_view namespaceName,
                                                  std::string_view key) const {
        return root_ / toString(namespaceName) / (toString(key) + ".txt");
    }

    std::filesystem::path root_;
};

#if defined(__linux__) || defined(__unix__)
struct DBusErrorScope {
    DBusErrorScope() {
        dbus_error_init(&error);
    }

    ~DBusErrorScope() {
        dbus_error_free(&error);
    }

    [[nodiscard]] bool hasError() const noexcept {
        return dbus_error_is_set(&error) != FALSE;
    }

    DBusError error;
};

struct DBusMessageDeleter {
    void operator()(DBusMessage* message) const noexcept {
        if (message != nullptr) {
            dbus_message_unref(message);
        }
    }
};

using dbus_message_ptr = std::unique_ptr<DBusMessage, DBusMessageDeleter>;

[[nodiscard]] DBusConnection* sessionBusConnection() {
    static DBusConnection* connection = []() -> DBusConnection* {
        DBusErrorScope error;
        DBusConnection* bus = dbus_bus_get(DBUS_BUS_SESSION, &error.error);
        if (error.hasError() || bus == nullptr) {
            return nullptr;
        }
        dbus_connection_set_exit_on_disconnect(bus, FALSE);
        return bus;
    }();
    return connection;
}

[[nodiscard]] bool dbusNameHasOwner(std::string_view name) {
    if (DBusConnection* bus = sessionBusConnection(); bus != nullptr) {
        DBusErrorScope error;
        const dbus_bool_t hasOwner = dbus_bus_name_has_owner(bus, toString(name).c_str(), &error.error);
        return !error.hasError() && hasOwner != FALSE;
    }
    return false;
}

[[nodiscard]] bool isKdeSession() {
    const auto containsToken = [](const char* name, std::string_view token) {
        if (const char* value = std::getenv(name); value != nullptr) {
            const std::string normalized = toString(value);
            return normalized.find(toString(token)) != std::string::npos;
        }
        return false;
    };

    return envFlagEnabled("KDE_FULL_SESSION") ||
        containsToken("XDG_CURRENT_DESKTOP", "KDE") ||
        containsToken("DESKTOP_SESSION", "plasma") ||
        containsToken("DESKTOP_SESSION", "kde");
}

[[nodiscard]] std::optional<std::pair<std::string, std::string>> kwalletServiceAddress() {
    if (dbusNameHasOwner("org.kde.kwalletd6")) {
        return std::pair{std::string("org.kde.kwalletd6"), std::string("/modules/kwalletd6")};
    }
    if (dbusNameHasOwner("org.kde.kwalletd5")) {
        return std::pair{std::string("org.kde.kwalletd5"), std::string("/modules/kwalletd5")};
    }
    return std::nullopt;
}

class KWalletVaultBackend final : public VaultBackend {
public:
    bool available() const override {
        if (envFlagEnabled("SAFEKEEPING_DISABLE_SYSTEM_VAULT") ||
            envFlagEnabled("SAFEKEEPING_FORCE_LIBSECRET")) {
            return false;
        }
        if (!envFlagEnabled("SAFEKEEPING_FORCE_KWALLET") && !isKdeSession()) {
            return false;
        }
        return kwalletServiceAddress().has_value();
    }

    bool store(std::string_view namespaceName, std::string_view key, std::string_view value) override {
        if (!available()) {
            return false;
        }

        auto wallet = openWallet();
        if (!wallet.has_value() || !ensureFolder(*wallet)) {
            return false;
        }

        const std::string entry = entryName(namespaceName, key);
        const std::string folderValue = linuxVaultRootName();
        const char* folder = folderValue.c_str();
        const char* entryKey = entry.c_str();
        const char* secret = value.data();
        const std::string appIdValue = linuxVaultRootName();
        const char* appId = appIdValue.c_str();

        return callIntMethod(wallet->service,
                             wallet->path,
                             "writePassword",
                             [&](DBusMessage* message) {
                                 const dbus_int32_t handle = wallet->handle;
                                 dbus_message_append_args(message,
                                                          DBUS_TYPE_INT32, &handle,
                                                          DBUS_TYPE_STRING, &folder,
                                                          DBUS_TYPE_STRING, &entryKey,
                                                          DBUS_TYPE_STRING, &secret,
                                                          DBUS_TYPE_STRING, &appId,
                                                          DBUS_TYPE_INVALID);
                             }) == 0;
    }

    std::optional<std::string> load(std::string_view namespaceName, std::string_view key) override {
        if (!available()) {
            return std::nullopt;
        }

        auto wallet = openWallet();
        if (!wallet.has_value() || !ensureFolder(*wallet)) {
            return std::nullopt;
        }

        const std::string entry = entryName(namespaceName, key);
        if (!hasEntry(*wallet, entry)) {
            return std::nullopt;
        }

        const std::string folderValue = linuxVaultRootName();
        const char* folder = folderValue.c_str();
        const char* entryKey = entry.c_str();
        const std::string appIdValue = linuxVaultRootName();
        const char* appId = appIdValue.c_str();
        return callStringMethod(wallet->service,
                                wallet->path,
                                "readPassword",
                                [&](DBusMessage* message) {
                                    const dbus_int32_t handle = wallet->handle;
                                    dbus_message_append_args(message,
                                                             DBUS_TYPE_INT32, &handle,
                                                             DBUS_TYPE_STRING, &folder,
                                                             DBUS_TYPE_STRING, &entryKey,
                                                             DBUS_TYPE_STRING, &appId,
                                                             DBUS_TYPE_INVALID);
                                });
    }

    bool remove(std::string_view namespaceName, std::string_view key) override {
        if (!available()) {
            return false;
        }

        auto wallet = openWallet();
        if (!wallet.has_value() || !ensureFolder(*wallet)) {
            return false;
        }

        const std::string entry = entryName(namespaceName, key);
        if (!hasEntry(*wallet, entry)) {
            return false;
        }

        const std::string folderValue = linuxVaultRootName();
        const char* folder = folderValue.c_str();
        const char* entryKey = entry.c_str();
        const std::string appIdValue = linuxVaultRootName();
        const char* appId = appIdValue.c_str();
        return callIntMethod(wallet->service,
                             wallet->path,
                             "removeEntry",
                             [&](DBusMessage* message) {
                                 const dbus_int32_t handle = wallet->handle;
                                 dbus_message_append_args(message,
                                                          DBUS_TYPE_INT32, &handle,
                                                          DBUS_TYPE_STRING, &folder,
                                                          DBUS_TYPE_STRING, &entryKey,
                                                          DBUS_TYPE_STRING, &appId,
                                                          DBUS_TYPE_INVALID);
                             }) == 0;
    }

private:
    struct WalletHandle {
        std::string service;
        std::string path;
        dbus_int32_t handle = -1;

        ~WalletHandle() {
            if (handle < 0) {
                return;
            }

            if (DBusConnection* bus = sessionBusConnection(); bus != nullptr) {
                dbus_message_ptr message(dbus_message_new_method_call(service.c_str(),
                                                                      path.c_str(),
                                                                      "org.kde.KWallet",
                                                                      "close"));
                if (!message) {
                    return;
                }
                const dbus_bool_t force = FALSE;
                const std::string appIdValue = linuxVaultRootName();
                const char* appId = appIdValue.c_str();
                dbus_message_append_args(message.get(),
                                         DBUS_TYPE_INT32, &handle,
                                         DBUS_TYPE_BOOLEAN, &force,
                                         DBUS_TYPE_STRING, &appId,
                                         DBUS_TYPE_INVALID);
                DBusErrorScope error;
                dbus_message_ptr reply(
                    dbus_connection_send_with_reply_and_block(bus, message.get(), kDbusTimeoutMs, &error.error));
                (void)reply;
            }
        }
    };

    static constexpr int kDbusTimeoutMs = 5000;

    template <typename AppendArgs>
    static dbus_message_ptr callMethod(std::string_view service,
                                       std::string_view path,
                                       std::string_view method,
                                       AppendArgs appendArgs) {
        DBusConnection* bus = sessionBusConnection();
        if (bus == nullptr) {
            return {};
        }

        dbus_message_ptr message(dbus_message_new_method_call(toString(service).c_str(),
                                                              toString(path).c_str(),
                                                              "org.kde.KWallet",
                                                              toString(method).c_str()));
        if (!message) {
            return {};
        }

        appendArgs(message.get());
        DBusErrorScope error;
        dbus_message_ptr reply(
            dbus_connection_send_with_reply_and_block(bus, message.get(), kDbusTimeoutMs, &error.error));
        if (error.hasError()) {
            return {};
        }
        return reply;
    }

    template <typename AppendArgs>
    static std::optional<std::string> callStringMethod(std::string_view service,
                                                       std::string_view path,
                                                       std::string_view method,
                                                       AppendArgs appendArgs) {
        auto reply = callMethod(service, path, method, appendArgs);
        if (!reply) {
            return std::nullopt;
        }

        DBusErrorScope error;
        const char* value = nullptr;
        if (dbus_message_get_args(reply.get(), &error.error, DBUS_TYPE_STRING, &value, DBUS_TYPE_INVALID) == FALSE ||
            error.hasError() || value == nullptr) {
            return std::nullopt;
        }
        return std::string(value);
    }

    template <typename AppendArgs>
    static std::optional<dbus_int32_t> callIntMethod(std::string_view service,
                                                     std::string_view path,
                                                     std::string_view method,
                                                     AppendArgs appendArgs) {
        auto reply = callMethod(service, path, method, appendArgs);
        if (!reply) {
            return std::nullopt;
        }

        DBusErrorScope error;
        dbus_int32_t value = -1;
        if (dbus_message_get_args(reply.get(), &error.error, DBUS_TYPE_INT32, &value, DBUS_TYPE_INVALID) == FALSE ||
            error.hasError()) {
            return std::nullopt;
        }
        return value;
    }

    template <typename AppendArgs>
    static std::optional<bool> callBoolMethod(std::string_view service,
                                              std::string_view path,
                                              std::string_view method,
                                              AppendArgs appendArgs) {
        auto reply = callMethod(service, path, method, appendArgs);
        if (!reply) {
            return std::nullopt;
        }

        DBusErrorScope error;
        dbus_bool_t value = FALSE;
        if (dbus_message_get_args(reply.get(), &error.error, DBUS_TYPE_BOOLEAN, &value, DBUS_TYPE_INVALID) == FALSE ||
            error.hasError()) {
            return std::nullopt;
        }
        return value != FALSE;
    }

    static std::optional<WalletHandle> openWallet() {
        const auto address = kwalletServiceAddress();
        if (!address.has_value()) {
            return std::nullopt;
        }

        auto walletName = callStringMethod(address->first, address->second, "localWallet", [](DBusMessage*) {});
        if (!walletName.has_value()) {
            return std::nullopt;
        }

        const char* wallet = walletName->c_str();
        const dbus_int64_t windowId = 0;
        const std::string appIdValue = linuxVaultRootName();
        const char* appId = appIdValue.c_str();
        auto handle = callIntMethod(address->first,
                                    address->second,
                                    "open",
                                    [&](DBusMessage* message) {
                                        dbus_message_append_args(message,
                                                                 DBUS_TYPE_STRING, &wallet,
                                                                 DBUS_TYPE_INT64, &windowId,
                                                                 DBUS_TYPE_STRING, &appId,
                                                                 DBUS_TYPE_INVALID);
                                    });
        if (!handle.has_value() || *handle < 0) {
            return std::nullopt;
        }

        return WalletHandle{
            .service = address->first,
            .path = address->second,
            .handle = *handle,
        };
    }

    static bool ensureFolder(const WalletHandle& wallet) {
        const std::string folderValue = linuxVaultRootName();
        const char* folder = folderValue.c_str();
        const std::string appIdValue = linuxVaultRootName();
        const char* appId = appIdValue.c_str();

        const auto exists = callBoolMethod(wallet.service,
                                           wallet.path,
                                           "hasFolder",
                                           [&](DBusMessage* message) {
                                               const dbus_int32_t handle = wallet.handle;
                                               dbus_message_append_args(message,
                                                                        DBUS_TYPE_INT32, &handle,
                                                                        DBUS_TYPE_STRING, &folder,
                                                                        DBUS_TYPE_STRING, &appId,
                                                                        DBUS_TYPE_INVALID);
                                           });
        if (exists == std::optional<bool>{true}) {
            return true;
        }
        if (!exists.has_value()) {
            return false;
        }

        const auto created = callBoolMethod(wallet.service,
                                            wallet.path,
                                            "createFolder",
                                            [&](DBusMessage* message) {
                                                const dbus_int32_t handle = wallet.handle;
                                                dbus_message_append_args(message,
                                                                         DBUS_TYPE_INT32, &handle,
                                                                         DBUS_TYPE_STRING, &folder,
                                                                         DBUS_TYPE_STRING, &appId,
                                                                         DBUS_TYPE_INVALID);
                                            });
        return created == std::optional<bool>{true};
    }

    static bool hasEntry(const WalletHandle& wallet, const std::string& entry) {
        const std::string folderValue = linuxVaultRootName();
        const char* folder = folderValue.c_str();
        const char* entryKey = entry.c_str();
        const std::string appIdValue = linuxVaultRootName();
        const char* appId = appIdValue.c_str();
        const auto exists = callBoolMethod(wallet.service,
                                           wallet.path,
                                           "hasEntry",
                                           [&](DBusMessage* message) {
                                               const dbus_int32_t handle = wallet.handle;
                                               dbus_message_append_args(message,
                                                                        DBUS_TYPE_INT32, &handle,
                                                                        DBUS_TYPE_STRING, &folder,
                                                                        DBUS_TYPE_STRING, &entryKey,
                                                                        DBUS_TYPE_STRING, &appId,
                                                                        DBUS_TYPE_INVALID);
                                           });
        return exists == std::optional<bool>{true};
    }

    static std::string entryName(std::string_view namespaceName, std::string_view key) {
        return toString(namespaceName) + "/" + toString(key);
    }
};

class LibSecretVaultBackend final : public VaultBackend {
public:
    bool available() const override {
        return !envFlagEnabled("SAFEKEEPING_DISABLE_SYSTEM_VAULT");
    }

    bool store(std::string_view namespaceName, std::string_view key, std::string_view value) override {
        if (envFlagEnabled("SAFEKEEPING_DISABLE_SYSTEM_VAULT")) {
            return false;
        }
        const std::string account = accountName(namespaceName, key);
        const std::string service = serviceName(namespaceName);
        GError* error = nullptr;
        const gboolean ok = secret_password_store_sync(
            &schema(),
            SECRET_COLLECTION_DEFAULT,
            displayLabel(namespaceName, key).c_str(),
            value.data(),
            nullptr,
            &error,
            "service", service.c_str(),
            "account", account.c_str(),
            nullptr);
        if (error != nullptr) {
            g_error_free(error);
        }
        return ok != FALSE;
    }

    std::optional<std::string> load(std::string_view namespaceName, std::string_view key) override {
        if (envFlagEnabled("SAFEKEEPING_DISABLE_SYSTEM_VAULT")) {
            return std::nullopt;
        }
        const std::string account = accountName(namespaceName, key);
        const std::string service = serviceName(namespaceName);
        GError* error = nullptr;
        gchar* secret = secret_password_lookup_sync(
            &schema(),
            nullptr,
            &error,
            "service", service.c_str(),
            "account", account.c_str(),
            nullptr);
        if (error != nullptr) {
            g_error_free(error);
        }
        if (secret == nullptr) {
            return std::nullopt;
        }
        std::string result(secret);
        secret_password_free(secret);
        return result;
    }

    bool remove(std::string_view namespaceName, std::string_view key) override {
        if (envFlagEnabled("SAFEKEEPING_DISABLE_SYSTEM_VAULT")) {
            return false;
        }
        const std::string account = accountName(namespaceName, key);
        const std::string service = serviceName(namespaceName);
        GError* error = nullptr;
        const gboolean ok = secret_password_clear_sync(
            &schema(),
            nullptr,
            &error,
            "service", service.c_str(),
            "account", account.c_str(),
            nullptr);
        if (error != nullptr) {
            g_error_free(error);
        }
        return ok != FALSE;
    }

private:
    static SecretSchema& schema() {
        static SecretSchema schemaValue = {
            "SafeKeepingSchema",
            SECRET_SCHEMA_DONT_MATCH_NAME,
            {{"service", SECRET_SCHEMA_ATTRIBUTE_STRING},
             {"account", SECRET_SCHEMA_ATTRIBUTE_STRING},
             {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING}},
        };
        return schemaValue;
    }

    static std::string serviceName(std::string_view namespaceName) {
        return linuxVaultRootName() + "/" + toString(namespaceName);
    }

    static std::string accountName(std::string_view namespaceName, std::string_view key) {
        return toString(namespaceName) + "/" + toString(key);
    }

    static std::string displayLabel(std::string_view namespaceName, std::string_view key) {
        return linuxVaultRootName() + "/" + accountName(namespaceName, key);
    }
};
#elif defined(__APPLE__)
class MacVaultBackend final : public VaultBackend {
public:
    bool available() const override {
        return !envFlagEnabled("SAFEKEEPING_DISABLE_SYSTEM_VAULT");
    }

    bool store(std::string_view namespaceName, std::string_view key, std::string_view value) override {
        if (!available()) {
            return false;
        }

        const auto service = cfString(toString(namespaceName));
        const auto account = cfString(toString(key));
        const auto data = cfData(toString(value));
        if (service == nullptr || account == nullptr || data == nullptr) {
            return false;
        }

        auto query = mutableDictionary();
        CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(query, kSecAttrService, service);
        CFDictionarySetValue(query, kSecAttrAccount, account);

        OSStatus status = SecItemCopyMatching(query, nullptr);
        if (status == errSecSuccess) {
            auto attrs = mutableDictionary();
            CFDictionarySetValue(attrs, kSecValueData, data);
            status = SecItemUpdate(query, attrs);
            CFRelease(attrs);
        } else {
            CFDictionarySetValue(query, kSecValueData, data);
            status = SecItemAdd(query, nullptr);
        }

        CFRelease(query);
        CFRelease(service);
        CFRelease(account);
        CFRelease(data);
        return status == errSecSuccess;
    }

    std::optional<std::string> load(std::string_view namespaceName, std::string_view key) override {
        if (!available()) {
            return std::nullopt;
        }

        const auto service = cfString(toString(namespaceName));
        const auto account = cfString(toString(key));
        auto query = mutableDictionary();
        CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(query, kSecAttrService, service);
        CFDictionarySetValue(query, kSecAttrAccount, account);
        CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
        CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

        CFTypeRef result = nullptr;
        const OSStatus status = SecItemCopyMatching(query, &result);
        CFRelease(query);
        CFRelease(service);
        CFRelease(account);
        if (status != errSecSuccess || result == nullptr) {
            return std::nullopt;
        }

        const auto* data = static_cast<CFDataRef>(result);
        std::string value(reinterpret_cast<const char*>(CFDataGetBytePtr(data)), CFDataGetLength(data));
        CFRelease(result);
        return value;
    }

    bool remove(std::string_view namespaceName, std::string_view key) override {
        if (!available()) {
            return false;
        }

        const auto service = cfString(toString(namespaceName));
        const auto account = cfString(toString(key));
        auto query = mutableDictionary();
        CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(query, kSecAttrService, service);
        CFDictionarySetValue(query, kSecAttrAccount, account);
        const OSStatus status = SecItemDelete(query);
        CFRelease(query);
        CFRelease(service);
        CFRelease(account);
        return status == errSecSuccess;
    }

private:
    static CFStringRef cfString(const std::string& value) {
        return CFStringCreateWithCString(nullptr, value.c_str(), kCFStringEncodingUTF8);
    }

    static CFDataRef cfData(const std::string& value) {
        return CFDataCreate(nullptr,
                            reinterpret_cast<const UInt8*>(value.data()),
                            static_cast<CFIndex>(value.size()));
    }

    static CFMutableDictionaryRef mutableDictionary() {
        return CFDictionaryCreateMutable(nullptr,
                                         0,
                                         &kCFTypeDictionaryKeyCallBacks,
                                         &kCFTypeDictionaryValueCallBacks);
    }
};
#elif defined(_WIN32)
class WinVaultBackend final : public VaultBackend {
public:
    bool available() const override {
        return !envFlagEnabled("SAFEKEEPING_DISABLE_SYSTEM_VAULT");
    }

    bool store(std::string_view namespaceName, std::string_view key, std::string_view value) override {
        if (!available()) {
            return false;
        }
        const std::string target = targetName(namespaceName, key);
        CREDENTIALA credential{};
        credential.Type = CRED_TYPE_GENERIC;
        credential.TargetName = const_cast<char*>(target.c_str());
        credential.CredentialBlobSize = static_cast<DWORD>(value.size());
        credential.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char*>(value.data()));
        credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
        return CredWriteA(&credential, 0) != FALSE;
    }

    std::optional<std::string> load(std::string_view namespaceName, std::string_view key) override {
        if (!available()) {
            return std::nullopt;
        }
        const std::string target = targetName(namespaceName, key);
        PCREDENTIALA credential = nullptr;
        if (CredReadA(target.c_str(), CRED_TYPE_GENERIC, 0, &credential) == FALSE) {
            return std::nullopt;
        }
        std::string value(reinterpret_cast<char*>(credential->CredentialBlob),
                          credential->CredentialBlobSize);
        CredFree(credential);
        return value;
    }

    bool remove(std::string_view namespaceName, std::string_view key) override {
        if (!available()) {
            return false;
        }
        return CredDeleteA(targetName(namespaceName, key).c_str(), CRED_TYPE_GENERIC, 0) != FALSE;
    }

private:
    static std::string targetName(std::string_view namespaceName, std::string_view key) {
        return "safekeeping/" + toString(namespaceName) + "/" + toString(key);
    }
};
#endif

std::unique_ptr<VaultBackend> makeVaultBackend() {
    if (const auto fakeVault = pathFromEnv("SAFEKEEPING_TEST_FAKE_VAULT_DIR"); !fakeVault.empty()) {
        return std::make_unique<FileVaultBackend>(fakeVault);
    }
#if defined(__linux__) || defined(__unix__)
    if (auto kwallet = std::make_unique<KWalletVaultBackend>(); kwallet->available()) {
        return kwallet;
    }
    return std::make_unique<LibSecretVaultBackend>();
#elif defined(__APPLE__)
    return std::make_unique<MacVaultBackend>();
#elif defined(_WIN32)
    return std::make_unique<WinVaultBackend>();
#else
    return std::make_unique<FileVaultBackend>(std::filesystem::path{});
#endif
}

struct SlotRecord {
    std::string slotId;
    std::string slotType;
    std::optional<std::string> kdfName;
    std::optional<bytes> kdfSalt;
    std::int64_t kdfOpslimit = 0;
    std::int64_t kdfMemlimit = 0;
    bytes nonce;
    bytes wrappedDek;
};

struct SecretRecord {
    bytes nameHash;
    bytes nameNonce;
    bytes nameCiphertext;
    bytes valueNonce;
    bytes valueCiphertext;
    std::optional<bytes> descriptionNonce;
    std::optional<bytes> descriptionCiphertext;
};

[[nodiscard]] SlotRecord readSingleSlot(sqlite3* db, std::string_view slotType) {
    auto stmt = prepare(
        db,
        "SELECT slot_id, slot_type, kdf_name, kdf_salt, kdf_opslimit, kdf_memlimit, nonce, wrapped_dek "
        "FROM key_slots WHERE status = 'active' AND slot_type = ? LIMIT 1");
    bindText(stmt.get(), 1, slotType);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
        throw std::runtime_error("slot not found");
    }

    SlotRecord record;
    record.slotId = columnText(stmt.get(), 0);
    record.slotType = columnText(stmt.get(), 1);
    if (sqlite3_column_type(stmt.get(), 2) != SQLITE_NULL) {
        record.kdfName = columnText(stmt.get(), 2);
    }
    record.kdfSalt = columnOptionalBlob(stmt.get(), 3);
    record.kdfOpslimit = sqlite3_column_int64(stmt.get(), 4);
    record.kdfMemlimit = sqlite3_column_int64(stmt.get(), 5);
    record.nonce = columnBlob(stmt.get(), 6);
    record.wrappedDek = columnBlob(stmt.get(), 7);
    return record;
}

[[nodiscard]] int activeSlotCount(sqlite3* db) {
    auto stmt = prepare(db, "SELECT COUNT(*) FROM key_slots WHERE status = 'active'");
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
        throw std::runtime_error("failed to count key slots");
    }
    return sqlite3_column_int(stmt.get(), 0);
}

[[nodiscard]] bool hasSlot(sqlite3* db, std::string_view slotType) {
    auto stmt = prepare(db, "SELECT 1 FROM key_slots WHERE status = 'active' AND slot_type = ? LIMIT 1");
    bindText(stmt.get(), 1, slotType);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

[[nodiscard]] std::vector<SafeKeeping::UnlockMethod> listUnlockMethods(sqlite3* db) {
    std::vector<SafeKeeping::UnlockMethod> methods;
    if (hasSlot(db, kSlotTypeVault)) {
        methods.push_back(SafeKeeping::UnlockMethod::SystemVault);
    }
    if (hasSlot(db, kSlotTypePassphrase)) {
        methods.push_back(SafeKeeping::UnlockMethod::Passphrase);
    }
    if (hasSlot(db, kSlotTypeRecovery)) {
        methods.push_back(SafeKeeping::UnlockMethod::RecoveryKey);
    }
    return methods;
}

[[nodiscard]] bytes unwrapDek(const SlotRecord& slot,
                              const bytes& kek,
                              std::string_view aadSuffix) {
    return aeadDecrypt(slot.wrappedDek,
                       slot.nonce,
                       kek,
                       "slot-wrap-v1:" + slot.slotType + ":" + slot.slotId + ":" + toString(aadSuffix));
}

[[nodiscard]] SlotRecord buildWrappedSlot(std::string slotId,
                                          std::string slotType,
                                          const bytes& dek,
                                          const bytes& kek,
                                          std::optional<std::string> kdfName,
                                          std::optional<bytes> kdfSalt,
                                          std::int64_t kdfOpslimit,
                                          std::int64_t kdfMemlimit) {
    SlotRecord slot;
    slot.slotId = std::move(slotId);
    slot.slotType = std::move(slotType);
    slot.kdfName = std::move(kdfName);
    slot.kdfSalt = std::move(kdfSalt);
    slot.kdfOpslimit = kdfOpslimit;
    slot.kdfMemlimit = kdfMemlimit;
    slot.wrappedDek = aeadEncrypt(
        dek,
        kek,
        "slot-wrap-v1:" + slot.slotType + ":" + slot.slotId + ":schema-1",
        slot.nonce);
    return slot;
}

void insertSlot(sqlite3* db, const SlotRecord& slot, std::optional<std::string> label = std::nullopt) {
    auto stmt = prepare(
        db,
        "INSERT INTO key_slots (slot_id, slot_type, status, kdf_name, kdf_salt, kdf_opslimit, "
        "kdf_memlimit, nonce, wrapped_dek, created_at, updated_at, label) "
        "VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    const auto now = nowSeconds();
    bindText(stmt.get(), 1, slot.slotId);
    bindText(stmt.get(), 2, slot.slotType);
    bindOptionalText(stmt.get(), 3, slot.kdfName);
    bindOptionalBlob(stmt.get(), 4, slot.kdfSalt);
    bindInt64(stmt.get(), 5, slot.kdfOpslimit);
    bindInt64(stmt.get(), 6, slot.kdfMemlimit);
    bindBlob(stmt.get(), 7, slot.nonce);
    bindBlob(stmt.get(), 8, slot.wrappedDek);
    bindInt64(stmt.get(), 9, now);
    bindInt64(stmt.get(), 10, now);
    bindOptionalText(stmt.get(), 11, label);
    stepDone(db, stmt.get());
}

void removeActiveSlot(sqlite3* db, std::string_view slotType) {
    auto stmt = prepare(db, "DELETE FROM key_slots WHERE status = 'active' AND slot_type = ?");
    bindText(stmt.get(), 1, slotType);
    stepDone(db, stmt.get());
}

void initializeSchema(sqlite3* db, std::string_view namespaceName) {
    execute(db, kSchema);

    auto countStmt = prepare(db, "SELECT COUNT(*) FROM metadata");
    if (sqlite3_step(countStmt.get()) != SQLITE_ROW) {
        throw std::runtime_error("failed to count metadata rows");
    }
    if (sqlite3_column_int(countStmt.get(), 0) > 0) {
        return;
    }

    auto insert = prepare(
        db,
        "INSERT INTO metadata (schema_version, created_at, updated_at, namespace_name) VALUES (?, ?, ?, ?)");
    const auto now = nowSeconds();
    bindInt64(insert.get(), 1, kSchemaVersion);
    bindInt64(insert.get(), 2, now);
    bindInt64(insert.get(), 3, now);
    bindText(insert.get(), 4, namespaceName);
    stepDone(db, insert.get());
}

void validateSchema(sqlite3* db, std::string_view namespaceName) {
    auto stmt = prepare(db, "SELECT schema_version, namespace_name FROM metadata LIMIT 1");
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
        throw std::runtime_error("metadata row is missing");
    }
    if (sqlite3_column_int(stmt.get(), 0) != kSchemaVersion) {
        throw std::runtime_error("unsupported schema version");
    }
    if (columnText(stmt.get(), 1) != namespaceName) {
        throw std::runtime_error("namespace metadata mismatch");
    }
}

sqlite_ptr openDatabase(const std::filesystem::path& dbPath, bool createIfMissing) {
    ensurePrivateDirectory(dbPath.parent_path());

    sqlite3* rawDb = nullptr;
    const int flags = SQLITE_OPEN_READWRITE |
        SQLITE_OPEN_FULLMUTEX |
        (createIfMissing ? SQLITE_OPEN_CREATE : 0);
    if (sqlite3_open_v2(dbPath.string().c_str(), &rawDb, flags, nullptr) != SQLITE_OK) {
        const std::string message = rawDb != nullptr ? sqlite3_errmsg(rawDb) : "failed to open sqlite database";
        if (rawDb != nullptr) {
            sqlite3_close(rawDb);
        }
        throw std::runtime_error(message);
    }

    sqlite_ptr db(rawDb);
    sqlite3_busy_timeout(db.get(), 5000);
    execute(db.get(), "PRAGMA foreign_keys = ON");
    execute(db.get(), "PRAGMA journal_mode = WAL");
    execute(db.get(), "PRAGMA synchronous = FULL");
    lockDownDatabaseArtifacts(dbPath);
    return db;
}

} // namespace

class SafeKeeping::Impl {
public:
    Impl(std::string namespaceName,
         sqlite_ptr db,
         std::filesystem::path dbPath,
         std::unique_ptr<VaultBackend> vaultBackend)
        : namespaceName_(std::move(namespaceName)),
          db_(std::move(db)),
          dbPath_(std::move(dbPath)),
          vaultBackend_(std::move(vaultBackend)) {}

    ~Impl() {
        lock();
    }

    static CreateResult createNew(std::string namespaceName, const CreateOptions& options) {
        validateNamespaceOrSecretName(namespaceName, "namespace");
        const auto dbPath = databasePath(namespaceName);
        if (std::filesystem::exists(dbPath)) {
            throw std::runtime_error("namespace already exists");
        }

        auto vaultBackend = makeVaultBackend();
        const bool vaultAvailable = vaultBackend != nullptr && vaultBackend->available();
        if (!vaultAvailable && !options.passphrase.has_value() &&
            options.requireAtLeastOneUnlockMethod) {
            throw std::runtime_error("no usable unlock method is available");
        }

        const bytes dek = randomBytes(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        std::optional<std::string> recoveryKeyString;

        try {
            auto db = openDatabase(dbPath, true);
            Transaction txn(db.get());
            initializeSchema(db.get(), namespaceName);

            if (options.createSystemVaultSlot && vaultAvailable) {
                const std::string vaultMaterial = bytesToHex(randomBytes(32));
                if (!vaultBackend->store(namespaceName, kVaultEntryName, vaultMaterial)) {
                    throw std::runtime_error("failed to store vault material");
                }
                const auto kek = deriveVaultKek(vaultMaterial);
                insertSlot(db.get(),
                           buildWrappedSlot("vault",
                                            "vault",
                                            dek,
                                            kek,
                                            std::nullopt,
                                            std::nullopt,
                                            0,
                                            0));
            }

            if (options.passphrase.has_value()) {
                const bytes salt = randomBytes(crypto_pwhash_SALTBYTES);
                const auto kek = derivePassphraseKek(*options.passphrase,
                                                     salt,
                                                     crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                                     crypto_pwhash_MEMLIMIT_INTERACTIVE);
                insertSlot(db.get(),
                           buildWrappedSlot("passphrase",
                                            "passphrase",
                                            dek,
                                            kek,
                                            std::string("argon2id"),
                                            salt,
                                            crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                            crypto_pwhash_MEMLIMIT_INTERACTIVE));
            }

            if (options.createRecoveryKey) {
                auto [formattedKey, rawRecovery] = generateRecoverySecret();
                const bytes salt = randomBytes(crypto_pwhash_SALTBYTES);
                const auto kek = derivePassphraseKek(normalizeRecoveryKey(formattedKey),
                                                     salt,
                                                     crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                                     crypto_pwhash_MEMLIMIT_INTERACTIVE);
                insertSlot(db.get(),
                           buildWrappedSlot("recovery",
                                            "recovery",
                                            dek,
                                            kek,
                                            std::string("argon2id"),
                                            salt,
                                            crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                            crypto_pwhash_MEMLIMIT_INTERACTIVE));
                recoveryKeyString = formattedKey;
                sodium_memzero(rawRecovery.data(), rawRecovery.size());
            }

            if (activeSlotCount(db.get()) == 0 && options.requireAtLeastOneUnlockMethod) {
                throw std::runtime_error("namespace would be created without an unlock method");
            }

            txn.commit();
            lockDownDatabaseArtifacts(dbPath);

            auto impl = std::make_unique<Impl>(namespaceName, std::move(db), dbPath, std::move(vaultBackend));
            impl->dek_ = dek;
            impl->unlocked_ = true;
            return {.instance = std::unique_ptr<SafeKeeping>(new SafeKeeping(std::move(impl))),
                    .recoveryKey = recoveryKeyString};
        } catch (...) {
            std::error_code ignored;
            if (vaultAvailable) {
                vaultBackend->remove(namespaceName, kVaultEntryName);
            }
            std::filesystem::remove_all(dbPath.parent_path(), ignored);
            throw;
        }
    }

    static std::unique_ptr<SafeKeeping> open(std::string namespaceName, const UnlockOptions& options) {
        validateNamespaceOrSecretName(namespaceName, "namespace");
        const auto dbPath = databasePath(namespaceName);
        if (!std::filesystem::exists(dbPath)) {
            return nullptr;
        }

        auto db = openDatabase(dbPath, false);
        validateSchema(db.get(), namespaceName);

        auto impl = std::make_unique<Impl>(namespaceName, std::move(db), dbPath, makeVaultBackend());
        auto result = std::unique_ptr<SafeKeeping>(new SafeKeeping(std::move(impl)));

        if (options.trySystemVaultFirst) {
            result->unlockWithSystemVault();
        }
        if (!result->isUnlocked() && options.passphrase.has_value()) {
            result->unlockWithPassphrase(*options.passphrase);
        }
        if (!result->isUnlocked() && options.recoveryKey.has_value()) {
            result->unlockWithRecoveryKey(*options.recoveryKey);
        }
        return result;
    }

    static bool exists(std::string_view namespaceName) {
        return std::filesystem::exists(databasePath(namespaceName));
    }

    static bool removeNamespace(std::string namespaceName) {
        validateNamespaceOrSecretName(namespaceName, "namespace");
        const auto dbPath = databasePath(namespaceName);
        const bool dbExists = std::filesystem::exists(dbPath);
        const auto vaultBackend = makeVaultBackend();
        if (vaultBackend != nullptr && vaultBackend->available()) {
            vaultBackend->remove(namespaceName, kVaultEntryName);
        }
        std::error_code error;
        std::filesystem::remove_all(dbPath.parent_path(), error);
        return dbExists && !error;
    }

    const std::string& namespaceName() const noexcept {
        return namespaceName_;
    }

    bool isUnlocked() const noexcept {
        return unlocked_;
    }

    bool unlockWithSystemVault() {
        if (unlocked_) {
            return true;
        }
        if (!hasSlot(db_.get(), kSlotTypeVault)) {
            fail(Error::UnlockUnavailable, "system vault unlock slot is not configured");
        }
        if (vaultBackend_ == nullptr || !vaultBackend_->available()) {
            fail(Error::VaultError, "system vault backend is not available");
        }

        const auto material = vaultBackend_->load(namespaceName_, kVaultEntryName);
        if (!material.has_value()) {
            fail(Error::VaultError, "failed to load namespace material from the system vault");
        }

        try {
            const auto slot = readSingleSlot(db_.get(), kSlotTypeVault);
            const auto dek = unwrapDek(slot, deriveVaultKek(*material), "schema-1");
            setUnlockedDek(dek);
            return true;
        } catch (const OperationError&) {
            throw;
        } catch (const std::exception&) {
            fail(Error::UnlockFailed, "system vault material did not unlock the namespace");
        }
    }

    bool unlockWithPassphrase(std::string_view passphrase) {
        if (unlocked_) {
            return true;
        }
        if (!hasSlot(db_.get(), kSlotTypePassphrase)) {
            fail(Error::UnlockUnavailable, "passphrase unlock slot is not configured");
        }

        try {
            const auto slot = readSingleSlot(db_.get(), kSlotTypePassphrase);
            if (!slot.kdfSalt.has_value()) {
                fail(Error::DataCorrupted, "passphrase slot is missing KDF salt");
            }
            const auto dek = unwrapDek(slot,
                                       derivePassphraseKek(passphrase,
                                                           *slot.kdfSalt,
                                                           slot.kdfOpslimit,
                                                           static_cast<std::size_t>(slot.kdfMemlimit)),
                                       "schema-1");
            setUnlockedDek(dek);
            return true;
        } catch (const OperationError&) {
            throw;
        } catch (const std::exception&) {
            fail(Error::UnlockFailed, "passphrase did not unlock the namespace");
        }
    }

    bool unlockWithRecoveryKey(std::string_view recoveryKey) {
        if (unlocked_) {
            return true;
        }
        if (!hasSlot(db_.get(), kSlotTypeRecovery)) {
            fail(Error::UnlockUnavailable, "recovery key unlock slot is not configured");
        }

        try {
            const auto slot = readSingleSlot(db_.get(), kSlotTypeRecovery);
            if (!slot.kdfSalt.has_value()) {
                fail(Error::DataCorrupted, "recovery slot is missing KDF salt");
            }
            const auto dek = unwrapDek(slot,
                                       derivePassphraseKek(normalizeRecoveryKey(recoveryKey),
                                                           *slot.kdfSalt,
                                                           slot.kdfOpslimit,
                                                           static_cast<std::size_t>(slot.kdfMemlimit)),
                                       "schema-1");
            setUnlockedDek(dek);
            return true;
        } catch (const OperationError&) {
            throw;
        } catch (const std::exception&) {
            fail(Error::UnlockFailed, "recovery key did not unlock the namespace");
        }
    }

    bool lock() {
        if (!dek_.empty()) {
            sodium_memzero(dek_.data(), dek_.size());
            dek_.clear();
        }
        unlocked_ = false;
        return true;
    }

    bool storeSecret(std::string_view name,
                     byte_view secret,
                     std::optional<std::string_view> description = std::nullopt) {
        requireUnlocked();
        validateNamespaceOrSecretName(name, "secret name");
        validateSecretValue(secret);
        if (description.has_value()) {
            validateDescription(*description);
        }

        const bytes nameHash = computeNameHash(dek_, name);
        SecretRecord record;
        record.nameHash = nameHash;
        record.nameCiphertext = aeadEncrypt(toBytes(name),
                                            dek_,
                                            "secret-name-v1:" + bytesToHex(nameHash),
                                            record.nameNonce);
        record.valueCiphertext = aeadEncrypt(toBytes(secret),
                                             dek_,
                                             "secret-value-v1:" + bytesToHex(nameHash),
                                             record.valueNonce);
        if (description.has_value()) {
            bytes nonce;
            record.descriptionCiphertext = aeadEncrypt(
                toBytes(*description),
                dek_,
                "secret-description-v1:" + bytesToHex(nameHash),
                nonce);
            record.descriptionNonce = std::move(nonce);
        }

        Transaction txn(db_.get());
        auto stmt = prepare(
            db_.get(),
            "INSERT INTO secrets (name_hash, name_nonce, name_ciphertext, value_nonce, value_ciphertext, "
            "description_nonce, description_ciphertext, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(name_hash) DO UPDATE SET "
            "name_nonce = excluded.name_nonce, "
            "name_ciphertext = excluded.name_ciphertext, "
            "value_nonce = excluded.value_nonce, "
            "value_ciphertext = excluded.value_ciphertext, "
            "description_nonce = excluded.description_nonce, "
            "description_ciphertext = excluded.description_ciphertext, "
            "updated_at = excluded.updated_at");
        const auto now = nowSeconds();
        bindBlob(stmt.get(), 1, record.nameHash);
        bindBlob(stmt.get(), 2, record.nameNonce);
        bindBlob(stmt.get(), 3, record.nameCiphertext);
        bindBlob(stmt.get(), 4, record.valueNonce);
        bindBlob(stmt.get(), 5, record.valueCiphertext);
        bindOptionalBlob(stmt.get(), 6, record.descriptionNonce);
        bindOptionalBlob(stmt.get(), 7, record.descriptionCiphertext);
        bindInt64(stmt.get(), 8, now);
        bindInt64(stmt.get(), 9, now);
        stepDone(db_.get(), stmt.get());
        updateMetadataTimestamp();
        txn.commit();
        lockDownDatabaseArtifacts(dbPath_);
        return true;
    }

    std::optional<std::vector<std::byte>> retrieveSecretBytes(std::string_view name) const {
        requireUnlocked();
        validateNamespaceOrSecretName(name, "secret name");
        const bytes nameHash = computeNameHash(dek_, name);
        auto stmt = prepare(
            db_.get(),
            "SELECT name_nonce, name_ciphertext, value_nonce, value_ciphertext "
            "FROM secrets WHERE name_hash = ?");
        bindBlob(stmt.get(), 1, nameHash);
        if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
            fail(Error::NotFound, "secret was not found");
        }

        const bytes nameNonce = columnBlob(stmt.get(), 0);
        const bytes nameCiphertext = columnBlob(stmt.get(), 1);
        const bytes valueNonce = columnBlob(stmt.get(), 2);
        const bytes valueCiphertext = columnBlob(stmt.get(), 3);

        const auto decryptedNameBytes = aeadDecrypt(nameCiphertext,
                                                    nameNonce,
                                                    dek_,
                                                    "secret-name-v1:" + bytesToHex(nameHash));
        const std::string decryptedName(reinterpret_cast<const char*>(decryptedNameBytes.data()),
                                        decryptedNameBytes.size());

        if (decryptedName != name) {
            fail(Error::DataCorrupted, "secret name payload is corrupted");
        }

        const auto plaintext = aeadDecrypt(valueCiphertext,
                                           valueNonce,
                                           dek_,
                                           "secret-value-v1:" + bytesToHex(nameHash));
        return toByteVector(plaintext);
    }

    bool removeSecret(std::string_view name) {
        requireUnlocked();
        validateNamespaceOrSecretName(name, "secret name");
        Transaction txn(db_.get());
        auto stmt = prepare(db_.get(), "DELETE FROM secrets WHERE name_hash = ?");
        bindBlob(stmt.get(), 1, computeNameHash(dek_, name));
        stepDone(db_.get(), stmt.get());
        const bool removed = sqlite3_changes(db_.get()) > 0;
        if (!removed) {
            fail(Error::NotFound, "secret was not found");
        }
        updateMetadataTimestamp();
        txn.commit();
        return true;
    }

    info_list_t listSecrets() const {
        requireUnlocked();
        auto stmt = prepare(
            db_.get(),
            "SELECT name_hash, name_nonce, name_ciphertext, description_nonce, description_ciphertext FROM secrets");
        info_list_t list;
        while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            const bytes nameHash = columnBlob(stmt.get(), 0);
            const bytes nameNonce = columnBlob(stmt.get(), 1);
            const bytes nameCiphertext = columnBlob(stmt.get(), 2);
            const auto descriptionNonce = columnOptionalBlob(stmt.get(), 3);
            const auto descriptionCiphertext = columnOptionalBlob(stmt.get(), 4);

            const auto decryptedName = aeadDecrypt(nameCiphertext,
                                                   nameNonce,
                                                   dek_,
                                                   "secret-name-v1:" + bytesToHex(nameHash));
            std::string description;
            if (descriptionNonce.has_value() && descriptionCiphertext.has_value()) {
                const auto decryptedDescription = aeadDecrypt(*descriptionCiphertext,
                                                              *descriptionNonce,
                                                              dek_,
                                                              "secret-description-v1:" + bytesToHex(nameHash));
                description.assign(reinterpret_cast<const char*>(decryptedDescription.data()),
                                   decryptedDescription.size());
            }
            list.push_back({
                .name = std::string(reinterpret_cast<const char*>(decryptedName.data()), decryptedName.size()),
                .description = std::move(description),
            });
        }

        std::sort(list.begin(), list.end(), [](const Info& lhs, const Info& rhs) {
            return lhs.name < rhs.name;
        });
        return list;
    }

    bool hasSystemVaultSlot() const {
        return hasSlot(db_.get(), kSlotTypeVault);
    }

    bool hasPassphraseSlot() const {
        return hasSlot(db_.get(), kSlotTypePassphrase);
    }

    bool hasRecoverySlot() const {
        return hasSlot(db_.get(), kSlotTypeRecovery);
    }

    std::vector<UnlockMethod> availableUnlockMethods() const {
        return listUnlockMethods(db_.get());
    }

    bool addSystemVaultSlot() {
        requireUnlocked();
        if (hasSystemVaultSlot()) {
            fail(Error::AlreadyExists, "system vault slot already exists");
        }
        if (vaultBackend_ == nullptr || !vaultBackend_->available()) {
            fail(Error::VaultError, "system vault backend is not available");
        }

        const std::string material = bytesToHex(randomBytes(32));
        if (!vaultBackend_->store(namespaceName_, kVaultEntryName, material)) {
            fail(Error::VaultError, "failed to store namespace material in the system vault");
        }

        Transaction txn(db_.get());
        insertSlot(db_.get(),
                   buildWrappedSlot("vault",
                                    "vault",
                                    dek_,
                                    deriveVaultKek(material),
                                    std::nullopt,
                                    std::nullopt,
                                    0,
                                    0));
        updateMetadataTimestamp();
        txn.commit();
        return true;
    }

    bool addPassphrase(std::string_view passphrase) {
        requireUnlocked();
        if (hasPassphraseSlot()) {
            fail(Error::AlreadyExists, "passphrase slot already exists");
        }

        const bytes salt = randomBytes(crypto_pwhash_SALTBYTES);
        const auto kek = derivePassphraseKek(passphrase,
                                             salt,
                                             crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                             crypto_pwhash_MEMLIMIT_INTERACTIVE);
        Transaction txn(db_.get());
        insertSlot(db_.get(),
                   buildWrappedSlot("passphrase",
                                    "passphrase",
                                    dek_,
                                    kek,
                                    std::string("argon2id"),
                                    salt,
                                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                    crypto_pwhash_MEMLIMIT_INTERACTIVE));
        updateMetadataTimestamp();
        txn.commit();
        return true;
    }

    bool changePassphrase(std::string_view newPassphrase) {
        requireUnlocked();
        if (!hasPassphraseSlot()) {
            fail(Error::NotFound, "passphrase slot does not exist");
        }

        const bytes salt = randomBytes(crypto_pwhash_SALTBYTES);
        const auto kek = derivePassphraseKek(newPassphrase,
                                             salt,
                                             crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                             crypto_pwhash_MEMLIMIT_INTERACTIVE);
        Transaction txn(db_.get());
        removeActiveSlot(db_.get(), kSlotTypePassphrase);
        insertSlot(db_.get(),
                   buildWrappedSlot("passphrase",
                                    "passphrase",
                                    dek_,
                                    kek,
                                    std::string("argon2id"),
                                    salt,
                                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                    crypto_pwhash_MEMLIMIT_INTERACTIVE));
        updateMetadataTimestamp();
        txn.commit();
        return true;
    }

    bool removePassphrase() {
        requireUnlocked();
        if (!hasPassphraseSlot()) {
            fail(Error::NotFound, "passphrase slot does not exist");
        }
        if (activeSlotCount(db_.get()) <= 1) {
            fail(Error::InvalidArgument, "cannot remove the last unlock method");
        }

        Transaction txn(db_.get());
        removeActiveSlot(db_.get(), kSlotTypePassphrase);
        updateMetadataTimestamp();
        txn.commit();
        return true;
    }

    std::optional<std::string> rotateRecoveryKey() {
        requireUnlocked();
        if (!hasRecoverySlot() && activeSlotCount(db_.get()) == 0) {
            fail(Error::InvalidArgument, "cannot rotate recovery key without an active unlock method");
        }

        auto [formattedKey, rawRecovery] = generateRecoverySecret();
        const bytes salt = randomBytes(crypto_pwhash_SALTBYTES);
        const auto kek = derivePassphraseKek(normalizeRecoveryKey(formattedKey),
                                             salt,
                                             crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                             crypto_pwhash_MEMLIMIT_INTERACTIVE);
        Transaction txn(db_.get());
        removeActiveSlot(db_.get(), kSlotTypeRecovery);
        insertSlot(db_.get(),
                   buildWrappedSlot("recovery",
                                    "recovery",
                                    dek_,
                                    kek,
                                    std::string("argon2id"),
                                    salt,
                                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                    crypto_pwhash_MEMLIMIT_INTERACTIVE));
        updateMetadataTimestamp();
        txn.commit();
        sodium_memzero(rawRecovery.data(), rawRecovery.size());
        return formattedKey;
    }

    bool removeRecoveryKey() {
        requireUnlocked();
        if (!hasRecoverySlot()) {
            fail(Error::NotFound, "recovery slot does not exist");
        }
        if (activeSlotCount(db_.get()) <= 1) {
            fail(Error::InvalidArgument, "cannot remove the last unlock method");
        }

        Transaction txn(db_.get());
        removeActiveSlot(db_.get(), kSlotTypeRecovery);
        updateMetadataTimestamp();
        txn.commit();
        return true;
    }

    void clearLastError() const {
        lastError_ = {};
    }

    void setLastError(Error error, std::string message) const {
        lastError_ = {.error = error, .message = std::move(message)};
    }

    [[nodiscard]] LatestError latestError() const {
        return lastError_;
    }

private:

    void updateMetadataTimestamp() {
        auto stmt = prepare(db_.get(), "UPDATE metadata SET updated_at = ?");
        bindInt64(stmt.get(), 1, nowSeconds());
        stepDone(db_.get(), stmt.get());
    }

    void requireUnlocked() const {
        if (!unlocked_) {
            fail(Error::Locked, "namespace is locked");
        }
    }

    void setUnlockedDek(const bytes& dek) {
        if (dek.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
            throw std::runtime_error("unexpected DEK size");
        }
        dek_ = dek;
        unlocked_ = true;
    }

    std::string namespaceName_;
    sqlite_ptr db_;
    std::filesystem::path dbPath_;
    std::unique_ptr<VaultBackend> vaultBackend_;
    bytes dek_;
    bool unlocked_ = false;
    mutable LatestError lastError_;
};

SafeKeeping::SafeKeeping(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

SafeKeeping::SafeKeeping(SafeKeeping&&) noexcept = default;
SafeKeeping& SafeKeeping::operator=(SafeKeeping&&) noexcept = default;
SafeKeeping::~SafeKeeping() = default;

namespace {

template <typename Fn>
bool runBoolOperation(const auto& impl, Fn&& fn) {
    impl.clearLastError();
    try {
        return std::forward<Fn>(fn)();
    } catch (const OperationError& error) {
        impl.setLastError(error.error(), error.what());
    } catch (const std::invalid_argument& error) {
        impl.setLastError(SafeKeeping::Error::InvalidArgument, error.what());
    } catch (const std::logic_error& error) {
        impl.setLastError(SafeKeeping::Error::Locked, error.what());
    } catch (const std::runtime_error& error) {
        impl.setLastError(SafeKeeping::Error::StorageError, error.what());
    } catch (const std::exception& error) {
        impl.setLastError(SafeKeeping::Error::InternalError, error.what());
    }
    return false;
}

template <typename T, typename Fn>
T runValueOperation(const auto& impl, T fallback, Fn&& fn) {
    impl.clearLastError();
    try {
        return std::forward<Fn>(fn)();
    } catch (const OperationError& error) {
        impl.setLastError(error.error(), error.what());
    } catch (const std::invalid_argument& error) {
        impl.setLastError(SafeKeeping::Error::InvalidArgument, error.what());
    } catch (const std::logic_error& error) {
        impl.setLastError(SafeKeeping::Error::Locked, error.what());
    } catch (const std::runtime_error& error) {
        impl.setLastError(SafeKeeping::Error::StorageError, error.what());
    } catch (const std::exception& error) {
        impl.setLastError(SafeKeeping::Error::InternalError, error.what());
    }
    return fallback;
}

byte_view asByteView(std::string_view value) {
    return {reinterpret_cast<const std::byte*>(value.data()), value.size()};
}

} // namespace

SafeKeeping::CreateResult SafeKeeping::createNew(std::string namespaceName) {
    return Impl::createNew(std::move(namespaceName), CreateOptions{});
}

SafeKeeping::CreateResult SafeKeeping::createNew(std::string namespaceName,
                                                 CreateOptions options) {
    return Impl::createNew(std::move(namespaceName), options);
}

std::unique_ptr<SafeKeeping> SafeKeeping::open(std::string namespaceName) {
    return Impl::open(std::move(namespaceName), UnlockOptions{});
}

std::unique_ptr<SafeKeeping> SafeKeeping::open(std::string namespaceName,
                                               UnlockOptions options) {
    return Impl::open(std::move(namespaceName), options);
}

std::unique_ptr<SafeKeeping> SafeKeeping::openOrCreate(std::string namespaceName) {
    return openOrCreate(std::move(namespaceName), CreateOptions{});
}

std::unique_ptr<SafeKeeping> SafeKeeping::openOrCreate(std::string namespaceName,
                                                       CreateOptions options) {
    if (exists(namespaceName)) {
        return open(std::move(namespaceName));
    }
    return createNew(std::move(namespaceName), std::move(options)).instance;
}

void SafeKeeping::setLinuxVaultRootName(std::string name) {
    validateLinuxVaultRootName(name);
    std::scoped_lock lock(linuxVaultRootMutex());
    linuxVaultRootStorage() = std::move(name);
}

std::string SafeKeeping::linuxVaultRootName() {
    return jgaa::safekeeping::linuxVaultRootName();
}

bool SafeKeeping::exists(std::string_view namespaceName) {
    return Impl::exists(namespaceName);
}

bool SafeKeeping::removeNamespace(std::string namespaceName) {
    return Impl::removeNamespace(std::move(namespaceName));
}

const std::string& SafeKeeping::namespaceName() const noexcept {
    return impl_->namespaceName();
}

bool SafeKeeping::isUnlocked() const noexcept {
    return impl_->isUnlocked();
}

bool SafeKeeping::unlockWithSystemVault() {
    return runBoolOperation(*impl_, [this] {
        return impl_->unlockWithSystemVault();
    });
}

bool SafeKeeping::unlockWithPassphrase(std::string_view passphrase) {
    return runBoolOperation(*impl_, [this, passphrase] {
        return impl_->unlockWithPassphrase(passphrase);
    });
}

bool SafeKeeping::unlockWithRecoveryKey(std::string_view recoveryKey) {
    return runBoolOperation(*impl_, [this, recoveryKey] {
        return impl_->unlockWithRecoveryKey(recoveryKey);
    });
}

bool SafeKeeping::lock() {
    return runBoolOperation(*impl_, [this] {
        return impl_->lock();
    });
}

bool SafeKeeping::storeSecret(std::string_view name, std::string_view secret) {
    return storeSecret(name, asByteView(secret));
}

bool SafeKeeping::storeSecret(std::string_view name, std::span<const std::byte> secret) {
    return runBoolOperation(*impl_, [this, name, secret] {
        return impl_->storeSecret(name, secret);
    });
}

bool SafeKeeping::storeSecretWithDescription(std::string_view name,
                                             std::string_view secret,
                                             std::string_view description) {
    return storeSecretWithDescription(name, asByteView(secret), description);
}

bool SafeKeeping::storeSecretWithDescription(std::string_view name,
                                             std::span<const std::byte> secret,
                                             std::string_view description) {
    return runBoolOperation(*impl_, [this, name, secret, description] {
        return impl_->storeSecret(name, secret, description);
    });
}

std::optional<std::string> SafeKeeping::retrieveSecret(std::string_view name) const {
    const auto value = retrieveSecretBytes(name);
    if (!value.has_value()) {
        return std::nullopt;
    }
    return std::string(reinterpret_cast<const char*>(value->data()), value->size());
}

std::optional<std::vector<std::byte>> SafeKeeping::retrieveSecretBytes(std::string_view name) const {
    return runValueOperation(*impl_, std::optional<std::vector<std::byte>>{}, [this, name] {
        return impl_->retrieveSecretBytes(name);
    });
}

bool SafeKeeping::removeSecret(std::string_view name) {
    return runBoolOperation(*impl_, [this, name] {
        return impl_->removeSecret(name);
    });
}

SafeKeeping::info_list_t SafeKeeping::listSecrets() const {
    return runValueOperation(*impl_, info_list_t{}, [this] {
        return impl_->listSecrets();
    });
}

SafeKeeping::LatestError SafeKeeping::latestError() const {
    return impl_->latestError();
}

bool SafeKeeping::hasSystemVaultSlot() const {
    return impl_->hasSystemVaultSlot();
}

bool SafeKeeping::hasPassphraseSlot() const {
    return impl_->hasPassphraseSlot();
}

bool SafeKeeping::hasRecoverySlot() const {
    return impl_->hasRecoverySlot();
}

std::vector<SafeKeeping::UnlockMethod> SafeKeeping::availableUnlockMethods() const {
    return impl_->availableUnlockMethods();
}

bool SafeKeeping::addSystemVaultSlot() {
    return runBoolOperation(*impl_, [this] {
        return impl_->addSystemVaultSlot();
    });
}

bool SafeKeeping::addPassphrase(std::string_view passphrase) {
    return runBoolOperation(*impl_, [this, passphrase] {
        return impl_->addPassphrase(passphrase);
    });
}

bool SafeKeeping::changePassphrase(std::string_view newPassphrase) {
    return runBoolOperation(*impl_, [this, newPassphrase] {
        return impl_->changePassphrase(newPassphrase);
    });
}

bool SafeKeeping::removePassphrase() {
    return runBoolOperation(*impl_, [this] {
        return impl_->removePassphrase();
    });
}

std::optional<std::string> SafeKeeping::rotateRecoveryKey() {
    return runValueOperation(*impl_, std::optional<std::string>{}, [this] {
        return impl_->rotateRecoveryKey();
    });
}

bool SafeKeeping::removeRecoveryKey() {
    return runBoolOperation(*impl_, [this] {
        return impl_->removeRecoveryKey();
    });
}

} // namespace jgaa::safekeeping
