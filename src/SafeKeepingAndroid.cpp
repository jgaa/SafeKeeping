#include "safekeeping/SafeKeeping.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <regex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace jgaa::safekeeping {

namespace {

using byte_vector = std::vector<std::byte>;

constexpr std::string_view kMetadataFileName = "namespace.meta";
constexpr std::string_view kSecretsDirName = "secrets";
constexpr std::string_view kVaultMaterialFileName = "vault-material.txt";
constexpr std::size_t kMaxSecretSize = 10 * 1024;

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

[[nodiscard]] std::string toString(std::string_view value) {
    return std::string(value.begin(), value.end());
}

[[nodiscard]] std::string lowerHex(std::span<const unsigned char> data) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (unsigned char byte : data) {
        out.push_back(digits[(byte >> 4U) & 0x0FU]);
        out.push_back(digits[byte & 0x0FU]);
    }
    return out;
}

[[nodiscard]] std::string hexEncode(std::string_view value) {
    return lowerHex({reinterpret_cast<const unsigned char*>(value.data()), value.size()});
}

[[nodiscard]] std::optional<unsigned char> hexNibble(char ch) {
    if (ch >= '0' && ch <= '9') {
        return static_cast<unsigned char>(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return static_cast<unsigned char>(10 + (ch - 'a'));
    }
    if (ch >= 'A' && ch <= 'F') {
        return static_cast<unsigned char>(10 + (ch - 'A'));
    }
    return std::nullopt;
}

[[nodiscard]] std::string hexDecode(std::string_view value) {
    if ((value.size() % 2U) != 0U) {
        throw std::runtime_error("invalid hex encoding");
    }

    std::string out;
    out.reserve(value.size() / 2U);
    for (std::size_t i = 0; i < value.size(); i += 2U) {
        const auto hi = hexNibble(value[i]);
        const auto lo = hexNibble(value[i + 1U]);
        if (!hi.has_value() || !lo.has_value()) {
            throw std::runtime_error("invalid hex encoding");
        }
        out.push_back(static_cast<char>((*hi << 4U) | *lo));
    }
    return out;
}

[[nodiscard]] std::string randomHex(std::size_t bytes) {
    std::random_device device;
    std::uniform_int_distribution<unsigned int> dist(0, 255);
    std::vector<unsigned char> raw(bytes);
    for (auto& byte : raw) {
        byte = static_cast<unsigned char>(dist(device));
    }
    return lowerHex(raw);
}

void validateNamespaceOrSecretName(std::string_view name, std::string_view label) {
    static const std::regex validName{R"(^[A-Za-z0-9_.-]{1,128}$)"};
    if (!std::regex_match(name.begin(), name.end(), validName)) {
        fail(SafeKeeping::Error::InvalidArgument,
             toString(label) + " must match [A-Za-z0-9_.-]{1,128}");
    }
}

void validateDescription(std::string_view description) {
    if (description.size() > 4096U) {
        fail(SafeKeeping::Error::InvalidArgument, "description is too long");
    }
}

void validateSecretValue(std::span<const std::byte> secret) {
    if (secret.size() > kMaxSecretSize) {
        fail(SafeKeeping::Error::TooLarge, "secret exceeds 10240 bytes");
    }
}

[[nodiscard]] std::filesystem::path pathFromEnv(const char* name) {
    if (const char* value = std::getenv(name); value != nullptr && *value != '\0') {
        return value;
    }
    return {};
}

[[nodiscard]] std::filesystem::path userHomePath() {
    if (const char* home = std::getenv("HOME"); home != nullptr && *home != '\0') {
        return home;
    }
    throw std::runtime_error("HOME is not set");
}

[[nodiscard]] std::filesystem::path baseDataPath() {
    if (const auto overridePath = pathFromEnv("SAFEKEEPING_DATA_DIR"); !overridePath.empty()) {
        return overridePath;
    }
    return userHomePath() / "files" / "safekeeping";
}

[[nodiscard]] std::filesystem::path namespacePath(std::string_view namespaceName) {
    validateNamespaceOrSecretName(namespaceName, "namespace");
    return baseDataPath() / toString(namespaceName);
}

[[nodiscard]] std::filesystem::path metadataPath(std::string_view namespaceName) {
    return namespacePath(namespaceName) / kMetadataFileName;
}

[[nodiscard]] std::filesystem::path secretsPath(std::string_view namespaceName) {
    return namespacePath(namespaceName) / kSecretsDirName;
}

[[nodiscard]] std::filesystem::path secretValuePath(std::string_view namespaceName, std::string_view secretName) {
    return secretsPath(namespaceName) / (toString(secretName) + ".secret");
}

[[nodiscard]] std::filesystem::path secretDescriptionPath(std::string_view namespaceName, std::string_view secretName) {
    return secretsPath(namespaceName) / (toString(secretName) + ".desc");
}

[[nodiscard]] std::filesystem::path vaultMaterialPath(std::string_view namespaceName) {
    return namespacePath(namespaceName) / kVaultMaterialFileName;
}

void lockDownPath(const std::filesystem::path& path, bool directory) {
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
}

void ensurePrivateDirectory(const std::filesystem::path& path) {
    std::filesystem::create_directories(path);
    lockDownPath(path, true);
}

void writeBytes(const std::filesystem::path& path, std::span<const std::byte> data) {
    ensurePrivateDirectory(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("failed to open file for writing");
    }
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    out.close();
    if (!out.good()) {
        throw std::runtime_error("failed to write file");
    }
    lockDownPath(path, false);
}

void writeText(const std::filesystem::path& path, std::string_view value) {
    writeBytes(path,
               {reinterpret_cast<const std::byte*>(value.data()),
                value.size()});
}

[[nodiscard]] byte_vector readBytes(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open file for reading");
    }
    const std::vector<char> raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    byte_vector out(raw.size());
    std::transform(raw.begin(), raw.end(), out.begin(), [](char ch) {
        return static_cast<std::byte>(static_cast<unsigned char>(ch));
    });
    return out;
}

[[nodiscard]] std::string readText(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open file for reading");
    }
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

struct Metadata {
    std::string namespaceName;
    bool hasSystemVaultSlot = false;
    bool hasPassphraseSlot = false;
    std::optional<std::string> passphrase;
    bool hasRecoveryKeySlot = false;
    std::optional<std::string> recoveryKey;
};

[[nodiscard]] Metadata loadMetadata(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open metadata");
    }

    std::map<std::string, std::string> values;
    std::string line;
    while (std::getline(in, line)) {
        const auto pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }
        values.emplace(line.substr(0, pos), line.substr(pos + 1U));
    }

    Metadata metadata;
    metadata.namespaceName = hexDecode(values["namespace"]);
    metadata.hasSystemVaultSlot = values["system_vault_slot"] == "1";
    metadata.hasPassphraseSlot = values["passphrase_slot"] == "1";
    if (metadata.hasPassphraseSlot) {
        const auto it = values.find("passphrase");
        if (it == values.end()) {
            throw std::runtime_error("passphrase slot metadata is missing");
        }
        metadata.passphrase = hexDecode(it->second);
    }
    metadata.hasRecoveryKeySlot = values["recovery_key_slot"] == "1";
    if (metadata.hasRecoveryKeySlot) {
        const auto it = values.find("recovery_key");
        if (it == values.end()) {
            throw std::runtime_error("recovery key slot metadata is missing");
        }
        metadata.recoveryKey = hexDecode(it->second);
    }
    return metadata;
}

void saveMetadata(const std::filesystem::path& path, const Metadata& metadata) {
    std::string text;
    text += "namespace=" + hexEncode(metadata.namespaceName) + "\n";
    text += "system_vault_slot=" + std::string(metadata.hasSystemVaultSlot ? "1" : "0") + "\n";
    text += "passphrase_slot=" + std::string(metadata.hasPassphraseSlot ? "1" : "0") + "\n";
    text += "passphrase=" + hexEncode(metadata.passphrase.value_or(std::string{})) + "\n";
    text += "recovery_key_slot=" + std::string(metadata.hasRecoveryKeySlot ? "1" : "0") + "\n";
    text += "recovery_key=" + hexEncode(metadata.recoveryKey.value_or(std::string{})) + "\n";
    writeText(path, text);
}

[[nodiscard]] std::string normalizeRecoveryKey(std::string_view recoveryKey) {
    std::string normalized;
    normalized.reserve(recoveryKey.size());
    for (unsigned char ch : recoveryKey) {
        if (std::isxdigit(ch) != 0) {
            normalized.push_back(static_cast<char>(std::tolower(ch)));
        }
    }
    return normalized;
}

[[nodiscard]] std::string formatRecoveryKey(std::string_view hex) {
    std::string formatted;
    formatted.reserve(hex.size() + (hex.size() / 4U));
    for (std::size_t i = 0; i < hex.size(); ++i) {
        if (i > 0U && (i % 4U) == 0U) {
            formatted.push_back('-');
        }
        formatted.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(hex[i]))));
    }
    return formatted;
}

[[nodiscard]] std::string generateRecoverySecret() {
    return formatRecoveryKey(randomHex(20));
}

template <typename Fn>
bool runBoolOperation(const auto& impl, Fn&& fn) {
    impl.clearLastError();
    try {
        return std::forward<Fn>(fn)();
    } catch (const OperationError& error) {
        impl.setLastError(error.error(), error.what());
    } catch (const std::invalid_argument& error) {
        impl.setLastError(SafeKeeping::Error::InvalidArgument, error.what());
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
    } catch (const std::runtime_error& error) {
        impl.setLastError(SafeKeeping::Error::StorageError, error.what());
    } catch (const std::exception& error) {
        impl.setLastError(SafeKeeping::Error::InternalError, error.what());
    }
    return fallback;
}

[[nodiscard]] std::span<const std::byte> asByteView(std::string_view value) {
    return {reinterpret_cast<const std::byte*>(value.data()), value.size()};
}

} // namespace

class SafeKeeping::Impl {
public:
    Impl(std::string namespaceName, Metadata metadata)
        : namespaceName_(std::move(namespaceName)),
          metadata_(std::move(metadata)) {}

    static CreateResult createNew(std::string namespaceName, const CreateOptions& options) {
        validateNamespaceOrSecretName(namespaceName, "namespace");
        const auto nsPath = namespacePath(namespaceName);
        if (std::filesystem::exists(metadataPath(namespaceName))) {
            throw std::runtime_error("namespace already exists");
        }

        if (!options.createSystemVaultSlot &&
            !options.passphrase.has_value() &&
            !options.createRecoveryKey &&
            options.requireAtLeastOneUnlockMethod) {
            throw std::runtime_error("no usable unlock method is available");
        }

        try {
            ensurePrivateDirectory(nsPath);
            ensurePrivateDirectory(secretsPath(namespaceName));

            Metadata metadata;
            metadata.namespaceName = namespaceName;
            metadata.hasSystemVaultSlot = options.createSystemVaultSlot;
            metadata.hasPassphraseSlot = options.passphrase.has_value();
            metadata.passphrase = options.passphrase;
            std::optional<std::string> recoveryKey;
            if (options.createRecoveryKey) {
                recoveryKey = generateRecoverySecret();
                metadata.hasRecoveryKeySlot = true;
                metadata.recoveryKey = recoveryKey;
            }

            if (metadata.hasSystemVaultSlot) {
                writeText(vaultMaterialPath(namespaceName), randomHex(32));
            }
            saveMetadata(metadataPath(namespaceName), metadata);

            auto impl = std::make_unique<Impl>(namespaceName, metadata);
            impl->unlocked_ = true;
            return {.instance = std::unique_ptr<SafeKeeping>(new SafeKeeping(std::move(impl))),
                    .recoveryKey = recoveryKey};
        } catch (...) {
            std::error_code ignored;
            std::filesystem::remove_all(nsPath, ignored);
            throw;
        }
    }

    static std::unique_ptr<SafeKeeping> open(std::string namespaceName, const UnlockOptions& options) {
        validateNamespaceOrSecretName(namespaceName, "namespace");
        const auto metaPath = metadataPath(namespaceName);
        if (!std::filesystem::exists(metaPath)) {
            return nullptr;
        }

        auto metadata = loadMetadata(metaPath);
        if (metadata.namespaceName != namespaceName) {
            throw std::runtime_error("namespace metadata mismatch");
        }

        auto result = std::unique_ptr<SafeKeeping>(new SafeKeeping(std::make_unique<Impl>(namespaceName, metadata)));
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
        return std::filesystem::exists(metadataPath(namespaceName));
    }

    static bool removeNamespace(std::string namespaceName) {
        validateNamespaceOrSecretName(namespaceName, "namespace");
        const auto nsPath = namespacePath(namespaceName);
        if (!std::filesystem::exists(metadataPath(namespaceName))) {
            return false;
        }

        std::error_code error;
        std::filesystem::remove_all(nsPath, error);
        return !error;
    }

    [[nodiscard]] const std::string& namespaceName() const noexcept {
        return namespaceName_;
    }

    [[nodiscard]] bool isUnlocked() const noexcept {
        return unlocked_;
    }

    bool unlockWithSystemVault() {
        if (unlocked_) {
            return true;
        }
        if (!metadata_.hasSystemVaultSlot) {
            fail(Error::UnlockUnavailable, "system vault unlock slot is not configured");
        }
        const auto path = vaultMaterialPath(namespaceName_);
        if (!std::filesystem::exists(path)) {
            fail(Error::VaultError, "failed to load namespace material from the system vault");
        }
        const auto material = readText(path);
        if (material.empty()) {
            fail(Error::UnlockFailed, "system vault material did not unlock the namespace");
        }
        unlocked_ = true;
        return true;
    }

    bool unlockWithPassphrase(std::string_view passphrase) {
        if (unlocked_) {
            return true;
        }
        if (!metadata_.hasPassphraseSlot || !metadata_.passphrase.has_value()) {
            fail(Error::UnlockUnavailable, "passphrase unlock slot is not configured");
        }
        if (*metadata_.passphrase != passphrase) {
            fail(Error::UnlockFailed, "passphrase did not unlock the namespace");
        }
        unlocked_ = true;
        return true;
    }

    bool unlockWithRecoveryKey(std::string_view recoveryKey) {
        if (unlocked_) {
            return true;
        }
        if (!metadata_.hasRecoveryKeySlot || !metadata_.recoveryKey.has_value()) {
            fail(Error::UnlockUnavailable, "recovery key unlock slot is not configured");
        }
        if (normalizeRecoveryKey(*metadata_.recoveryKey) != normalizeRecoveryKey(recoveryKey)) {
            fail(Error::UnlockFailed, "recovery key did not unlock the namespace");
        }
        unlocked_ = true;
        return true;
    }

    bool lock() {
        unlocked_ = false;
        return true;
    }

    bool storeSecret(std::string_view name,
                     std::span<const std::byte> secret,
                     std::optional<std::string_view> description = std::nullopt) {
        requireUnlocked();
        validateNamespaceOrSecretName(name, "secret name");
        validateSecretValue(secret);
        if (description.has_value()) {
            validateDescription(*description);
        }

        writeBytes(secretValuePath(namespaceName_, name), secret);
        if (description.has_value()) {
            writeText(secretDescriptionPath(namespaceName_, name), *description);
        } else {
            std::error_code ignored;
            std::filesystem::remove(secretDescriptionPath(namespaceName_, name), ignored);
        }
        return true;
    }

    std::optional<byte_vector> retrieveSecretBytes(std::string_view name) const {
        requireUnlocked();
        validateNamespaceOrSecretName(name, "secret name");
        const auto path = secretValuePath(namespaceName_, name);
        if (!std::filesystem::exists(path)) {
            fail(Error::NotFound, "secret was not found");
        }
        return readBytes(path);
    }

    bool removeSecret(std::string_view name) {
        requireUnlocked();
        validateNamespaceOrSecretName(name, "secret name");

        const auto valuePath = secretValuePath(namespaceName_, name);
        if (!std::filesystem::exists(valuePath)) {
            fail(Error::NotFound, "secret was not found");
        }

        std::error_code error;
        std::filesystem::remove(valuePath, error);
        if (error) {
            throw std::runtime_error("failed to remove secret");
        }
        std::filesystem::remove(secretDescriptionPath(namespaceName_, name), error);
        return true;
    }

    info_list_t listSecrets() const {
        requireUnlocked();
        info_list_t list;
        const auto dir = secretsPath(namespaceName_);
        if (!std::filesystem::exists(dir)) {
            return list;
        }

        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (!entry.is_regular_file() || entry.path().extension() != ".secret") {
                continue;
            }
            const auto name = entry.path().stem().string();
            std::string description;
            const auto descPath = secretDescriptionPath(namespaceName_, name);
            if (std::filesystem::exists(descPath)) {
                description = readText(descPath);
            }
            list.push_back({.name = name, .description = std::move(description)});
        }

        std::sort(list.begin(), list.end(), [](const Info& lhs, const Info& rhs) {
            return lhs.name < rhs.name;
        });
        return list;
    }

    [[nodiscard]] bool hasSystemVaultSlot() const {
        return metadata_.hasSystemVaultSlot;
    }

    [[nodiscard]] bool hasPassphraseSlot() const {
        return metadata_.hasPassphraseSlot;
    }

    [[nodiscard]] bool hasRecoverySlot() const {
        return metadata_.hasRecoveryKeySlot;
    }

    [[nodiscard]] std::vector<UnlockMethod> availableUnlockMethods() const {
        std::vector<UnlockMethod> methods;
        if (hasSystemVaultSlot()) {
            methods.push_back(UnlockMethod::SystemVault);
        }
        if (hasPassphraseSlot()) {
            methods.push_back(UnlockMethod::Passphrase);
        }
        if (hasRecoverySlot()) {
            methods.push_back(UnlockMethod::RecoveryKey);
        }
        return methods;
    }

    bool addSystemVaultSlot() {
        requireUnlocked();
        if (metadata_.hasSystemVaultSlot) {
            fail(Error::AlreadyExists, "system vault slot already exists");
        }
        metadata_.hasSystemVaultSlot = true;
        writeText(vaultMaterialPath(namespaceName_), randomHex(32));
        persistMetadata();
        return true;
    }

    bool addPassphrase(std::string_view passphrase) {
        requireUnlocked();
        if (metadata_.hasPassphraseSlot) {
            fail(Error::AlreadyExists, "passphrase slot already exists");
        }
        metadata_.hasPassphraseSlot = true;
        metadata_.passphrase = toString(passphrase);
        persistMetadata();
        return true;
    }

    bool changePassphrase(std::string_view newPassphrase) {
        requireUnlocked();
        if (!metadata_.hasPassphraseSlot || !metadata_.passphrase.has_value()) {
            fail(Error::NotFound, "passphrase slot does not exist");
        }
        metadata_.passphrase = toString(newPassphrase);
        persistMetadata();
        return true;
    }

    bool removePassphrase() {
        requireUnlocked();
        if (!metadata_.hasPassphraseSlot || !metadata_.passphrase.has_value()) {
            fail(Error::NotFound, "passphrase slot does not exist");
        }
        if (activeSlotCount() <= 1U) {
            fail(Error::InvalidArgument, "cannot remove the last unlock method");
        }
        metadata_.hasPassphraseSlot = false;
        metadata_.passphrase.reset();
        persistMetadata();
        return true;
    }

    std::optional<std::string> rotateRecoveryKey() {
        requireUnlocked();
        if (!metadata_.hasRecoveryKeySlot && activeSlotCount() == 0U) {
            fail(Error::InvalidArgument, "cannot rotate recovery key without an active unlock method");
        }
        metadata_.hasRecoveryKeySlot = true;
        metadata_.recoveryKey = generateRecoverySecret();
        persistMetadata();
        return metadata_.recoveryKey;
    }

    bool removeRecoveryKey() {
        requireUnlocked();
        if (!metadata_.hasRecoveryKeySlot || !metadata_.recoveryKey.has_value()) {
            fail(Error::NotFound, "recovery slot does not exist");
        }
        if (activeSlotCount() <= 1U) {
            fail(Error::InvalidArgument, "cannot remove the last unlock method");
        }
        metadata_.hasRecoveryKeySlot = false;
        metadata_.recoveryKey.reset();
        persistMetadata();
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
    void requireUnlocked() const {
        if (!unlocked_) {
            fail(Error::Locked, "namespace is locked");
        }
    }

    void persistMetadata() const {
        saveMetadata(metadataPath(namespaceName_), metadata_);
    }

    [[nodiscard]] std::size_t activeSlotCount() const {
        std::size_t count = 0;
        if (metadata_.hasSystemVaultSlot) {
            ++count;
        }
        if (metadata_.hasPassphraseSlot) {
            ++count;
        }
        if (metadata_.hasRecoveryKeySlot) {
            ++count;
        }
        return count;
    }

    std::string namespaceName_;
    Metadata metadata_;
    bool unlocked_ = false;
    mutable LatestError lastError_;
};

SafeKeeping::SafeKeeping(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

SafeKeeping::SafeKeeping(SafeKeeping&&) noexcept = default;
SafeKeeping& SafeKeeping::operator=(SafeKeeping&&) noexcept = default;
SafeKeeping::~SafeKeeping() = default;

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
    static const std::regex validName{R"(^[A-Za-z0-9_.-]{1,128}$)"};
    if (!std::regex_match(name.begin(), name.end(), validName)) {
        throw std::invalid_argument("linux vault root name must match [A-Za-z0-9_.-]{1,128}");
    }
}

std::string SafeKeeping::linuxVaultRootName() {
    return "android-file-backend";
}

void SafeKeeping::setLinuxVaultBackend(LinuxVaultBackend backend) {
    (void)backend;
}

SafeKeeping::LinuxVaultBackend SafeKeeping::linuxVaultBackend() {
    return LinuxVaultBackend::Auto;
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
