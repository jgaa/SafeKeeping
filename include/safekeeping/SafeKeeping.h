#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace jgaa::safekeeping {

/**
 * @brief Secure per-namespace secret storage with application-layer encryption.
 *
 * A `SafeKeeping` instance manages one namespace backed by an encrypted SQLite
 * database plus one or more unlock methods such as the system vault,
 * passphrase, or recovery key.
 *
 * Instance methods follow a `bool`/value-returning style. On failure they
 * return `false` or an empty optional and record details in latestError().
 */
class SafeKeeping {
public:
    /** @brief Owning pointer to a `SafeKeeping` instance. */
    using ptr_t = std::unique_ptr<SafeKeeping>;

    /** @brief Error category reported by latestError(). */
    enum class Error {
        /** No error is recorded. */
        None,
        /** Caller input is invalid. */
        InvalidArgument,
        /** The namespace is locked. */
        Locked,
        /** The supplied secret exceeds the configured size limit. */
        TooLarge,
        /** The requested object was not found. */
        NotFound,
        /** The requested object already exists. */
        AlreadyExists,
        /** The requested unlock path is not configured. */
        UnlockUnavailable,
        /** Unlock credentials were accepted syntactically but did not unlock the namespace. */
        UnlockFailed,
        /** An interaction with the platform vault failed. */
        VaultError,
        /** A storage, crypto, or persistence operation failed. */
        StorageError,
        /** Stored data appears corrupted or inconsistent. */
        DataCorrupted,
        /** An unexpected internal failure occurred. */
        InternalError,
    };

    /** @brief Details about the most recent instance-level failure. */
    struct LatestError {
        /** Error category for the last failure. */
        Error error = Error::None;
        /** Human-readable description of the last failure. */
        std::string message;
    };

    /** @brief Metadata for a stored secret. */
    struct Info {
        /** Secret name. */
        std::string name;
        /** Optional secret description. */
        std::string description;
    };

    /** @brief Options for createNew() and openOrCreate() when creation is required. */
    struct CreateOptions {
        /** Create a system-vault-backed unlock slot when available. */
        bool createSystemVaultSlot = true;
        /** Optional passphrase to add as an unlock method. */
        std::optional<std::string> passphrase;
        /** Generate and return a recovery key unlock method. */
        bool createRecoveryKey = false;
        /** Require that at least one unlock method is configured. */
        bool requireAtLeastOneUnlockMethod = true;
    };

    /** @brief Options for opening and attempting to unlock an existing namespace. */
    struct UnlockOptions {
        /** Attempt system-vault unlock before other provided credentials. */
        bool trySystemVaultFirst = true;
        /** Optional passphrase to try if vault unlock does not succeed. */
        std::optional<std::string> passphrase;
        /** Optional recovery key to try if earlier methods do not succeed. */
        std::optional<std::string> recoveryKey;
    };

    /** @brief Result returned when a new namespace is created. */
    struct CreateResult {
        /** The created and unlocked instance. */
        ptr_t instance;
        /** The generated recovery key, when requested during creation. */
        std::optional<std::string> recoveryKey;
    };

    /** @brief Supported unlock methods for a namespace. */
    enum class UnlockMethod {
        /** Unlock using the platform system vault. */
        SystemVault,
        /** Unlock using a passphrase-derived key. */
        Passphrase,
        /** Unlock using a generated recovery key. */
        RecoveryKey,
    };

    /** @brief List of secret metadata entries. */
    using info_list_t = std::vector<Info>;

    SafeKeeping(const SafeKeeping&) = delete;
    SafeKeeping& operator=(const SafeKeeping&) = delete;
    /** @brief Move-construct a `SafeKeeping` instance. */
    SafeKeeping(SafeKeeping&&) noexcept;
    /** @brief Move-assign a `SafeKeeping` instance. */
    SafeKeeping& operator=(SafeKeeping&&) noexcept;
    /** @brief Destroy the instance and clear in-memory key material. */
    ~SafeKeeping();

    /**
     * @brief Create a new namespace using default creation options.
     * @param namespaceName Namespace identifier.
     * @return Newly created unlocked instance and optional recovery key.
     * @throws std::exception on creation failure.
     */
    static CreateResult createNew(std::string namespaceName);
    /**
     * @brief Create a new namespace with explicit creation options.
     * @param namespaceName Namespace identifier.
     * @param options Creation options.
     * @return Newly created unlocked instance and optional recovery key.
     * @throws std::exception on creation failure.
     */
    static CreateResult createNew(std::string namespaceName, CreateOptions options);
    /**
     * @brief Open an existing namespace without explicit unlock options.
     * @param namespaceName Namespace identifier.
     * @return Opened instance, or `nullptr` if the namespace does not exist.
     * @throws std::exception on open or schema failure.
     */
    static ptr_t open(std::string namespaceName);
    /**
     * @brief Open an existing namespace and optionally try provided unlock credentials.
     * @param namespaceName Namespace identifier.
     * @param options Unlock attempts to perform while opening.
     * @return Opened instance, or `nullptr` if the namespace does not exist.
     * @throws std::exception on open or schema failure.
     */
    static ptr_t open(std::string namespaceName, UnlockOptions options);
    /**
     * @brief Open an existing namespace or create it with default options.
     * @param namespaceName Namespace identifier.
     * @return Opened or newly created instance.
     * @throws std::exception on open or creation failure.
     */
    static ptr_t openOrCreate(std::string namespaceName);
    /**
     * @brief Open an existing namespace or create it with explicit options.
     * @param namespaceName Namespace identifier.
     * @param options Creation options used only when the namespace does not exist.
     * @return Opened or newly created instance.
     * @throws std::exception on open or creation failure.
     */
    static ptr_t openOrCreate(std::string namespaceName, CreateOptions options);
    /**
     * @brief Set the Linux system-vault root name used for libsecret entries.
     *
     * On Linux desktops using libsecret, this becomes the service-name prefix
     * used for stored system-vault items. The default is
     * `com.jgaa.SafeKeeping`.
     *
     * Set this during application startup before creating or opening
     * namespaces if you need an application-specific root.
     *
     * @param name Non-empty root name.
     * @throws std::exception on invalid names.
     */
    static void setLinuxVaultRootName(std::string name);
    /**
     * @brief Get the configured Linux system-vault root name.
     * @return The current Linux vault root name.
     */
    [[nodiscard]] static std::string linuxVaultRootName();
    /**
     * @brief Check whether a namespace database exists.
     * @param namespaceName Namespace identifier.
     * @return `true` if the namespace exists.
     */
    static bool exists(std::string_view namespaceName);
    /**
     * @brief Remove a namespace database and any stored vault material.
     * @param namespaceName Namespace identifier.
     * @return `true` if the namespace existed and removal succeeded.
     * @throws std::exception on invalid namespace names.
     */
    static bool removeNamespace(std::string namespaceName);

    /** @brief Get the namespace name for this instance. */
    [[nodiscard]] const std::string& namespaceName() const noexcept;
    /** @brief Check whether the namespace is currently unlocked. */
    [[nodiscard]] bool isUnlocked() const noexcept;

    /**
     * @brief Attempt to unlock using the configured system vault slot.
     * @return `true` on success, otherwise `false` and latestError() is updated.
     */
    bool unlockWithSystemVault();
    /**
     * @brief Attempt to unlock using a passphrase.
     * @param passphrase Passphrase to try.
     * @return `true` on success, otherwise `false` and latestError() is updated.
     */
    bool unlockWithPassphrase(std::string_view passphrase);
    /**
     * @brief Attempt to unlock using a recovery key.
     * @param recoveryKey Recovery key to try.
     * @return `true` on success, otherwise `false` and latestError() is updated.
     */
    bool unlockWithRecoveryKey(std::string_view recoveryKey);
    /**
     * @brief Lock the namespace and clear in-memory key material.
     * @return `true` on success.
     */
    bool lock();

    /**
     * @brief Store or replace a text secret.
     * @param name Secret name.
     * @param secret Secret bytes carried as a string view.
     * @return `true` on success, otherwise `false` and latestError() is updated.
     */
    bool storeSecret(std::string_view name, std::string_view secret);
    /**
     * @brief Store or replace a binary secret.
     * @param name Secret name.
     * @param secret Secret bytes.
     * @return `true` on success, otherwise `false` and latestError() is updated.
     */
    bool storeSecret(std::string_view name, std::span<const std::byte> secret);
    /**
     * @brief Store or replace a text secret with a description.
     * @param name Secret name.
     * @param secret Secret bytes carried as a string view.
     * @param description Human-readable description.
     * @return `true` on success, otherwise `false` and latestError() is updated.
     */
    bool storeSecretWithDescription(std::string_view name,
                                    std::string_view secret,
                                    std::string_view description);
    /**
     * @brief Store or replace a binary secret with a description.
     * @param name Secret name.
     * @param secret Secret bytes.
     * @param description Human-readable description.
     * @return `true` on success, otherwise `false` and latestError() is updated.
     */
    bool storeSecretWithDescription(std::string_view name,
                                    std::span<const std::byte> secret,
                                    std::string_view description);
    /**
     * @brief Retrieve a secret as a string.
     * @param name Secret name.
     * @return Secret value on success, otherwise an empty optional.
     *
     * On failure or if the secret does not exist, latestError() is updated.
     */
    std::optional<std::string> retrieveSecret(std::string_view name) const;
    /**
     * @brief Retrieve a secret as raw bytes.
     * @param name Secret name.
     * @return Secret value on success, otherwise an empty optional.
     *
     * On failure or if the secret does not exist, latestError() is updated.
     */
    std::optional<std::vector<std::byte>> retrieveSecretBytes(std::string_view name) const;
    /**
     * @brief Remove a stored secret.
     * @param name Secret name.
     * @return `true` on success, otherwise `false` and latestError() is updated.
     */
    bool removeSecret(std::string_view name);
    /**
     * @brief List all stored secret names and descriptions.
     * @return Sorted list of secret metadata, or an empty list on failure.
     *
     * On failure latestError() is updated.
     */
    info_list_t listSecrets() const;
    /**
     * @brief Get the most recent instance-level error.
     * @return Error category and message for the last failed operation.
     */
    [[nodiscard]] LatestError latestError() const;

    /** @brief Check whether a system vault slot exists. */
    [[nodiscard]] bool hasSystemVaultSlot() const;
    /** @brief Check whether a passphrase slot exists. */
    [[nodiscard]] bool hasPassphraseSlot() const;
    /** @brief Check whether a recovery key slot exists. */
    [[nodiscard]] bool hasRecoverySlot() const;
    /** @brief Enumerate active unlock methods for this namespace. */
    [[nodiscard]] std::vector<UnlockMethod> availableUnlockMethods() const;

    /**
     * @brief Add a system vault unlock slot.
     * @return `true` on success, otherwise `false` and latestError() is updated.
     */
    bool addSystemVaultSlot();
    /**
     * @brief Add a passphrase unlock slot.
     * @param passphrase Passphrase to add.
     * @return `true` on success, otherwise `false` and latestError() is updated.
     */
    bool addPassphrase(std::string_view passphrase);
    /**
     * @brief Replace the active passphrase unlock slot.
     * @param newPassphrase New passphrase to install.
     * @return `true` on success, otherwise `false` and latestError() is updated.
     */
    bool changePassphrase(std::string_view newPassphrase);
    /**
     * @brief Remove the active passphrase unlock slot.
     * @return `true` on success, otherwise `false` and latestError() is updated.
     */
    bool removePassphrase();
    /**
     * @brief Rotate the recovery key and return the new value.
     * @return New recovery key on success, otherwise an empty optional.
     *
     * On failure latestError() is updated.
     */
    std::optional<std::string> rotateRecoveryKey();
    /**
     * @brief Remove the active recovery key unlock slot.
     * @return `true` on success, otherwise `false` and latestError() is updated.
     */
    bool removeRecoveryKey();

private:
    class Impl;

    explicit SafeKeeping(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;
};

} // namespace jgaa::safekeeping
