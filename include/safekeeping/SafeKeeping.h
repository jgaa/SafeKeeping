#pragma once

#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <optional>
#include <filesystem>

namespace jgaa::safekeeping {

/*! A class to store and retrieve secrets in a secure manner.
 *
 */
class SafeKeeping {
public:
    enum class Vault {
        INSECURE_FILE,
        DEFAULT_SECURE_STORAGE,
    };

    struct Info {
        std::string name;
        std::string description;
    };

    using info_list_t = std::vector<Info>;

    SafeKeeping(std::string name);

    virtual ~SafeKeeping() = default;

    /*! Stores a secret in a secure manner.
     * \param key The key to store the secret under
     * \param secret The secret to store
     * \return True if the secret was stored successfully
     */
    virtual bool storeSecret(const std::string& key, const std::string& secret) = 0;

    /*! Retrieves a secret from storage.
     * \param key The key to retrieve the secret for
     * \return The secret, if it exists
     */
    virtual std::optional<std::string> retrieveSecret(const std::string& key) = 0;

    /*! Removes a secret from storage.
     * \param key The key to remove the secret for
     * \return True if the secret was removed successfully
     */
    virtual bool removeSecret(const std::string& key) = 0;

    /*! Creates a new SafeKeeping object.
     * \param nameSpace The namespace of the SafeKeeping object
     * \param vault Specifies the storage type.
     *        If `Vault::DEFAULT_SECURE_STORAGE`, the platform's secure storage is used,
     *        for example libsecret on Linux.
     *        If `Vault::INSECURE_FILE`, the secret is stored in plain text in a file.
     * \return A unique pointer to the created SafeKeeping object
     */
    static std::unique_ptr<SafeKeeping> create(std::string nameSpace, Vault vault = Vault::DEFAULT_SECURE_STORAGE);

    const std::string& name() const noexcept {
        return name_;
    }

    /*! Stores the secret and associates a description with it.
     * \param key The key to store the secret under
     * \param secret The secret to store
     * \param description A description of the secret
     * \return True if the secret was stored successfully
     */
    bool storeSecretWithDescription(const std::string& key,
                                    const std::string& secret,
                                    const std::string& description);

    /*! List keys with their description.
     *
     * Only lists secrets created using `storeSecretWithDescription()`.
     * Does not return secrets stored via `storeSecret()`.
     *
     */
    info_list_t listSecrets() const;

protected:
    void addDescription(const std::string& key, const std::string& description);
    void removeDescription(const std::string& key);

private:
    void storeDescriptions();
    bool loadDescriptions();

    std::string name_;
    std::filesystem::path info_path_;
    info_list_t list_;
};


} // namespace jgaa::safekeeping
