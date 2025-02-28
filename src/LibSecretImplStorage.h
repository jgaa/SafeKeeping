#pragma once

#include "safekeeping/SafeKeeping.h"
#include <libsecret/secret.h>
#include <string>
#include <iostream>

namespace jgaa::safekeeping {

class LibSecretImpl : public SafeKeeping {
public:
    explicit LibSecretImpl(std::string name)
        : SafeKeeping(std::move(name)) {}

    bool storeSecret(const std::string& key, const std::string& secret) override {
        std::string namespacedKey = nsName() + "/" + key;

        SecretSchema schema = {
            "SafeKeepingSchema",
            SECRET_SCHEMA_DONT_MATCH_NAME,
            {
                {"key", SECRET_SCHEMA_ATTRIBUTE_STRING},
                {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING}
            }
        };

        return secret_password_store_sync(
            &schema,
            SECRET_COLLECTION_DEFAULT,
            namespacedKey.c_str(),
            secret.c_str(),
            nullptr,  // GCancellable
            nullptr,  // GError**
            "key", namespacedKey.c_str(),
            nullptr
            );
    }


    std::optional<std::string> retrieveSecret(const std::string& key) override {
        std::string namespacedKey = nsName() + "/" + key;

        SecretSchema schema = {
            "SafeKeepingSchema",
            SECRET_SCHEMA_DONT_MATCH_NAME,
            {
                {"key", SECRET_SCHEMA_ATTRIBUTE_STRING},
                {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING}
            }
        };

        gchar* secret = secret_password_lookup_sync(
            &schema,
            nullptr,  // GCancellable
            nullptr,  // GError**
            "key", namespacedKey.c_str(),
            nullptr
            );

        if (!secret) return std::nullopt;

        std::string result(secret);
        secret_password_free(secret);
        return result;
    }

    bool removeSecret(const std::string& key) override {
        std::string namespacedKey = nsName() + "/" + key;

        SecretSchema schema = {
            "SafeKeepingSchema",
            SECRET_SCHEMA_DONT_MATCH_NAME,
            {
                {"key", SECRET_SCHEMA_ATTRIBUTE_STRING},
                {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING}
            }
        };

        removeDescription(key);
        return secret_password_clear_sync(
            &schema,
            nullptr,  // GCancellable
            nullptr,  // GError**
            "key", namespacedKey.c_str(),
            nullptr
            );
    }

};

} // namespace jgaa::safekeeping
