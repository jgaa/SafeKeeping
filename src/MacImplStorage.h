#pragma once

#include "safekeeping/SafeKeeping.h"
#include <Security/Security.h>
#include <vector>

namespace jgaa::safekeeping {

class MacSafeKeeping : public SafeKeeping {
private:
    std::string serviceName;

public:
    explicit MacSafeKeeping(const std::string& name) : serviceName(name) {}

    bool storeSecret(const std::string& key, const std::string& secret) override {
        SecKeychainItemRef item = nullptr;

        // First, try to update an existing item
        OSStatus status = SecKeychainFindGenericPassword(
            nullptr,  // Default keychain
            serviceName.size(), serviceName.c_str(),
            key.size(), key.c_str(),
            nullptr, nullptr, &item
        );

        if (status == errSecSuccess) {
            return SecKeychainItemModifyAttributesAndData(
                item, nullptr, secret.size(), secret.c_str()) == errSecSuccess;
        }

        // If not found, create a new one
        return SecKeychainAddGenericPassword(
            nullptr, serviceName.size(), serviceName.c_str(),
            key.size(), key.c_str(),
            secret.size(), secret.c_str(),
            nullptr
        ) == errSecSuccess;
    }

    std::optional<std::string> retrieveSecret(const std::string& key) override {
        void* data = nullptr;
        UInt32 length = 0;

        OSStatus status = SecKeychainFindGenericPassword(
            nullptr,
            serviceName.size(), serviceName.c_str(),
            key.size(), key.c_str(),
            &length, &data,
            nullptr
        );

        if (status != errSecSuccess) return std::nullopt;

        std::string secret((char*)data, length);
        SecKeychainItemFreeContent(nullptr, data);
        return secret;
    }

    bool removeSecret(const std::string& key) override {
        SecKeychainItemRef item = nullptr;
        OSStatus status = SecKeychainFindGenericPassword(
            nullptr, serviceName.size(), serviceName.c_str(),
            key.size(), key.c_str(),
            nullptr, nullptr, &item
        );

        if (status == errSecSuccess && item) {
            return SecKeychainItemDelete(item) == errSecSuccess;
        }
        return false;
    }

    std::vector<std::string> listSecrets() override {
        return {"Listing stored secrets is not supported by macOS Keychain"};
    }
};

}
