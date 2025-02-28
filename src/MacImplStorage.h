#pragma once

#include "safekeeping/SafeKeeping.h"
#include <Security/Security.h>
#include <vector>

namespace jgaa::safekeeping {

class MacSafeKeeping : public SafeKeeping {
public:
    explicit MacSafeKeeping(const std::string& name)
        : SafeKeeping(name) {}

    bool storeSecret(const std::string& key, const std::string& secret) override {
        CFStringRef service = CFStringCreateWithCString(nullptr, nsName().c_str(), kCFStringEncodingUTF8);
        CFStringRef account = CFStringCreateWithCString(nullptr, key.c_str(), kCFStringEncodingUTF8);
        CFDataRef secretData = CFDataCreate(nullptr, reinterpret_cast<const UInt8*>(secret.c_str()), secret.size());

        if (!service || !account || !secretData) {
            printf("Error: CFStringRef or CFDataRef creation failed!\n");
            if (service) CFRelease(service);
            if (account) CFRelease(account);
            if (secretData) CFRelease(secretData);
            return false;
        }

        // Query to check if the key exists
        CFMutableDictionaryRef query = CFDictionaryCreateMutable(nullptr, 0,
                                                                 &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(query, kSecAttrService, service);
        CFDictionarySetValue(query, kSecAttrAccount, account);

        OSStatus status = SecItemCopyMatching(query, nullptr);

        if (status == errSecSuccess) {
            // Update existing entry: Use a new dictionary
            CFMutableDictionaryRef updateQuery = CFDictionaryCreateMutable(nullptr, 0,
                                                                           &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            CFDictionarySetValue(updateQuery, kSecValueData, secretData);

            status = SecItemUpdate(query, updateQuery);
            CFRelease(updateQuery);
        } else {
            // Add new entry
            CFDictionarySetValue(query, kSecValueData, secretData);
            status = SecItemAdd(query, nullptr);
        }

        CFRelease(query);
        CFRelease(service);
        CFRelease(account);
        CFRelease(secretData);

        // if (status != errSecSuccess) {
        //     printf("SecItemAdd failed with error: %d\n", status);
        // }

        return status == errSecSuccess;
    }



    std::optional<std::string> retrieveSecret(const std::string& key) override {
        CFStringRef service = CFStringCreateWithCString(nullptr, nsName().c_str(), kCFStringEncodingUTF8);
        CFStringRef account = CFStringCreateWithCString(nullptr, key.c_str(), kCFStringEncodingUTF8);

        CFDictionaryRef query = CFDictionaryCreate(nullptr,
                                                   (const void*[]) { kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit },
                                                   (const void*[]) { kSecClassGenericPassword, service, account, kCFBooleanTrue, kSecMatchLimitOne },
                                                   5, nullptr, nullptr);

        CFDataRef secretData = nullptr;
        OSStatus status = SecItemCopyMatching(query, (CFTypeRef*)&secretData);
        CFRelease(query);
        CFRelease(service);
        CFRelease(account);

        if (status != errSecSuccess || secretData == nullptr) {
            return std::nullopt;
        }

        std::string secret(reinterpret_cast<const char*>(CFDataGetBytePtr(secretData)), CFDataGetLength(secretData));
        CFRelease(secretData);
        return secret;
    }

    bool removeSecret(const std::string& key) override {
        CFStringRef service = CFStringCreateWithCString(nullptr, nsName().c_str(), kCFStringEncodingUTF8);
        CFStringRef account = CFStringCreateWithCString(nullptr, key.c_str(), kCFStringEncodingUTF8);

        removeDescription(key);
        CFDictionaryRef query = CFDictionaryCreate(nullptr,
                                                   (const void*[]) { kSecClass, kSecAttrService, kSecAttrAccount },
                                                   (const void*[]) { kSecClassGenericPassword, service, account },
                                                   3, nullptr, nullptr);

        OSStatus status = SecItemDelete(query);
        CFRelease(query);
        CFRelease(service);
        CFRelease(account);
        return status == errSecSuccess;
    }
};

}
