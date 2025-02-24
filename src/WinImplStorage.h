#pragma once

#include "safekeeping/SafeKeeping.h"
#include <windows.h>
#include <wincred.h>
#include <vector>

#pragma comment(lib, "Advapi32.lib")

namespace jgaa::safekeeping {

class WinSafeKeeping : public SafeKeeping {
private:
    std::string appName;

public:
    explicit WinSafeKeeping(const std::string& name) : SafeKeeping(name) {}

    bool storeSecret(const std::string& key, const std::string& secret) override {
        CREDENTIAL cred = {0};
        auto target = getTargetName(key);
        cred.Type = CRED_TYPE_GENERIC;
        cred.TargetName = target.data();
        cred.CredentialBlobSize = static_cast<DWORD>(secret.size());
        cred.CredentialBlob = (LPBYTE)secret.c_str();
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

        return CredWrite(&cred, 0);
    }

    std::optional<std::string> retrieveSecret(const std::string& key) override {
        PCREDENTIAL cred = nullptr;
        auto target = getTargetName(key);
        if (CredRead(target.c_str(), CRED_TYPE_GENERIC, 0, &cred)) {
            std::string secret((char*)cred->CredentialBlob, cred->CredentialBlobSize);
            CredFree(cred);
            return secret;
        }
        return std::nullopt;
    }

    bool removeSecret(const std::string& key) override {
        auto target = getTargetName(key);
        removeDescription(key);
        return CredDelete(target.c_str(), CRED_TYPE_GENERIC, 0);
    }

private:
    std::string getTargetName(const std::string& key) {
		return std::format("{}_{}", name(), key);
	}

};

} // ns
