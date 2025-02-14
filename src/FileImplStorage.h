#pragma once

#include "safekeeping/SafeKeeping.h"
#include <fstream>
#include <filesystem>

#include "safekeeping/SafeKeeping.h"

namespace jgaa::safekeeping {

class FileSafeKeeping : public SafeKeeping {
public:
    explicit FileSafeKeeping(std::string name,
                             const std::filesystem::path& path)
        : SafeKeeping(std::move(name))
        , path_{path} {
        std::filesystem::create_directories(path_);
    }

    bool storeSecret(const std::string& key, const std::string& secret) override {
        std::ofstream out(path_ /  key, std::ios::out | std::ios::trunc | std::ios::binary);
        if (!out.is_open()) return false;
        out.write(secret.data(), secret.size());
        return true;
    }

    std::optional<std::string> retrieveSecret(const std::string& key) override {
        auto path = path_ / key;
        std::ifstream in(path, std::ios::binary);
        if (!in.is_open()) return std::nullopt;
        std::string secret;
        const auto len = std::filesystem::file_size(path);
        secret.resize(len);
        in.read(secret.data(), len);
        return secret;
    }

    bool removeSecret(const std::string& key) override {
        return std::filesystem::remove(path_ / key);
    }

    const std::filesystem::path& path() const noexcept {
        return path_;
    }

    std::vector<std::string> listSecrets() {
        std::vector<std::string> secrets;
        for (const auto& entry : std::filesystem::directory_iterator(path_)) {
            secrets.push_back(entry.path().filename().string());
        }
        return secrets;
    }

private:
    std::filesystem::path path_;

};

} // ns
