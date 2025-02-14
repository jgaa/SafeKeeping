#pragma once

#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <optional>

namespace jgaa::safekeeping {


class SafeKeeping {
public:
    SafeKeeping(std::string name)
        : name_{std::move(name)} {};

    virtual ~SafeKeeping() = default;

    // Store a secret with a given key
    virtual bool storeSecret(const std::string& key, const std::string& secret) = 0;

    // Retrieve a secret based on a key
    virtual std::optional<std::string> retrieveSecret(const std::string& key) = 0;

    // Remove a secret from storage
    virtual bool removeSecret(const std::string& key) = 0;

    static std::unique_ptr<SafeKeeping> create(std::string name, bool useFile = false);

    const std::string& name() const noexcept {
        return name_;
    }

private:
    std::string name_;
};


} // ns
