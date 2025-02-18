
#include <regex>
#include <fstream>
#include <ranges>
#include <algorithm>
#include <iostream>

// Include if the file exists
#if defined(__linux__) || defined(__unix__) || defined(__APPLE__)
#   include <sys/stat.h>
#endif

#include "safekeeping/SafeKeeping.h"
#include "FileImplStorage.h"

#ifdef _WIN32
#include "WinSecretStorage.h"
#elif __APPLE__
#include "MacSecretStorage.h"
#else
#include "LibSecretImplStorage.h"
#endif

using namespace ::std;
using namespace ::std::string_literals;

namespace jgaa::safekeeping {

namespace {

std::filesystem::path getHome() {
    auto home = getenv("HOME");
    if (home == nullptr) {
        throw runtime_error{"HOME environment variable not set"};
    }
    return home;
}

std::filesystem::path getSafeKeepingPath(const std::string &name) {
    return getHome() / ".local" / "share" / "safekeeping" / name;
}

void preparePrivateDir() {
    auto path = getHome() / ".local" / "share" / "safekeeping";
    if (!std::filesystem::exists(path) && path.has_parent_path() && filesystem::exists(path.parent_path())) {
#ifdef WIN32
        static_assert(false, "Implement me");
#else
        // Create using POSIX calls. Set permissions to user only
        // This set the permissions when the directory is created, preventing
        // a potential attack where a malicious user tries to gain access to the
        // directory before the permissions are set.
        if (mkdir(path.c_str(), 0700) == -1) {
            auto err = errno;
            throw runtime_error{"Failed to create directory {}"s + path.string()
                                + ". Error #" + to_string(err)};
        }
#endif
    }
}

void validateKey(string_view key) {
    static const regex validKey{R"(^[a-zA-Z0-9_-]+$)"};

    cout << "Validating key: '" << key << "'" << endl;

    if (!regex_match(key.begin(), key.end(), validKey)) {
        throw invalid_argument{"Invalid key. Must consist of Latin letters, digits, hyphen and underscore"};
    }
}

void validateDescription(string_view descr) {
    if (descr.size() > 1024) {
        throw invalid_argument{"Description too long"};
    }

    if (descr.find('\n') != string::npos) {
        throw invalid_argument{"Description cannot contain newline"};
    }

    if (descr.find('\r') != string::npos) {
        throw invalid_argument{"Description cannot contain carriage return"};
    }

    if (descr.find('\0') != string::npos) {
        throw invalid_argument{"Description cannot contain null character"};
    }

    if (descr.find('/') != string::npos) {
        throw invalid_argument{"Description cannot contain '/'"};
    }
}

} // anon ns

SafeKeeping::SafeKeeping(std::string name)
    : name_{std::move(name)}
    , info_path_{getSafeKeepingPath(name_) / "info.dat"}
{

    const auto path = getSafeKeepingPath(name_);
    preparePrivateDir();

    if (!std::filesystem::exists(path)) {
        std::filesystem::create_directories(path);

        std::filesystem::permissions(
            path,
            std::filesystem::perms::owner_read |
                std::filesystem::perms::owner_write |
                std::filesystem::perms::owner_exec,
            std::filesystem::perm_options::replace);
    }

    loadDescriptions();
}

std::unique_ptr<SafeKeeping> SafeKeeping::create(std::string name, Vault vault) {
    if (vault == Vault::DEFAULT_SECURE_STORAGE) {
#ifdef _WIN32
        return std::make_unique<WinSecretStorage>(appName);
#elif __APPLE__
        return std::make_unique<MacSecretStorage>(appName);
#else // Linux
        return std::make_unique<LibSecretImpl>(std::move(name));
#endif
    throw runtime_error{"Unsupported platform"};
    }

    const auto path = getSafeKeepingPath(name) / "storage";;
    return std::make_unique<FileSafeKeeping>(std::move(name), path);
}

bool SafeKeeping::storeSecretWithDescription(const std::string &key,
                                             const std::string& secret,
                                             const std::string& description)
{
    validateKey(key);
    validateDescription(description);

    if (storeSecret(key, secret)) {
        addDescription(key, description);
        return true;
    }

    return false;
}

SafeKeeping::info_list_t SafeKeeping::listSecrets() const
{
    return list_;
}

void SafeKeeping::storeDescriptions()
{
    if (list_.empty() && std::filesystem::exists(info_path_)) {
        std::filesystem::remove(info_path_);
        return;
    };

    const auto parent_path = info_path_.parent_path();
    if (!std::filesystem::exists(parent_path)) {
        std::filesystem::create_directories(info_path_.parent_path());
        std::filesystem::permissions(
            parent_path,
            std::filesystem::perms::owner_read |
                std::filesystem::perms::owner_write |
                std::filesystem::perms::owner_exec,
            std::filesystem::perm_options::replace);
    }

    std::ofstream file(info_path_, std::ios::out | std::ios::trunc);
    if (!file) {
        throw std::runtime_error("Failed to open file for writing.");
    }

    std::filesystem::permissions(
        info_path_,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,  // Only user read/write
        std::filesystem::perm_options::replace);

    ranges::sort(list_, {}, &Info::name);

    for (const auto& info : list_) {
        file << info.name << "|" << info.description << "\n";
    }
}

bool SafeKeeping::loadDescriptions()
{
    list_.clear();

    // Check if the info_path_ file exists
    if (!std::filesystem::exists(info_path_)) {
        return false;
    }

    std::ifstream file(info_path_, std::ios::in);
    if (!file) {
        throw std::runtime_error("Failed to open file for reading.");
    }

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream ss(line);
        std::string name, description;

        if (std::getline(ss, name, '|') && std::getline(ss, description)) {
            list_.push_back({name, description});
        }
    }

    return true;
}

void SafeKeeping::addDescription(const std::string &key, const std::string& description)
{
    loadDescriptions();

    // Replace it it exists
    for (auto& info : list_) {
        if (info.name == key) {
            info.description = description;
            storeDescriptions();
            return;
        }
    }

    list_.emplace_back(Info{key, description});
    storeDescriptions();
}

void SafeKeeping::removeDescription(const std::string &key)
{
    loadDescriptions();
    list_.erase(std::remove_if(list_.begin(), list_.end(),
                               [key](const Info& info) { return info.name == key; }),
                list_.end());
    storeDescriptions();
}

} // ns
