
#include <regex>
#include <fstream>
#include <ranges>
#include <algorithm>
#include <iostream>
#include <sstream>

// Include if the file exists
#if defined(__linux__) || defined(__unix__) || defined(__APPLE__)
#   include <sys/stat.h>
#endif

#include "safekeeping/SafeKeeping.h"
#include "FileImplStorage.h"

#ifdef _WIN32
#include <windows.h>
#include <ShlObj.h> // For SHGetFolderPath
#include <Aclapi.h> // For EXPLICIT_ACCESSA and related functions
#include "WinImplStorage.h"
#elif __APPLE__
#include "MacImplStorage.h"
#else
#include "LibSecretImplStorage.h"
#endif

using namespace ::std;
using namespace ::std::string_literals;

namespace jgaa::safekeeping {

namespace {

std::filesystem::path getHome() {
#ifdef _WIN32
    char home[MAX_PATH]{};
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, home) != S_OK) {
        throw std::runtime_error{ "Failed to get home directory" };
    }
    return home;
#else
    auto home = getenv("HOME");
    if (home == nullptr) {
        throw runtime_error{"HOME environment variable not set"};
    }
    return home;
#endif
}

std::filesystem::path getSafeKeepingPath(const std::string &name) {
    return getHome() / ".local" / "share" / "safekeeping" / name;
}

void preparePrivateDir() {
    auto path = getHome() / ".local" / "share" / "safekeeping";
    if (!std::filesystem::exists(path) && path.has_parent_path() && filesystem::exists(path.parent_path())) {
#ifdef _WIN32
        // Create the directory
        if (!CreateDirectoryA(path.string().c_str(), NULL)) {
            DWORD error = GetLastError();
            if (error != ERROR_ALREADY_EXISTS) {
                throw std::runtime_error{ "Failed to create directory " + path.string() + ". Error #" + std::to_string(error) };
            }
        }

        // RAII wrapper for LocalFree
        auto localFreeDeleter = [](void* ptr) { if (ptr) LocalFree(ptr); };
        std::unique_ptr<void, decltype(localFreeDeleter)> pSD(LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH), localFreeDeleter);
        if (!pSD) {
            throw std::runtime_error{ "Failed to allocate security descriptor" };
        }

        if (!InitializeSecurityDescriptor(pSD.get(), SECURITY_DESCRIPTOR_REVISION)) {
            throw std::runtime_error{ "Failed to initialize security descriptor" };
        }

        // Add a DACL to the security descriptor
        char current_user [] = "CURRENT_USER";
        EXPLICIT_ACCESSA ea;
        ZeroMemory(&ea, sizeof(EXPLICIT_ACCESSA));
        ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
        ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
        ea.Trustee.ptstrName = current_user;

        PACL pACL = NULL;
        DWORD dwRes = SetEntriesInAclA(1, &ea, NULL, &pACL);
        std::unique_ptr<void, decltype(localFreeDeleter)> pACLPtr(pACL, localFreeDeleter);
        if (dwRes != ERROR_SUCCESS) {
            throw std::runtime_error{ "Failed to set entries in ACL. Error #" + std::to_string(dwRes) };
        }

        if (!SetSecurityDescriptorDacl(pSD.get(), TRUE, pACL, FALSE)) {
            throw std::runtime_error{ "Failed to set security descriptor DACL" };
        }

        if (!SetFileSecurityA(path.string().c_str(), DACL_SECURITY_INFORMATION, pSD.get())) {
            throw std::runtime_error{ "Failed to set file security" };
        }

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
    : name_{}, ns_name_{"com.jgaa.safekeeping."s + name}
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
        return std::make_unique<WinSafeKeeping>(name);
#elif __APPLE__
        return std::make_unique<MacSafeKeeping>(std::move(name));
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

        if (std::getline(ss, name, '|')) {
            // If no description exists after '|', assign an empty string
            std::getline(ss, description);
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
