

#include "safekeeping/SafeKeeping.h"
#include "FileImplStorage.h"

#ifdef _WIN32
#include "WinSecretStorage.h"
#elif __APPLE__
#include "MacSecretStorage.h"
#else
#include "LibSecretImplStorage.h"
#endif

using namespace std;

namespace jgaa::safekeeping {

std::unique_ptr<SafeKeeping> SafeKeeping::create(std::string name, bool useFile) {
    if (!useFile) {
#ifdef _WIN32
        return std::make_unique<WinSecretStorage>(appName);
#elif __APPLE__
        return std::make_unique<MacSecretStorage>(appName);
#else // Linux
        return std::make_unique<LibSecretImpl>(std::move(name));
#endif
    throw runtime_error{"Unsupported platform"};
    }

    auto home = getenv("HOME");
    if (home == nullptr) {
        throw runtime_error{"HOME environment variable not set"};
    }

    auto path = filesystem::path{home} / ".local" / "share" / "safekeeping" / name;
    return std::make_unique<FileSafeKeeping>(std::move(name), path);
}

}
