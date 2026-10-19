#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#include <sys/wait.h>
#endif

#include <sqlite3.h>

#include "safekeeping/SafeKeeping.h"

#ifdef SAFEKEEPING_WRAP_SQLITE_STEP
namespace {
std::string corruptWalletRoot;
std::optional<std::string> corruptWalletRead;
}
extern "C" int __real_sqlite3_step(sqlite3_stmt*);
extern "C" int __wrap_sqlite3_step(sqlite3_stmt* stmt) {
    const int status = __real_sqlite3_step(stmt);
    const char* sql = sqlite3_sql(stmt);
    if (status == SQLITE_DONE && !corruptWalletRoot.empty() && sql &&
        std::string_view(sql).find("INSERT INTO key_slots") != std::string_view::npos) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(corruptWalletRoot)) {
            if (entry.is_regular_file() && entry.path().extension() == ".txt") {
                if (corruptWalletRead) {
                    std::ofstream out(entry.path(), std::ios::trunc);
                    out << *corruptWalletRead;
                } else {
                    std::filesystem::remove(entry.path());
                }
            }
        }
    }
    return status;
}
#endif

namespace fs = std::filesystem;
using jgaa::safekeeping::SafeKeeping;

namespace {

std::string uniqueName(std::string_view prefix) {
    return std::string(prefix) + "_" + std::to_string(::getpid()) + "_" +
        std::to_string(std::rand());
}

std::optional<std::string> envString(const char* name) {
    if (const char* value = std::getenv(name); value != nullptr && *value != '\0') {
        return std::string(value);
    }
    return std::nullopt;
}

bool envFlagEnabled(const char* name) {
    const auto value = envString(name);
    return value == std::optional<std::string>{"1"} ||
        value == std::optional<std::string>{"true"} ||
        value == std::optional<std::string>{"TRUE"};
}

void setEnvVar(const char* name, const fs::path& value) {
    setenv(name, value.string().c_str(), 1);
}

void setEnvVar(const char* name, const char* value) {
    setenv(name, value, 1);
}

void unsetEnvVar(const char* name) {
    unsetenv(name);
}

fs::path namespaceDbPath(const fs::path& root, std::string_view name) {
    return root / name / "vault.db";
}

void execSql(const fs::path& dbPath, const char* sql) {
    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open_v2(dbPath.string().c_str(), &db, SQLITE_OPEN_READWRITE, nullptr), SQLITE_OK);
    char* error = nullptr;
    ASSERT_EQ(sqlite3_exec(db, sql, nullptr, nullptr, &error), SQLITE_OK) << (error ? error : "sqlite error");
    sqlite3_free(error);
    sqlite3_close(db);
}

std::optional<std::string> querySingleText(const fs::path& dbPath, const char* sql) {
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(dbPath.string().c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return std::nullopt;
    }

    std::optional<std::string> value;
    if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
        const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        value = text != nullptr ? std::optional<std::string>(text) : std::nullopt;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return value;
}

} // namespace

class SafeKeepingRebootTest : public ::testing::Test {
protected:
    void SetUp() override {
        root_ = fs::temp_directory_path() / uniqueName("safekeeping-reboot");
        vaultRoot_ = root_ / "fake-vault";
        fs::create_directories(root_);
        SafeKeeping::setLinuxVaultRootName("com.jgaa.SafeKeeping");
        SafeKeeping::setLinuxVaultBackend(SafeKeeping::LinuxVaultBackend::Auto);
        setEnvVar("SAFEKEEPING_DATA_DIR", root_);
        setEnvVar("SAFEKEEPING_TEST_FAKE_VAULT_DIR", vaultRoot_);
        unsetEnvVar("SAFEKEEPING_DISABLE_SYSTEM_VAULT");
        unsetEnvVar("XDG_CURRENT_DESKTOP");
    }

    void TearDown() override {
        SafeKeeping::setLinuxVaultRootName("com.jgaa.SafeKeeping");
        SafeKeeping::setLinuxVaultBackend(SafeKeeping::LinuxVaultBackend::Auto);
        unsetEnvVar("SAFEKEEPING_DATA_DIR");
        unsetEnvVar("SAFEKEEPING_TEST_FAKE_VAULT_DIR");
        unsetEnvVar("SAFEKEEPING_DISABLE_SYSTEM_VAULT");
        unsetEnvVar("XDG_CURRENT_DESKTOP");
        std::error_code ignored;
        fs::remove_all(root_, ignored);
    }

    fs::path root_;
    fs::path vaultRoot_;
};

TEST_F(SafeKeepingRebootTest, BackendIdentificationWorksWhileLocked) {
    EXPECT_EQ(SafeKeeping::selectedSystemVaultBackendName(), "file");
    auto created = SafeKeeping::createNew("backend_name");
    ASSERT_NE(created.instance, nullptr);
    EXPECT_EQ(created.instance->systemVaultBackendName(), "file");
    ASSERT_TRUE(created.instance->lock());
    EXPECT_EQ(created.instance->systemVaultBackendName(), "file");
    created.instance.reset();
    auto reopened = SafeKeeping::open("backend_name");
    ASSERT_NE(reopened, nullptr);
    EXPECT_EQ(reopened->systemVaultBackendName(), "file");
}

TEST_F(SafeKeepingRebootTest, BackendIdentificationReportsExplicitLinuxSelection) {
#if defined(__linux__) || defined(__unix__)
    unsetEnvVar("SAFEKEEPING_TEST_FAKE_VAULT_DIR");
    SafeKeeping::setLinuxVaultBackend(SafeKeeping::LinuxVaultBackend::LibSecret);
    EXPECT_EQ(SafeKeeping::selectedSystemVaultBackendName(), "libsecret");
    SafeKeeping::setLinuxVaultBackend(SafeKeeping::LinuxVaultBackend::KWallet);
#if defined(SAFEKEEPING_ENABLE_KWALLET)
    EXPECT_EQ(SafeKeeping::selectedSystemVaultBackendName(), "kwallet");
#else
    EXPECT_EQ(SafeKeeping::selectedSystemVaultBackendName(), "unavailable");
#endif
#endif
}

TEST_F(SafeKeepingRebootTest, PassphraseOnlyNamespaceRoundTripsAndPersists) {
    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = false;
    options.passphrase = std::string("correct horse battery staple");
    const auto created = SafeKeeping::createNew("passphrase_only", options);
    ASSERT_NE(created.instance, nullptr);
    EXPECT_FALSE(created.recoveryKey.has_value());
    EXPECT_TRUE(created.instance->isUnlocked());
    EXPECT_TRUE(created.instance->hasPassphraseSlot());
    EXPECT_FALSE(created.instance->hasSystemVaultSlot());

    std::string binarySecret("abc\0xyz", 7);
    ASSERT_TRUE(created.instance->storeSecretWithDescription("api_token", binarySecret, "primary token"));
    ASSERT_TRUE(created.instance->lock());

    auto reopened = SafeKeeping::open("passphrase_only");
    ASSERT_NE(reopened, nullptr);
    EXPECT_FALSE(reopened->isUnlocked());
    EXPECT_FALSE(reopened->unlockWithPassphrase("wrong passphrase"));
    EXPECT_TRUE(reopened->unlockWithPassphrase("correct horse battery staple"));

    const auto secret = reopened->retrieveSecret("api_token");
    ASSERT_TRUE(secret.has_value());
    EXPECT_EQ(*secret, binarySecret);

    const auto secretBytes = reopened->retrieveSecretBytes("api_token");
    ASSERT_TRUE(secretBytes.has_value());
    EXPECT_EQ(secretBytes->size(), binarySecret.size());
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(secretBytes->data()), secretBytes->size()), binarySecret);

    const auto listed = reopened->listSecrets();
    ASSERT_EQ(listed.size(), 1u);
    EXPECT_EQ(listed[0].name, "api_token");
    EXPECT_EQ(listed[0].description, "primary token");
}

TEST_F(SafeKeepingRebootTest, VaultPassphraseAndRecoveryUnlockPathsAllWork) {
    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = true;
    options.passphrase = std::string("hunter2");
    options.createRecoveryKey = true;
    const auto created = SafeKeeping::createNew("mixed_unlocks", options);
    ASSERT_NE(created.instance, nullptr);
    ASSERT_TRUE(created.recoveryKey.has_value());
    ASSERT_TRUE(created.instance->storeSecret("db_password", "supersecret"));

    auto viaVault = SafeKeeping::open("mixed_unlocks");
    ASSERT_NE(viaVault, nullptr);
    EXPECT_TRUE(viaVault->isUnlocked());
    EXPECT_EQ(viaVault->retrieveSecret("db_password"), std::optional<std::string>("supersecret"));

    SafeKeeping::UnlockOptions unlockWithoutVault;
    unlockWithoutVault.trySystemVaultFirst = false;
    auto viaPassphrase = SafeKeeping::open("mixed_unlocks", unlockWithoutVault);
    ASSERT_NE(viaPassphrase, nullptr);
    EXPECT_FALSE(viaPassphrase->isUnlocked());
    EXPECT_TRUE(viaPassphrase->unlockWithPassphrase("hunter2"));
    EXPECT_EQ(viaPassphrase->retrieveSecret("db_password"), std::optional<std::string>("supersecret"));

    ASSERT_TRUE(SafeKeeping::removeNamespace("mixed_unlocks"));

    const auto recreated = SafeKeeping::createNew("mixed_unlocks", options);
    ASSERT_NE(recreated.recoveryKey, std::nullopt);
    ASSERT_TRUE(recreated.instance->storeSecret("db_password", "supersecret"));
    const auto recoveryKey = *recreated.recoveryKey;
    ASSERT_TRUE(recreated.instance->lock());

    unsetEnvVar("SAFEKEEPING_TEST_FAKE_VAULT_DIR");
    setEnvVar("SAFEKEEPING_DISABLE_SYSTEM_VAULT", "1");
    auto viaRecovery = SafeKeeping::open("mixed_unlocks", unlockWithoutVault);
    ASSERT_NE(viaRecovery, nullptr);
    EXPECT_FALSE(viaRecovery->isUnlocked());
    EXPECT_TRUE(viaRecovery->unlockWithRecoveryKey(recoveryKey));
    EXPECT_EQ(viaRecovery->retrieveSecret("db_password"), std::optional<std::string>("supersecret"));
}

TEST_F(SafeKeepingRebootTest, LockedInstancesRejectSecretOperations) {
    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = false;
    options.passphrase = std::string("pw");
    auto created = SafeKeeping::createNew("locked_semantics", options);
    ASSERT_NE(created.instance, nullptr);
    ASSERT_TRUE(created.instance->lock());

    EXPECT_FALSE(created.instance->storeSecret("key", "value"));
    EXPECT_EQ(created.instance->latestError().error, SafeKeeping::Error::Locked);
    EXPECT_FALSE(created.instance->retrieveSecret("key").has_value());
    EXPECT_EQ(created.instance->latestError().error, SafeKeeping::Error::Locked);
    EXPECT_FALSE(created.instance->removeSecret("key"));
    EXPECT_EQ(created.instance->latestError().error, SafeKeeping::Error::Locked);
    EXPECT_TRUE(created.instance->listSecrets().empty());
    EXPECT_EQ(created.instance->latestError().error, SafeKeeping::Error::Locked);

    EXPECT_TRUE(created.instance->unlockWithPassphrase("pw"));
    EXPECT_TRUE(created.instance->storeSecret("key", "value"));
}

TEST_F(SafeKeepingRebootTest, SlotManagementPreservesAccessAndRejectsLastSlotRemoval) {
    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = false;
    options.passphrase = std::string("old-pass");
    auto created = SafeKeeping::createNew("slot_management", options);
    ASSERT_NE(created.instance, nullptr);
    ASSERT_TRUE(created.instance->storeSecret("token", "one"));
    EXPECT_FALSE(created.instance->removePassphrase());

    ASSERT_TRUE(created.instance->addSystemVaultSlot());
    EXPECT_TRUE(created.instance->hasSystemVaultSlot());
    ASSERT_TRUE(created.instance->changePassphrase("new-pass"));
    ASSERT_TRUE(created.instance->addPassphrase("second-pass") == false);

    const auto rotatedRecovery = created.instance->rotateRecoveryKey();
    ASSERT_TRUE(rotatedRecovery.has_value());
    EXPECT_TRUE(created.instance->hasRecoverySlot());

    ASSERT_TRUE(created.instance->removePassphrase());
    EXPECT_FALSE(created.instance->hasPassphraseSlot());

    auto vaultOpen = SafeKeeping::open("slot_management");
    ASSERT_NE(vaultOpen, nullptr);
    EXPECT_TRUE(vaultOpen->isUnlocked());
    EXPECT_EQ(vaultOpen->retrieveSecret("token"), std::optional<std::string>("one"));

    SafeKeeping::UnlockOptions unlockWithoutVault;
    unlockWithoutVault.trySystemVaultFirst = false;
    auto passphraseOpen = SafeKeeping::open("slot_management", unlockWithoutVault);
    ASSERT_NE(passphraseOpen, nullptr);
    EXPECT_FALSE(passphraseOpen->unlockWithPassphrase("new-pass"));
    EXPECT_TRUE(passphraseOpen->unlockWithRecoveryKey(*rotatedRecovery));
    EXPECT_EQ(passphraseOpen->retrieveSecret("token"), std::optional<std::string>("one"));

    EXPECT_TRUE(passphraseOpen->removeRecoveryKey());
    EXPECT_FALSE(passphraseOpen->hasRecoverySlot());
}

TEST_F(SafeKeepingRebootTest, RemoveNamespaceDeletesDatabaseAndVaultMaterial) {
    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = true;
    options.passphrase = std::string("pw");
    options.createRecoveryKey = true;
    auto created = SafeKeeping::createNew("namespace_delete", options);
    ASSERT_NE(created.instance, nullptr);
    ASSERT_TRUE(created.instance->storeSecret("name", "value"));

    EXPECT_TRUE(SafeKeeping::exists("namespace_delete"));
    EXPECT_TRUE(SafeKeeping::removeNamespace("namespace_delete"));
    EXPECT_FALSE(SafeKeeping::exists("namespace_delete"));
    EXPECT_FALSE(fs::exists(namespaceDbPath(root_, "namespace_delete")));
    EXPECT_EQ(SafeKeeping::open("namespace_delete"), nullptr);
}

TEST_F(SafeKeepingRebootTest, CreateFailsWithoutAnyUnlockMethodWhenVaultIsDisabled) {
    unsetEnvVar("SAFEKEEPING_TEST_FAKE_VAULT_DIR");
    setEnvVar("SAFEKEEPING_DISABLE_SYSTEM_VAULT", "1");
    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = true;
    options.requireAtLeastOneUnlockMethod = true;
    EXPECT_THROW(
        SafeKeeping::createNew("no_unlock_method", options),
        std::runtime_error);
}

TEST_F(SafeKeepingRebootTest, CorruptedCiphertextFailsClosed) {
    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = false;
    options.passphrase = std::string("pw");
    auto created = SafeKeeping::createNew("corrupted_db", options);
    ASSERT_NE(created.instance, nullptr);
    ASSERT_TRUE(created.instance->storeSecret("target", "secret-value"));
    ASSERT_TRUE(created.instance->lock());

    execSql(namespaceDbPath(root_, "corrupted_db"),
            "UPDATE secrets SET value_ciphertext = zeroblob(length(value_ciphertext));");

    SafeKeeping::UnlockOptions unlockWithoutVault;
    unlockWithoutVault.trySystemVaultFirst = false;
    auto reopened = SafeKeeping::open("corrupted_db", unlockWithoutVault);
    ASSERT_NE(reopened, nullptr);
    ASSERT_TRUE(reopened->unlockWithPassphrase("pw"));
    EXPECT_FALSE(reopened->retrieveSecret("target").has_value());
    EXPECT_EQ(reopened->latestError().error, SafeKeeping::Error::StorageError);
}

TEST_F(SafeKeepingRebootTest, ListIsSortedAndOverwriteReplacesDescription) {
    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = false;
    options.passphrase = std::string("pw");
    auto created = SafeKeeping::createNew("listing", options);
    ASSERT_NE(created.instance, nullptr);
    ASSERT_TRUE(created.instance->storeSecret("zeta", "one"));
    ASSERT_TRUE(created.instance->storeSecretWithDescription("alpha", "two", "first"));
    ASSERT_TRUE(created.instance->storeSecretWithDescription("alpha", "three", "updated"));

    const auto listed = created.instance->listSecrets();
    ASSERT_EQ(listed.size(), 2u);
    EXPECT_EQ(listed[0].name, "alpha");
    EXPECT_EQ(listed[0].description, "updated");
    EXPECT_EQ(listed[1].name, "zeta");
    EXPECT_TRUE(listed[1].description.empty());
    EXPECT_EQ(created.instance->retrieveSecret("alpha"), std::optional<std::string>("three"));
}

TEST_F(SafeKeepingRebootTest, ByteOverloadsRoundTripBinaryPayloads) {
    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = false;
    options.passphrase = std::string("pw");
    auto created = SafeKeeping::createNew("byte_overloads", options);
    ASSERT_NE(created.instance, nullptr);

    const std::vector<std::byte> secret{
        std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x00}, std::byte{0xff}};
    ASSERT_TRUE(created.instance->storeSecretWithDescription("blob", std::span<const std::byte>(secret), "binary"));

    const auto loaded = created.instance->retrieveSecretBytes("blob");
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(*loaded, secret);
}

TEST_F(SafeKeepingRebootTest, SecretSizeLimitIsEnforcedAndReported) {
    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = false;
    options.passphrase = std::string("pw");
    auto created = SafeKeeping::createNew("size_limit", options);
    ASSERT_NE(created.instance, nullptr);

    const std::string maxSized(10 * 1024, 'a');
    EXPECT_TRUE(created.instance->storeSecret("fits", maxSized));
    EXPECT_EQ(created.instance->latestError().error, SafeKeeping::Error::None);

    const std::string tooLarge((10 * 1024) + 1, 'b');
    EXPECT_FALSE(created.instance->storeSecret("too_big", tooLarge));
    const auto error = created.instance->latestError();
    EXPECT_EQ(error.error, SafeKeeping::Error::TooLarge);
    EXPECT_NE(error.message.find("10240"), std::string::npos);
}

TEST_F(SafeKeepingRebootTest, MissingSecretSetsNotFoundError) {
    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = false;
    options.passphrase = std::string("pw");
    auto created = SafeKeeping::createNew("missing_secret", options);
    ASSERT_NE(created.instance, nullptr);

    EXPECT_FALSE(created.instance->retrieveSecret("missing").has_value());
    EXPECT_EQ(created.instance->latestError().error, SafeKeeping::Error::NotFound);

    EXPECT_FALSE(created.instance->removeSecret("missing"));
    EXPECT_EQ(created.instance->latestError().error, SafeKeeping::Error::NotFound);
}

TEST_F(SafeKeepingRebootTest, OpenOrCreateCreatesThenReopensNamespace) {
    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = false;
    options.passphrase = std::string("pw");

    auto created = SafeKeeping::openOrCreate("open_or_create", options);
    ASSERT_NE(created, nullptr);
    EXPECT_TRUE(created->isUnlocked());
    ASSERT_TRUE(created->storeSecret("token", "value"));
    ASSERT_TRUE(created->lock());

    auto reopened = SafeKeeping::openOrCreate("open_or_create", options);
    ASSERT_NE(reopened, nullptr);
    EXPECT_FALSE(reopened->isUnlocked());
    ASSERT_TRUE(reopened->unlockWithPassphrase("pw"));
    EXPECT_EQ(reopened->retrieveSecret("token"), std::optional<std::string>("value"));
}

TEST_F(SafeKeepingRebootTest, LinuxVaultRootNameCanBeConfigured) {
#if defined(__linux__) || defined(__unix__)
    const auto original = SafeKeeping::linuxVaultRootName();
    EXPECT_EQ(original, "com.jgaa.SafeKeeping");

    SafeKeeping::setLinuxVaultRootName("org.example.TestApp");
    EXPECT_EQ(SafeKeeping::linuxVaultRootName(), "org.example.TestApp");

    EXPECT_THROW(SafeKeeping::setLinuxVaultRootName("bad/root"), std::invalid_argument);

    SafeKeeping::setLinuxVaultRootName(original);
#else
    GTEST_SKIP() << "Linux-only configuration";
#endif
}

TEST_F(SafeKeepingRebootTest, LinuxVaultBackendOverrideControlsNewNamespaces) {
#if defined(__linux__) || defined(__unix__)
    setEnvVar("XDG_CURRENT_DESKTOP", "KDE");
    SafeKeeping::setLinuxVaultBackend(SafeKeeping::LinuxVaultBackend::LibSecret);

    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = true;
    options.passphrase = std::string("pw");
    auto created = SafeKeeping::createNew("backend_override", options);
    ASSERT_NE(created.instance, nullptr);

    const auto backend = querySingleText(namespaceDbPath(root_, "backend_override"),
                                         "SELECT system_vault_backend FROM metadata LIMIT 1");
    ASSERT_TRUE(backend.has_value());
    EXPECT_EQ(*backend, "libsecret");
#else
    GTEST_SKIP() << "Linux-only backend selection";
#endif
}

TEST_F(SafeKeepingRebootTest, LinuxSystemVaultBackendIsPinnedAfterInitialization) {
#if defined(__linux__) || defined(__unix__)
    setEnvVar("XDG_CURRENT_DESKTOP", "KDE");
    SafeKeeping::setLinuxVaultBackend(SafeKeeping::LinuxVaultBackend::Auto);

    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = true;
    options.passphrase = std::string("pw");
    auto created = SafeKeeping::createNew("backend_pinned", options);
    ASSERT_NE(created.instance, nullptr);
    ASSERT_TRUE(created.instance->lock());

    const auto backend = querySingleText(namespaceDbPath(root_, "backend_pinned"),
                                         "SELECT system_vault_backend FROM metadata LIMIT 1");
    ASSERT_TRUE(backend.has_value());
#if defined(SAFEKEEPING_ENABLE_KWALLET)
    EXPECT_EQ(*backend, "kwallet");
#else
    EXPECT_EQ(*backend, "libsecret");
#endif

    unsetEnvVar("XDG_CURRENT_DESKTOP");
    SafeKeeping::setLinuxVaultBackend(SafeKeeping::LinuxVaultBackend::LibSecret);
    auto reopened = SafeKeeping::open("backend_pinned");
    ASSERT_NE(reopened, nullptr);
    EXPECT_TRUE(reopened->isUnlocked());
#else
    GTEST_SKIP() << "Linux-only backend selection";
#endif
}

TEST_F(SafeKeepingRebootTest, LegacyLinuxNamespacesPersistBackendOnFirstVaultUnlock) {
#if defined(__linux__) || defined(__unix__)
    SafeKeeping::setLinuxVaultBackend(SafeKeeping::LinuxVaultBackend::LibSecret);

    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = true;
    options.passphrase = std::string("pw");
    auto created = SafeKeeping::createNew("legacy_backend", options);
    ASSERT_NE(created.instance, nullptr);
    ASSERT_TRUE(created.instance->lock());

    execSql(namespaceDbPath(root_, "legacy_backend"),
            "UPDATE metadata SET schema_version = 1, system_vault_backend = NULL;");

    auto reopened = SafeKeeping::open("legacy_backend");
    ASSERT_NE(reopened, nullptr);
    EXPECT_TRUE(reopened->isUnlocked());

    const auto backend = querySingleText(namespaceDbPath(root_, "legacy_backend"),
                                         "SELECT system_vault_backend FROM metadata LIMIT 1");
    ASSERT_TRUE(backend.has_value());
    EXPECT_EQ(*backend, "libsecret");
#else
    GTEST_SKIP() << "Linux-only backend selection";
#endif
}

#if defined(__linux__) || defined(__unix__)
TEST(SafeKeepingAcceptance, RealSystemVaultEntryIsStoredWithExpectedMetadata) {
    if (!envFlagEnabled("SAFEKEEPING_ACCEPT_REAL_WALLET")) {
        GTEST_SKIP() << "SAFEKEEPING_ACCEPT_REAL_WALLET=1 is required";
    }

    unsetEnvVar("SAFEKEEPING_TEST_FAKE_VAULT_DIR");
    unsetEnvVar("SAFEKEEPING_DISABLE_SYSTEM_VAULT");

    const fs::path root = fs::temp_directory_path() / uniqueName("safekeeping-acceptance");
    setEnvVar("SAFEKEEPING_DATA_DIR", root);

    const std::string namespaceName = uniqueName("real_wallet");
    const std::string expectedRoot = SafeKeeping::linuxVaultRootName();
    std::string expectedEntry;

    auto cleanup = [&]() {
        SafeKeeping::removeNamespace(namespaceName);
        unsetEnvVar("SAFEKEEPING_DATA_DIR");
        std::error_code ignored;
        fs::remove_all(root, ignored);
    };

    cleanup();

    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = true;
    options.passphrase = std::string("acceptance-passphrase");

    auto created = SafeKeeping::createNew(namespaceName, options);
    ASSERT_NE(created.instance, nullptr);
    ASSERT_TRUE(created.instance->hasSystemVaultSlot());
    expectedEntry = namespaceName + "/" + *querySingleText(namespaceDbPath(root, namespaceName), "SELECT system_vault_entry FROM metadata");
    ASSERT_TRUE(created.instance->lock());

    auto reopened = SafeKeeping::open(namespaceName);
    ASSERT_NE(reopened, nullptr);
    EXPECT_TRUE(reopened->isUnlocked());
    EXPECT_TRUE(reopened->hasSystemVaultSlot());

    if (const auto namespaceFile = envString("SAFEKEEPING_ACCEPT_NAMESPACE_FILE"); namespaceFile.has_value()) {
        std::ofstream out(*namespaceFile, std::ios::trunc);
        ASSERT_TRUE(out.good());
        out << namespaceName << "\n";
        out << expectedRoot << "\n";
        out << expectedEntry << "\n";
    }

    std::cout << "SAFEKEEPING_ACCEPT_NAMESPACE=" << namespaceName << "\n";
    std::cout << "SAFEKEEPING_ACCEPT_ROOT=" << expectedRoot << "\n";
    std::cout << "SAFEKEEPING_ACCEPT_ENTRY=" << expectedEntry << "\n";

    EXPECT_EQ(reopened->namespaceName(), namespaceName);
    EXPECT_TRUE(reopened->removeSecret("missing") == false);
    EXPECT_EQ(reopened->latestError().error, SafeKeeping::Error::NotFound);
    EXPECT_TRUE(reopened->lock());

    if (envFlagEnabled("SAFEKEEPING_ACCEPT_CLEANUP")) {
        cleanup();
    } else {
        unsetEnvVar("SAFEKEEPING_DATA_DIR");
    }
}
#endif

TEST_F(SafeKeepingRebootTest, InvalidWalletMaterialIsVaultErrorAndDoesNotChangeData) {
    const auto created = SafeKeeping::createNew("invalid_material");
    const auto entry = *querySingleText(namespaceDbPath(root_, "invalid_material"), "SELECT system_vault_entry FROM metadata");
    const auto key = vaultRoot_ / "invalid_material" / (entry + ".txt");
    std::ifstream input(key);
    const std::string original((std::istreambuf_iterator<char>(input)), {});
    input.close();
    for (const auto& bad : {std::string{}, std::string("abc"), std::string(64, 'g')}) {
        { std::ofstream out(key, std::ios::trunc); out << bad; }
        auto reopened = SafeKeeping::open("invalid_material");
        ASSERT_NE(reopened, nullptr);
        EXPECT_FALSE(reopened->isUnlocked());
        EXPECT_EQ(reopened->latestError().error, SafeKeeping::Error::VaultError);
        EXPECT_NE(reopened->latestError().message.find("64 hexadecimal"), std::string::npos);
        EXPECT_NE(reopened->latestError().message.find("backend 'file'"), std::string::npos);
        EXPECT_NE(reopened->latestError().message.find(entry), std::string::npos);
    }
    { std::ofstream out(key, std::ios::trunc); out << original; }
    EXPECT_TRUE(SafeKeeping::open("invalid_material")->isUnlocked());
}

TEST_F(SafeKeepingRebootTest, SeparateDataRootsUseIndependentWalletEntries) {
    auto first = SafeKeeping::createNew("same_name");
    first.instance.reset();
    const auto firstEntry = querySingleText(namespaceDbPath(root_, "same_name"), "SELECT system_vault_entry FROM metadata");
    const auto secondRoot = root_ / "second-data-root";
    setEnvVar("SAFEKEEPING_DATA_DIR", secondRoot);
    auto second = SafeKeeping::createNew("same_name");
    second.instance.reset();
    EXPECT_NE(firstEntry, querySingleText(namespaceDbPath(secondRoot, "same_name"), "SELECT system_vault_entry FROM metadata"));
    EXPECT_TRUE(SafeKeeping::open("same_name")->isUnlocked());
    EXPECT_TRUE(SafeKeeping::removeNamespace("same_name"));
    setEnvVar("SAFEKEEPING_DATA_DIR", root_);
    EXPECT_TRUE(SafeKeeping::open("same_name")->isUnlocked());
}

TEST_F(SafeKeepingRebootTest, CreationFailureBeforeWritePreservesExistingWalletAndFiles) {
    auto first = SafeKeeping::createNew("failed_create");
    first.instance.reset();
    const auto secondRoot = root_ / "blocked-root";
    fs::create_directories(secondRoot);
    { std::ofstream out(secondRoot / "failed_create"); out << "must survive"; }
    setEnvVar("SAFEKEEPING_DATA_DIR", secondRoot);
    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = false;
    options.passphrase = "pw";
    EXPECT_THROW(SafeKeeping::createNew("failed_create", options), std::exception);
    EXPECT_TRUE(fs::is_regular_file(secondRoot / "failed_create"));
    setEnvVar("SAFEKEEPING_DATA_DIR", root_);
    EXPECT_TRUE(SafeKeeping::open("failed_create")->isUnlocked());
}

TEST_F(SafeKeepingRebootTest, RollbackPreservesUnrelatedNamespaceFiles) {
    const auto dir = root_ / "partial";
    fs::create_directories(dir);
    { std::ofstream out(dir / "unrelated"); out << "must survive"; }
    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = false;
    EXPECT_THROW(SafeKeeping::createNew("partial", options), std::exception);
    EXPECT_TRUE(fs::exists(dir / "unrelated"));
    EXPECT_FALSE(fs::exists(dir / "vault.db"));
}

TEST_F(SafeKeepingRebootTest, LegacyEntryIsPreservedAndBlocksNewDatabaseCreation) {
    auto created = SafeKeeping::createNew("legacy_entry");
    created.instance.reset();
    const auto db = namespaceDbPath(root_, "legacy_entry");
    const auto entry = *querySingleText(db, "SELECT system_vault_entry FROM metadata");
    fs::rename(vaultRoot_ / "legacy_entry" / (entry + ".txt"),
               vaultRoot_ / "legacy_entry" / "namespace-vault-material.txt");
    execSql(db, "ALTER TABLE metadata DROP COLUMN system_vault_entry; UPDATE metadata SET schema_version=2;");
    EXPECT_TRUE(SafeKeeping::open("legacy_entry")->isUnlocked());
    const auto secondRoot = root_ / "new-root";
    setEnvVar("SAFEKEEPING_DATA_DIR", secondRoot);
    EXPECT_THROW(SafeKeeping::createNew("legacy_entry"), std::exception);
    EXPECT_FALSE(fs::exists(namespaceDbPath(secondRoot, "legacy_entry")));
    setEnvVar("SAFEKEEPING_DATA_DIR", root_);
    EXPECT_TRUE(SafeKeeping::open("legacy_entry")->isUnlocked());
    EXPECT_TRUE(SafeKeeping::removeNamespace("legacy_entry"));
    EXPECT_FALSE(fs::exists(vaultRoot_ / "legacy_entry" / "namespace-vault-material.txt"));
}

#ifndef _WIN32
TEST_F(SafeKeepingRebootTest, ConcurrentCreatorsPreserveWinningDatabaseAndKey) {
    for (bool openOrCreate : {false, true}) {
        const std::string name = openOrCreate ? "concurrent_open_or_create" : "concurrent_create";
        int gate[2];
        ASSERT_EQ(pipe(gate), 0);
        std::vector<pid_t> children;
        for (int i = 0; i < 8; ++i) {
            const auto pid = fork();
            ASSERT_NE(pid, -1);
            if (pid == 0) {
                close(gate[1]);
                char token;
                if (read(gate[0], &token, 1) != 1) _exit(3);
                int result = 0;
                try {
                    auto vault = openOrCreate ? SafeKeeping::openOrCreate(name) : SafeKeeping::createNew(name).instance;
                    result = vault && vault->isUnlocked() ? 0 : 3;
                } catch (...) { result = 2; }
                _exit(result);
            }
            children.push_back(pid);
        }
        close(gate[0]);
        ASSERT_EQ(write(gate[1], "12345678", 8), 8);
        close(gate[1]);
        int successes = 0;
        for (auto pid : children) {
            int status = 0;
            ASSERT_EQ(waitpid(pid, &status, 0), pid);
            ASSERT_TRUE(WIFEXITED(status));
            const int code = WEXITSTATUS(status);
            EXPECT_TRUE(code == 0 || (!openOrCreate && code == 2));
            successes += code == 0;
        }
        EXPECT_EQ(successes, openOrCreate ? 8 : 1);
        EXPECT_TRUE(SafeKeeping::open(name)->isUnlocked());
    }
}
#endif

#ifdef SAFEKEEPING_WRAP_SQLITE_STEP
TEST_F(SafeKeepingRebootTest, NewMaterialMustReadBackAndAuthenticateBeforeCreationSucceeds) {
    int i = 0;
    for (const auto& bad : {std::optional<std::string>{}, std::optional<std::string>{""},
                           std::optional<std::string>{std::string(64, '0')}}) {
        corruptWalletRoot = vaultRoot_.string();
        corruptWalletRead = bad;
        const auto name = "readback_failure_" + std::to_string(i++);
        EXPECT_THROW(SafeKeeping::createNew(name), std::exception);
        corruptWalletRoot.clear();
        EXPECT_FALSE(SafeKeeping::exists(name));
        if (fs::exists(vaultRoot_ / name)) EXPECT_TRUE(fs::is_empty(vaultRoot_ / name));
    }
}

TEST_F(SafeKeepingRebootTest, AddingVaultSlotAlsoVerifiesReadBackAndRollsBack) {
    SafeKeeping::CreateOptions options;
    options.createSystemVaultSlot = false;
    options.passphrase = "pw";
    auto created = SafeKeeping::createNew("add_readback", options);
    corruptWalletRoot = vaultRoot_.string();
    corruptWalletRead = std::string(64, '0');
    EXPECT_FALSE(created.instance->addSystemVaultSlot());
    corruptWalletRoot.clear();
    EXPECT_EQ(created.instance->latestError().error, SafeKeeping::Error::VaultError);
    EXPECT_FALSE(created.instance->hasSystemVaultSlot());
    EXPECT_TRUE(created.instance->lock());
    EXPECT_TRUE(created.instance->unlockWithPassphrase("pw"));
}
#endif

TEST_F(SafeKeepingRebootTest, CreationPreservesPreExistingDatabaseArtifacts) {
    const auto dir = root_ / "orphan_artifact";
    fs::create_directories(dir);
    { std::ofstream out(dir / "vault.db-wal"); out << "must survive"; }
    EXPECT_THROW(SafeKeeping::createNew("orphan_artifact"), std::exception);
    EXPECT_FALSE(fs::exists(dir / "vault.db"));
    std::ifstream input(dir / "vault.db-wal");
    const std::string content((std::istreambuf_iterator<char>(input)), {});
    EXPECT_EQ(content, "must survive");
    EXPECT_FALSE(fs::exists(vaultRoot_ / "orphan_artifact"));
}

TEST_F(SafeKeepingRebootTest, NamespaceCannotAliasParentOrLockDirectory) {
    for (const auto& name : {".", "..", ".locks"}) {
        EXPECT_THROW(SafeKeeping::createNew(name), std::exception);
        EXPECT_THROW(SafeKeeping::removeNamespace(name), std::exception);
    }
}
