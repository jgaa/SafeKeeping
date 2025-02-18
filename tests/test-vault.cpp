#include <gtest/gtest.h>
#include <memory>
#include <unordered_set>
#include "safekeeping/SafeKeeping.h"

using namespace jgaa::safekeeping;

constexpr auto vault = SafeKeeping::Vault::DEFAULT_SECURE_STORAGE;

// Test Fixture for SafeKeeping
class TestVault : public ::testing::Test {
protected:
    void SetUp() override {
        // Create an instance using the factory method
        safeKeeping = SafeKeeping::create("TestSafe", vault);
        ASSERT_NE(safeKeeping, nullptr);  // Ensure creation was successful

        // Clear the list of stored keys before each test
        storedKeys.clear();
    }

    void TearDown() override {
        // Cleanup all stored secrets after each test
        cleanupSecrets();
    }

    void storeAndTrackSecret(const std::string& key, const std::string& value) {
        safeKeeping->removeSecret(key);  // Ensure the key does not exist before adding
        ASSERT_TRUE(safeKeeping->storeSecret(key, value));
        storedKeys.insert(key);
    }

    void storeAndTrackSecretWithDescription(const std::string& key, const std::string& value, const std::string& description) {
        safeKeeping->removeSecret(key);  // Ensure the key does not exist before adding
        ASSERT_TRUE(safeKeeping->storeSecretWithDescription(key, value, description));
        storedKeys.insert(key);
    }

    void cleanupSecrets() {
        for (const auto& key : storedKeys) {
            safeKeeping->removeSecret(key);
        }
        storedKeys.clear();
    }

    std::unique_ptr<SafeKeeping> safeKeeping;
    std::unordered_set<std::string> storedKeys;  // Track stored keys
};

// Test storing and retrieving a simple string (e.g., password)
TEST_F(TestVault, StoreAndRetrievePassword) {
    std::string key = "user_password";
    std::string password = "SuperSecret123!";

    storeAndTrackSecret(key, password);

    auto retrieved = safeKeeping->retrieveSecret(key);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved.value(), password);
}

// Test storing and retrieving a PEM-encoded certificate
TEST_F(TestVault, StoreAndRetrievePEMCertificate) {
    std::string key = "server_cert";
    std::string pemCert = R"(-----BEGIN CERTIFICATE-----
MIIE7zCCAtcCFGBr8HLCF8m3FO8r8L6bW3Qsmq3xMA0GCSqGSIb3DQEBCwUAMDQx
EjAQBgNVBAMMCU1vY2sgQ2VydDERMA8GA1UECgwIVGVzdCBPcmcxCzAJBgNVBAYT
AlVTMB4XDTI1MDIxNDExMzQ1N1oXDTI2MDIxNDExMzQ1N1owNDESMBAGA1UEAwwJ
TW9jayBDZXJ0MREwDwYDVQQKDAhUZXN0IE9yZzELMAkGA1UEBhMCVVMwggIiMA0G
CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC4+W5h6EVu64T6UhT1aBGwjwb4zz9y
FUBbbYKTStpOfwBIqJaA56EnruvfadFscfmACQESPeL/jturi+9Z6NA6VX6WVenx
hUppMYpd8DGr1ULPiVZUMHeNRBgCy1bk+/J0rdsZnaCYcplGr6QcbdFcBmAIBkn6
90vk14yAJrZ2pTjma+ou41tmYIHkqd6QzMup7tlH3Qs30LUQcawjZ+Oa4Rz9dUvD
0iiuoUslcVQdacQLy9RKhMPqBFa0azyH97k2PRxbzjJCBvnmcI9Lb4VEnn/UU2TX
5iGJHqTy/AePYSrIZQ3fLQK1aODm8u+iQuRHRGh9rc4Fsmfy7CG6cqCfN4kCDPoj
eBYWv2pFv1Te1BiLsfNGWgsHSeec9FXeBZyYHtJFvoIoAM/28AZ2fI90722m0zXr
D7RIyCbOLSmdUXhjleLvbX9C5G3bRKNdEHiwV4DzQnbYbC9aroKRXBGB0H7DAciR
j6/2vLbic9FK+/H0a3hCxwQL4WXh/YICKbbsYJQoheiUOq1QdewA439nykLtESCP
7/M9Dlcpw1juGqlvhhG6KcRJIHd4ZKTwqC+auaRx68YYmTEW27mPMuyDgYOj1uhp
pLuJ+ayrVJovJaxQ1kFbLa/V6ScrPK8mCpESavsvSaY24vJ6mUekwV9rE/9tu8DH
IctzUdRpJ9S0uwIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQAzPGqvB+2FgDNngsAj
wGUI0MvyWsHhlnxFlmOvjNEwEXkTXjDzwy8eYxWqPvHJcg+uQEESSrDZJcLFmiAQ
iiwxM5P11yPRwQeu8kL8TV3WBuozDh5TuYcAKCk0PHeRGuDA+ZbN79cUFMei3tdx
4mBpmSfBlmVJUyXWdzbIkCJL3WM9/w26cnOGwEEJyzbefHcMwklrNFhTYPfKfzJK
jWOMZFzxgEJdnrFG7F3dV0vA2t8zXzBei+SOfPHoj0rimxvKmzyD62OfodcB1b9J
oBQokuH3COdUW9wrH4/HEMkGm0y+1IB5r8q85cdoNhQaC56TE1Samow7rBNkv2mm
5O9wKm9nEV/lVQYCmJFViU5qwnFy7Le24Z7d4J6gJNb3FBJWe3UyS1lvJ0H9B9KW
twLZSJEVsaBLk/yCHu55YGu4JvOr80yAAsBKDx36xcR2rKq/gt/PJ79zeKk9L8Jz
d/ZdlnQnh2bpcwjTZRbuAN1HNUQD41p9fxtB1F7gXCtT+chht22Du22pemusMHE0
CTHSJuz6yFSLwqgQqaiTvb9ud4ANRMC6HxgvaxAJ+bjbqrASv/TRS8ZwD927OrP6
oKXtpQv49CcClIoFIwbpas6v/aWtvWa1zPmYRWLDOpVnnphF2F/cCLbP3DOj/Sru
PJ2RLcmxJHWiXpzbU0w7YSnGHg==
-----END CERTIFICATE-----
)";

    storeAndTrackSecret(key, pemCert);

    auto retrieved = safeKeeping->retrieveSecret(key);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved.value(), pemCert);
}

// Test storing and retrieving a JSON payload containing URLs and certificates
TEST_F(TestVault, StoreAndRetrieveJSONPayload) {
    std::string key = "json_payload";
    std::string jsonPayload = R"({
        "certificate": "-----BEGIN CERTIFICATE-----
MIIE7zCCAtcCFGBr8HLCF8m3FO8r8L6bW3Qsmq3xMA0GCSqGSIb3DQEBCwUAMDQx
EjAQBgNVBAMMCU1vY2sgQ2VydDERMA8GA1UECgwIVGVzdCBPcmcxCzAJBgNVBAYT
AlVTMB4XDTI1MDIxNDExMzQ1N1oXDTI2MDIxNDExMzQ1N1owNDESMBAGA1UEAwwJ
TW9jayBDZXJ0MREwDwYDVQQKDAhUZXN0IE9yZzELMAkGA1UEBhMCVVMwggIiMA0G
CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC4+W5h6EVu64T6UhT1aBGwjwb4zz9y
FUBbbYKTStpOfwBIqJaA56EnruvfadFscfmACQESPeL/jturi+9Z6NA6VX6WVenx
hUppMYpd8DGr1ULPiVZUMHeNRBgCy1bk+/J0rdsZnaCYcplGr6QcbdFcBmAIBkn6
90vk14yAJrZ2pTjma+ou41tmYIHkqd6QzMup7tlH3Qs30LUQcawjZ+Oa4Rz9dUvD
0iiuoUslcVQdacQLy9RKhMPqBFa0azyH97k2PRxbzjJCBvnmcI9Lb4VEnn/UU2TX
5iGJHqTy/AePYSrIZQ3fLQK1aODm8u+iQuRHRGh9rc4Fsmfy7CG6cqCfN4kCDPoj
eBYWv2pFv1Te1BiLsfNGWgsHSeec9FXeBZyYHtJFvoIoAM/28AZ2fI90722m0zXr
D7RIyCbOLSmdUXhjleLvbX9C5G3bRKNdEHiwV4DzQnbYbC9aroKRXBGB0H7DAciR
j6/2vLbic9FK+/H0a3hCxwQL4WXh/YICKbbsYJQoheiUOq1QdewA439nykLtESCP
7/M9Dlcpw1juGqlvhhG6KcRJIHd4ZKTwqC+auaRx68YYmTEW27mPMuyDgYOj1uhp
pLuJ+ayrVJovJaxQ1kFbLa/V6ScrPK8mCpESavsvSaY24vJ6mUekwV9rE/9tu8DH
IctzUdRpJ9S0uwIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQAzPGqvB+2FgDNngsAj
wGUI0MvyWsHhlnxFlmOvjNEwEXkTXjDzwy8eYxWqPvHJcg+uQEESSrDZJcLFmiAQ
iiwxM5P11yPRwQeu8kL8TV3WBuozDh5TuYcAKCk0PHeRGuDA+ZbN79cUFMei3tdx
4mBpmSfBlmVJUyXWdzbIkCJL3WM9/w26cnOGwEEJyzbefHcMwklrNFhTYPfKfzJK
jWOMZFzxgEJdnrFG7F3dV0vA2t8zXzBei+SOfPHoj0rimxvKmzyD62OfodcB1b9J
oBQokuH3COdUW9wrH4/HEMkGm0y+1IB5r8q85cdoNhQaC56TE1Samow7rBNkv2mm
5O9wKm9nEV/lVQYCmJFViU5qwnFy7Le24Z7d4J6gJNb3FBJWe3UyS1lvJ0H9B9KW
twLZSJEVsaBLk/yCHu55YGu4JvOr80yAAsBKDx36xcR2rKq/gt/PJ79zeKk9L8Jz
d/ZdlnQnh2bpcwjTZRbuAN1HNUQD41p9fxtB1F7gXCtT+chht22Du22pemusMHE0
CTHSJuz6yFSLwqgQqaiTvb9ud4ANRMC6HxgvaxAJ+bjbqrASv/TRS8ZwD927OrP6
oKXtpQv49CcClIoFIwbpas6v/aWtvWa1zPmYRWLDOpVnnphF2F/cCLbP3DOj/Sru
PJ2RLcmxJHWiXpzbU0w7YSnGHg==
-----END CERTIFICATE-----
",
        "private_key": "-----BEGIN PRIVATE KEY-----
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
qTKcjLQ+PkXZ5jrj2/6WtgozKmEdeA==
-----END PRIVATE KEY-----
",
        "api_url": "https://secure.example.com"
    })";

    storeAndTrackSecret(key, jsonPayload);

    auto retrieved = safeKeeping->retrieveSecret(key);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved.value(), jsonPayload);
}

// Test removing a secret
TEST_F(TestVault, RemoveSecret) {
    std::string key = "removable_secret";
    std::string value = "TemporaryValue";

    storeAndTrackSecret(key, value);
    ASSERT_TRUE(safeKeeping->removeSecret(key));

    auto retrieved = safeKeeping->retrieveSecret(key);
    EXPECT_FALSE(retrieved.has_value());

    // Remove from tracking since it's already deleted
    storedKeys.erase(key);
}

// Test retrieving a non-existent key
TEST_F(TestVault, RetrieveNonExistentKey) {
    std::string key = "non_existent_key";
    safeKeeping->removeSecret(key);

    auto retrieved = safeKeeping->retrieveSecret(key);
    EXPECT_FALSE(retrieved.has_value());
}

// Test removing a non-existent key
TEST_F(TestVault, RemoveNonExistentKey) {
    std::string key = "non_existent_key";
    safeKeeping->removeSecret(key);  // Ensure it's not there

    EXPECT_FALSE(safeKeeping->removeSecret(key));  // Should return false
}

// Test storing a secret with a description and retrieving it
TEST_F(TestVault, StoreAndRetrieveSecretWithDescription) {
    std::string key = "api_key";
    std::string secret = "API_SECRET_123";
    std::string description = "API Key for Service X";

    storeAndTrackSecretWithDescription(key, secret, description);

    auto retrieved = safeKeeping->retrieveSecret(key);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved.value(), secret);
}

// Test listing stored secrets with descriptions
TEST_F(TestVault, ListSecretsWithDescription) {
    safeKeeping->removeSecret("key1");
    safeKeeping->removeSecret("key2");

    std::string key1 = "key1";
    std::string secret1 = "password123";
    std::string desc1 = "Login password";

    std::string key2 = "key2";
    std::string secret2 = "myToken456";
    std::string desc2 = "API token for user";

    storeAndTrackSecretWithDescription(key1, secret1, desc1);
    storeAndTrackSecretWithDescription(key2, secret2, desc2);

    auto secrets = safeKeeping->listSecrets();
    ASSERT_EQ(secrets.size(), 2);
    EXPECT_EQ(secrets[0].name, key1);
    EXPECT_EQ(secrets[0].description, desc1);
    EXPECT_EQ(secrets[1].name, key2);
    EXPECT_EQ(secrets[1].description, desc2);
}

// Test that only secrets stored with a description appear in `listSecrets()`
TEST_F(TestVault, ListSecretsOnlyShowsDescribedSecrets) {
    std::string key1 = "described_key";
    std::string key2 = "undisclosed_key";
    std::string secret1 = "SecretWithDesc";
    std::string secret2 = "SecretWithoutDesc";
    std::string description = "A described secret";

    storeAndTrackSecretWithDescription(key1, secret1, description);
    storeAndTrackSecret(key2, secret2);  // No description added

    auto secrets = safeKeeping->listSecrets();
    ASSERT_EQ(secrets.size(), 1);
    EXPECT_EQ(secrets[0].name, key1);
    EXPECT_EQ(secrets[0].description, description);
}

// Test that two different namespaces do not interfere with each other
TEST(TestSafeKeeping, NamespaceIsolation) {
    const std::string key = "shared_key";
    const std::string secret1 = "Vault1_Secret";
    const std::string secret2 = "Vault2_Secret";

    {
        auto vault1 = SafeKeeping::create("Namespace1", vault);
        ASSERT_NE(vault1, nullptr);
        ASSERT_TRUE(vault1->storeSecret(key, secret1));
    }

    {
        auto vault2 = SafeKeeping::create("Namespace2", vault);
        ASSERT_NE(vault2, nullptr);
        ASSERT_TRUE(vault2->storeSecret(key, secret2));
    }

    {
        auto vault1 = SafeKeeping::create("Namespace1", vault);
        ASSERT_NE(vault1, nullptr);
        // Verify vault1 retrieves its own secret
        auto retrieved1 = vault1->retrieveSecret(key);
        ASSERT_TRUE(retrieved1.has_value());
        EXPECT_EQ(retrieved1.value(), secret1);
    }

    {
        auto vault2 = SafeKeeping::create("Namespace2", vault);
        ASSERT_NE(vault2, nullptr);
        ASSERT_TRUE(vault2->storeSecret(key, secret2));

        // Verify vault2 retrieves its own secret
        auto retrieved2 = vault2->retrieveSecret(key);
        ASSERT_TRUE(retrieved2.has_value());
        EXPECT_EQ(retrieved2.value(), secret2);

    }


    // Cleanup
    {
        auto vault1 = SafeKeeping::create("Namespace1", vault);
        vault1->removeSecret(key);
    }

    {
        auto vault2 = SafeKeeping::create("Namespace2", vault);
        vault2->removeSecret(key);
    }
}

// Test removing a secret with description
TEST_F(TestVault, RemoveSecretWithDescription) {
    std::string key = "remove_me";
    std::string secret = "TemporarySecret";
    std::string description = "Temporary Description";

    storeAndTrackSecretWithDescription(key, secret, description);
    ASSERT_TRUE(safeKeeping->removeSecret(key));

    auto retrieved = safeKeeping->retrieveSecret(key);
    EXPECT_FALSE(retrieved.has_value());

    auto secrets = safeKeeping->listSecrets();
    EXPECT_TRUE(secrets.empty());

    storedKeys.erase(key);
}

