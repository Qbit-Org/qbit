// Copyright (c) 2013-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <clientversion.h>
#include <key.h>
#include <key_io.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <string>
#include <vector>

namespace {

struct TestDerivation {
    std::string pub;
    std::string prv;
    unsigned int nChild;
};

struct TestVector {
    std::string strHexMaster;
    std::vector<TestDerivation> vDerive;

    explicit TestVector(std::string strHexMasterIn) : strHexMaster(strHexMasterIn) {}

    TestVector& operator()(std::string pub, std::string prv, unsigned int nChild) {
        vDerive.emplace_back();
        TestDerivation &der = vDerive.back();
        der.pub = pub;
        der.prv = prv;
        der.nChild = nChild;
        return *this;
    }
};

TestVector test1 =
  TestVector("000102030405060708090a0b0c0d0e0f")
    ("qpubUjHa4QkoifBNKm3pxSkvxMfTgUAk22ejcTodZSnYMzHTMG2F5E4iwBKsPABX1Hs9iiPebYSEeFPSPFPXRipojaEFCcduSMKmvbbTTAX7s4c",
     "qprvYWJDeuDutHd57GyMrRDvbDij8SLFcZvtFEt2m4NvoekUUTh6XgkUPP1PXtYDVQT5oBVi6bR5zx38ajCP8UzA7YEAQuugGppBAUziQrwLPSZ",
     0x80000000)
    ("qpubUmYz484GovJMUNBYACdZqPma1Hj6Q78kJ5EXXYAfLBUjiYKRVTbp4KgHARkDkbmgivgDTmyfNtTXMeMfNkZBoTgyQFSAMfDzSXj1knYxGEs",
     "qprvYYZdecXNyYk4Ft754B6ZUFpqTFtbzeQtvrJvj9m3mqwkqjzGwvHZWXMoK9tYu7q3WEPQTtjxPJt1JVE6n5GLucJgUnapWnX4sVdZr3oCsZT",
     1)
    ("qpubUoj7FucACdBRJpDytTXSS8fE4fiCQ8s3EPuN7owUGpGwx5pZDG281taWaWCoAYV2geJGFCRmVUwzwx6Ur5j5V7WuhTH1qJEG5GFo3jaNtQy",
     "qprvYajkrQ5GNFd86L9WnRzS4ziVWdshzg9BsAymKRXriUjy5HVQfihsU6G2jD5cW3c5xK96GiLPU1qRSRkKuR4Kgmo7zZYYaYHvYHwwNy3sjYs",
     0x80000002)
    ("qpubUrLPJSS1uW2qAz2593voo8hNHpaifgT2Zw93N9EdSgePMw1g21rYvL8S8XPdcQvM3APzraQNsRWyQHEmZBGcYZfkHMF9vFHwnxAw93z4VSx",
     "qprvYdM2tvu858UXxVwc32PoRzkdjnkEGDjBCiDSZkq1tM7QV8gXUUYJNXoxHFJEUH7aTnAUsBHJtRfKfdV5VRyWosEnMB76jUXs9ZhA1VLNrT6",
     2)
    ("qpubUtZn8sYy5yhpFTVnqK8tgdrgNdsTJGmE1R2Ld6m6m8Czj2e35nYv7ubMorP22D55WUXAzatKvAR5xhameUhpGA91C8oLkSBmoe5nHgDCZdX",
     "qprvYfaRjN25Fc9X2yRKjHbtKVuwpc2xtp3NeC6jpiMVCng1rEJtYFEfa7GsxZhgvwX1XaJBV6WsoF7V8pPXgrWs1FppkRCCHZMaJYAKX596qYH",
     1000000000)
    ("qpubUvHYcZADD761moHEwrhczLrgAsSm7maFofQtsP9EyCbVSA3RcCoaP1kRSgHxsU9nzAoiVvp8TN7gZ7ynkLCf7RJ84gDRYumQcbhhXkxE4ou",
     "qprvYhJCD3dKNjXiZKCmqqAcdCuwcqcGiJrQSSVJ4zjdQs4WZMiH4fVKqDRwbRUtqre68yhSGTVpeHec8zPuDvXb8DUN5uxRQU7HasigGCLVYxS",
     0);

TestVector test2 =
  TestVector("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
    ("qpubUjHa4QkoifBNKNZA4bqDQZPDvfKAheuZJ3bMrPXNLNQKeF3SFNqfN5VTjGGViYE7dGdSWD6Q3Kth737kYujxsVEC4YqNGqpSEyGZj8tF8H7",
     "qprvYWJDeuDutHd56tUgxaJD3RSVNdUgJCBhvpfm417kn2sLmSiHhqXQpHAysxKGfv1B3EF8qssYH45KgFvVAuNriuYvsKyvRAiujjcwmmaW7KU",
     0)
    ("qpubUnZKL8SmCg1Sqe9TCPD6UMnkHd4RQdPqrDLj2CYpQnGHLDVQpeBjWv4iJjEPWdEYqb7cNS69SQjfGCYSS4SPD5tULba3BBxpNTPEAJfTDvD",
     "qprvYZZxvcusNJT9dA4z6Mg67Dr1jbDw1AfzUzR8Dp9CrSjJTRAGH6sUy7kETTb5Jyr1StUxjtHGiDVT2mZJjBsuf8iKsWPyoetes9XW95rJfyd",
     0xFFFFFFFF)
    ("qpubUoiNajUHaaBZ1WMdcqCjwhUJgNHKx7ZXwNRFwbTb4X2fnWisSXc3iyrJv7UWGMqed73A2GwkjdAFvsQnCxvVwEM6sgC6XvDqEqeq15k661D",
     "qprvYaj2BDwPkCdFo2HAWofjaZXa8LSqYeqga9Vf9D3yWBVguiPitzHoBBXq4p543EaVM7orWuUumDzZU1J5TZV3ES9tJEdKaAcuevs2uVtqzRm",
     1)
    ("qpubUrXLzkTDkDUk782mgVMJueQY1u9q4JUoFov7nf7vNQP7TLb2k38kctEgkufe4EXwDHVhrv2zNkU61ffo7sMTCZp1TxPwkTf3AcKnFYEL9SU",
     "qprvYdXzbEvKuqvStdxJaTpJYWToTsKLeqkwtazWzGiJp4r8aYFtCVpW55vCucGg4wnBf5AZGCZJAmfmni5EWT1REuyBS1A8RGbJ8jHmPDEDdjK",
     0xFFFFFFFE)
    ("qpubUshNuiPaMcSTQ5GNQyArHA6ivddC7H7JHWe1KNpLDAeMuguxqi4m9QbnPZo9Fc4PAj9LfR6hRMnwfJqBokTxuvWTjriSJkkT2qQMnVc6LKM",
     "qprvYei2WCrgXEtABbBuJwdqv29zNbnhhpPSvHiQWzQieq7P2tapJAkWbcHJYK14hNAUCeTFa2LHZ9FMbqAc2PuuvkeMFwhSZUcvUKJHSti2fgp",
     2)
    ("qpubUu4Qs9c5snkh9LTG93JYFuUhKhAJMc2NwgFtjAApqxVwytFY1LzXKyYnTxsRPBR5gnMZwLc7K4ow9jtgdr9sEBN3P2YXF83Bi8bYT6puNrf",
     "qprvYg54Te5C3RCPvrNo31mXtmXxmfKox9JXaTLHvmmDHcxy75vPTogGnBEJcig4rPFYExJyrmy71F63eP47kiH8yjP54oCwctkeAgdqXY7aRTC",
     0);

TestVector test3 =
  TestVector("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")
    ("qpubUjHa4QkoifBNJS1KazL1cYeFoJeGTX4q1PMvFgYvc4V7cVGhuX5dKLizDFoUY8okoMPJLCyQRziYYLkfPcnQHptLBnjb1QGH2gnGFcNZzSc",
     "qprvYWJDeuDutHd55wvrUxo1FQhXFGon44LyeASKTJ9K3ix8jgwZMymNmYQWMx3ScwEW7vutQoZeBUp32uXoQLXHWP4BPcYZcc4t2THJRn1zPA5",
      0x80000000)
    ("qpubUmemoNawQ2YiVy6ip8fWfoPvVfFecNUjQsbs4vEmYNQUsWQAV1rVPoWhWydzGVQVzit97Aj9Gwv3Aoh1Krias5AGrtgUZFm5Ws9AuxW2WD6",
     "qprvYYfRPs43ZezRHV2Fi78WJfTBwdRACukt3egGGXq9z2sVzi51wUYEr1CDfiPnxtZRa5ZJRkMWqDSVgTAwyZ73G9FopkTcMmLh9UExP6efUpe",
      0);

TestVector test4 =
  TestVector("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678")
    ("qpubUjHa4QkoifBNLVWtRigpRJ79RYESNmUaFX4KdREWUbKoTP637RgPXZH5uP49ZaPpNtWrUtCbNmVHMDXnopoKNgkExD2fZiE5wHTVLPLEzVH",
     "qprvYWJDeuDutHd581SRKh9p4AAQsWPwyJkitJ8iq2ptvFnpaaktZtN8ykxc47KZdfdghPsWWzSn7p1ofvA64RnCbCiZtrQbfUxYJb9TBuGaxF1",
     0x80000000)
    ("qpubUnSgSnsU6RHoyNY243cbRhCusU7i6517zpfyyPQV83Pmwv99fm77fbxS4yKubCkwnzHDRvbCyhRXt9DrWcFiTzoGzXTdSXKTz61Y8nfpAYw",
     "qprvYZTL3HLaG3jWktTYx25b4ZGBKSHDgcHGdbkPAzzsZhro57p18Dns7odxDfEogUp3fNtx3Zd1SG7tcaMBfoSqbqbVkEiGsQQYHrBFvpLbLuo",
     0x80000001)
    ("qpubUpaN6nGUc9LQeXPfCKXVXZnm3QHnazhvekiok8vgnEVDj1TfYFaptivJxv6SSPPdNmtaKhXKS9mWrdYkyD4sBHjeLKJgQFoQrWNSCNBgTSW",
     "qprvYbb1hGjammn7S3KC6HzVARr2VNTJBXz5HXoCwkX5DtxErD8WziGaLvbq7dCtjsqsk9J4EASyCuDmKYAu4jPxtE4izaRHySes9Xix2LYR5Na",
     0);

const std::vector<std::string> TEST5 = {
    "qpubUjHa4QkoifBNJQxHTUQj6h7riPZAnRT8CjPJ7YqVsvisE9kmpaj8YLBevUE6kACuT8DjCFQ5qAixWyhpihBNJjm1JHiDA24D3pdXtMBJKid", // pubkey version / prvkey mismatch
    "qprvYWJDeuDutHd55vspMSsijZB8AMigNxjGqWThKARtKbBtMMRdH3QszXsB5QVgyFAwbyTmoBnbdjBQRQxEMFXsGTV3D5Pn5WKBwHHC82rwBaz", // prvkey version / pubkey mismatch
    "qpubUjHa4QkoifBNJQxHTUQj6h7riPZAnRT8CjPJ7YqVsvisE9kmpaj8YLBevc15T612rpvdjXiuTVCxLG6vP9eEuZ8WSqze8coo2Sf5rreVAa6", // invalid pubkey prefix 04
    "qprvYWJDeuDutHd55vspMSsijZB8AMigNxjGqWThKARtKbBtMMRdH3QszXsB5QroMurST6Udq5bynjTVipZ8VV9h9hYLvqgGHHzk6amr6ou9T5n", // invalid prvkey prefix 04
    "qpubUjHa4QkoifBNJQxHTUQj6h7riPZAnRT8CjPJ7YqVsvisE9kmpaj8YLBevWAqvPewJYtxL4ynjkLxUJJbdoo5xSbt5vnKQAk73UdvP4eb9iV", // invalid pubkey prefix 01
    "qprvYWJDeuDutHd55vspMSsijZB8AMigNxjGqWThKARtKbBtMMRdH3QszXsB5K2ZqDWLtpSxRcrs4zbVrrkok9JYCb1iZvTwYqw47ckgcxPJsxe", // invalid prvkey prefix 01
    "qprvYWJeUdi1HP5NA8yk1i8muzbMinbB8FTRKnWn1YUBT4orYgZ3QMjYSyzEVqbdkqPMfykFbUZAUWY7tWchcqDMdh4mEJ8pLo8R2jS1tnwjS6i", // zero depth with non-zero parent fingerprint
    "qpubUjHzt9Eu7kdfNd4D7jfnH8Y6GpRfXiBGh1SNovso1QLqRUtBwu3nznJiMA9nAGeaeHtJ1KBXcaVV1pxh2iYx77y8B6T8xw1Vmur9eTSmAWv", // zero depth with non-zero parent fingerprint
    "qprvYWJDeuDux5eDwas5VhRE1LrjbDLEup9qED8D5bYhpwEnYWEjcGc8aDuQoU68SFinZHxKNCtHB3jS4DRZai1ZPVe4a8yMQcJq9mzTaxvMr58", // zero depth with non-zero index
    "qpubUjHa4QkonTCXA4wYbixENUoU9FAjKGsgbS3osyxKPGmmRJZt9ovP82DteneGqgz1Xc6Mn3WeK7goBXmYzbM9rvYRWwHg2kButxQbLkTVfQt", // zero depth with non-zero index
    "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4", // unknown extended key version
    "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9", // unknown extended key version
    "qprvYWJDeuDutHd55vspMSsijZB8AMigNxjGqWThKARtKbBtMMRdH3QszXsB5H5pez4K3PmjHoHAAQyVuYA2q2gpYtAqnHPqJhFA7xkJ6yx4W6k", // private key 0 not in 1..n-1
    "qprvYWJDeuDutHd55vspMSsijZB8AMigNxjGqWThKARtKbBtMMRdH3QszXsB5K2ZqDWLtpSxRcrs4zbVrrkjDGwdfZkw7DCxHzDjRKjJqBB3A5R", // private key n not in 1..n-1
    "qpubUjHa4QkoifBNJQxHTUQj6h7riPZAnRT8CjPJ7YqVsvisE9kmpaj8YLBevY7b6d6y9yaBTtZVeKxxRcuNYvQoc9SksZrReKS138eJs8TGg8o", // invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007
    "qprvYWJDeuDutHd57GyMrRDvbDij8SLFcZvtFEt2m4NvoekUUTh6XgkUPP1PXtYDVQT5oBVi6bR5zx38ajCP8UzA7YEAQuugGppBAUziQrwLPSa", // invalid checksum
};

void RunTest(const TestVector& test)
{
    std::vector<std::byte> seed{ParseHex<std::byte>(test.strHexMaster)};
    CExtKey key;
    CExtPubKey pubkey;
    key.SetSeed(seed);
    pubkey = key.Neuter();
    for (const TestDerivation &derive : test.vDerive) {
        unsigned char data[74];
        key.Encode(data);
        pubkey.Encode(data);

        // Test private key
        BOOST_CHECK(EncodeExtKey(key) == derive.prv);
        BOOST_CHECK(DecodeExtKey(derive.prv) == key); //ensure a base58 decoded key also matches

        // Test public key
        BOOST_CHECK(EncodeExtPubKey(pubkey) == derive.pub);
        BOOST_CHECK(DecodeExtPubKey(derive.pub) == pubkey); //ensure a base58 decoded pubkey also matches

        // Derive new keys
        CExtKey keyNew;
        BOOST_CHECK(key.Derive(keyNew, derive.nChild));
        CExtPubKey pubkeyNew = keyNew.Neuter();
        if (!(derive.nChild & 0x80000000)) {
            // Compare with public derivation
            CExtPubKey pubkeyNew2;
            BOOST_CHECK(pubkey.Derive(pubkeyNew2, derive.nChild));
            BOOST_CHECK(pubkeyNew == pubkeyNew2);
        }
        key = keyNew;
        pubkey = pubkeyNew;
    }
}

}  // namespace

BOOST_FIXTURE_TEST_SUITE(bip32_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bip32_test1) {
    RunTest(test1);
}

BOOST_AUTO_TEST_CASE(bip32_test2) {
    RunTest(test2);
}

BOOST_AUTO_TEST_CASE(bip32_test3) {
    RunTest(test3);
}

BOOST_AUTO_TEST_CASE(bip32_test4) {
    RunTest(test4);
}

BOOST_AUTO_TEST_CASE(bip32_test5) {
    for (const auto& str : TEST5) {
        auto dec_extkey = DecodeExtKey(str);
        auto dec_extpubkey = DecodeExtPubKey(str);
        BOOST_CHECK_MESSAGE(!dec_extkey.key.IsValid(), "Decoding '" + str + "' as xprv should fail");
        BOOST_CHECK_MESSAGE(!dec_extpubkey.pubkey.IsValid(), "Decoding '" + str + "' as xpub should fail");
    }
}

BOOST_AUTO_TEST_CASE(bip32_max_depth) {
    CExtKey key_parent{DecodeExtKey(test1.vDerive[0].prv)}, key_child;
    CExtPubKey pubkey_parent{DecodeExtPubKey(test1.vDerive[0].pub)}, pubkey_child;

    // We can derive up to the 255th depth..
    for (auto i = 0; i++ < 255;) {
        BOOST_CHECK(key_parent.Derive(key_child, 0));
        std::swap(key_parent, key_child);
        BOOST_CHECK(pubkey_parent.Derive(pubkey_child, 0));
        std::swap(pubkey_parent, pubkey_child);
    }

    // But trying to derive a non-existent 256th depth will fail!
    BOOST_CHECK(key_parent.nDepth == 255 && pubkey_parent.nDepth == 255);
    BOOST_CHECK(!key_parent.Derive(key_child, 0));
    BOOST_CHECK(!pubkey_parent.Derive(pubkey_child, 0));
}

BOOST_AUTO_TEST_SUITE_END()
