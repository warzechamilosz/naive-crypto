#pragma once
#include <Poco/Crypto/RSAKey.h>
#include <Poco/Crypto/RSADigestEngine.h>

namespace Signatures
{
    using Key = Poco::Crypto::RSAKey;
    using Signature = Poco::DigestEngine::Digest;

    Key generateKeyPair()
    {
        return {Key::KL_1024, Key::EXP_SMALL};
    }

    std::pair<std::string, std::string> extractKeys(const Key& key, std::string pwd)
    {
        std::ostringstream strPub;
        std::ostringstream strPriv;
        key.save(&strPub, &strPriv, std::move(pwd));
        return {strPub.str(), strPriv.str()};
    }

    std::string getPublicKey(const Key& key)
    {
        std::ostringstream strPub;
		key.save(&strPub);
        return strPub.str();
    }

    template <typename Message>
    Signature sign(Message msg, const Key& key)
    {
        Poco::Crypto::RSADigestEngine eng(key, "SHA256");
        eng.update(msg.data(), msg.size());
        return eng.signature();
    }

    template <typename Message>
    bool verifySignature(const Message& msg, const Signature& sig, const Key& key)
    {
        Poco::Crypto::RSADigestEngine eng(key, "SHA256");
		eng.update(msg.data(), msg.size());
        return eng.verify(sig);
    }

    template <typename Message>
    bool verifySignature(const Message& msg, const Signature& sig, const std::string& pubKeyString)
    {
        std::istringstream ss(pubKeyString);
        auto key = Key(&ss);
        Poco::Crypto::RSADigestEngine eng(key, "SHA256");
		eng.update(msg.data(), msg.size());
        return eng.verify(sig);
    }
}