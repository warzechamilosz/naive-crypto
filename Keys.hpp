#pragma once
#include "Poco/Crypto/RSAKey.h"
#include "Poco/Crypto/RSADigestEngine.h"

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

    Signature sign(std::string msg, const Key& key)
    {
        Poco::Crypto::RSADigestEngine eng(key, "SHA256");
        eng.update(msg.c_str());
        return eng.signature();
    }

    bool verifySignature(std::string msg, const Signature& sig, const Key& key)
    {
        Poco::Crypto::RSADigestEngine eng(key, "SHA256");
		eng.update(msg.c_str());
        return eng.verify(sig);
    }
}