#include <iostream>
#include <vector>

#include <Poco/Hash.h>
#include "Poco/Crypto/RSADigestEngine.h"
#include "Poco/Crypto/CipherFactory.h"
#include "Poco/Crypto/Cipher.h"
#include <Poco/Net/SocketStream.h>
#include <Poco/Net/TCPServerConnection.h>

#include "Keys.hpp"
#include "Hash.hpp"
#include "Transactions.hpp"

class MinerServer: public Poco::Net::TCPServerConnection
{
public:
	MinerServer(const Poco::Net::StreamSocket& s): TCPServerConnection(s)
	{
	}
	
	void run()
	{
		Poco::Net::StreamSocket& ss = socket();
		try
		{
			char buffer[256];
			int n = ss.receiveBytes(buffer, sizeof(buffer));
			while (n > 0)
			{
				ss.sendBytes(buffer, n);
				n = ss.receiveBytes(buffer, sizeof(buffer));
			}
		}
		catch (Poco::Exception& exc)
		{
			std::cerr << "MinerServer error: " << exc.displayText() << std::endl;
		}
	}
};

int main()
{
    Poco::Crypto::RSAKey key = Signatures::generateKeyPair();
	std::ostringstream strPub;
	std::ostringstream strPriv;
	key.save(&strPub, &strPriv, "testpwd");
	auto [pubKey, privKey] = Signatures::extractKeys(key, "testpwd");

	// generate keys test
	{	
		std::istringstream iPriv(privKey);
		Poco::Crypto::RSAKey key(0, &iPriv,  "testpwd");
		std::ostringstream strPub;
		key.save(&strPub);
		std::string pubFromPrivate = strPub.str();
		std::cout << "generate keys result: " << std::boolalpha << (pubFromPrivate == pubKey) << "\n";
	}
	
	// sign message test
	{
		std::string msg("Test this sign message");
		auto sig = Signatures::sign(msg, key);
		std::ostringstream strPub;
		key.save(&strPub);
		std::string pubKey = strPub.str();
		std::istringstream iPub(pubKey);
		Poco::Crypto::RSAKey keyPub(&iPub);
		std::cout << "sign message result: " << 
			std::boolalpha << Signatures::verifySignature(msg, sig, keyPub) << "\n";
	}

	// test hashing
	{
		auto tx1 = Tx("Ross", "Chandler", 10);
		auto tx2 = Tx("Chandler", "Monica", 5);
		auto txBlock1 = TxBlock(nullptr);

		auto tx3 = Tx("Ross", "Joey", 2);
		auto tx4 = Tx("Rachel", "Ross", 5);
		auto txBlock2 = TxBlock(&txBlock1);

		
	}

    return 0;
}