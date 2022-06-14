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

	// tx testing
	{
		const auto rossKey = Signatures::generateKeyPair();
		const auto chandlerKey = Signatures::generateKeyPair();
		const auto moniKey = Signatures::generateKeyPair();
		const auto joeyKey = Signatures::generateKeyPair();

		auto tx1 = Tx();
		tx1.addInput(TxSource{rossKey, 10});
		tx1.addOutput(TxDestination{chandlerKey, 10});
		tx1.sign(rossKey);
		std::cout << "tx1 valid: " << std::boolalpha << tx1.isValid() << "\n";

		auto tx2 = Tx();
		tx2.addInput(TxSource{moniKey, 12});
		tx2.addOutput(TxDestination{chandlerKey, 12});
		tx2.sign(moniKey);
		std::cout << "tx2 valid: " << std::boolalpha << tx2.isValid() << "\n";

		auto txBlock1 = TxBlock(nullptr);
		txBlock1.addTx(tx1);
		txBlock1.addTx(tx2);
		std::cout << "txBlock1 valid: " << std::boolalpha << txBlock1.isValid() << "\n";

		auto tx3 = Tx();
		tx3.addInput(TxSource{chandlerKey, 4});
		tx3.addOutput(TxDestination{joeyKey, 4});
		tx3.sign(chandlerKey);
		std::cout << "tx3 valid: " << std::boolalpha << tx3.isValid() << "\n";

		auto tx4 = Tx();
		tx4.addInput(TxSource{moniKey, 17});
		tx4.addOutput(TxDestination{rossKey, 17});
		tx4.sign(moniKey);
		std::cout << "tx4 valid: " << std::boolalpha << tx4.isValid() << "\n";

		auto txBlock2 = TxBlock(&txBlock1);
		txBlock1.addTx(tx3);
		txBlock1.addTx(tx4);
		std::cout << "txBlock2 valid: " << std::boolalpha << txBlock2.isValid() << "\n";

		auto invalidTx = Tx();
		invalidTx.addInput(TxSource{joeyKey, 2});
		invalidTx.addOutput(TxDestination{moniKey, 2});
		invalidTx.sign(chandlerKey);
		std::cout << "wrong signature detected: "
			<< std::boolalpha << (not invalidTx.isValid()) << "\n";

		auto invalidBlock = TxBlock(txBlock2);
		std::cout << "block valid before invalid tx: "
			<< std::boolalpha << invalidBlock.isValid() << "\n";
		invalidBlock.addTx(invalidTx);
		std::cout << "block invalid after invalid tx: "
			<< std::boolalpha << (not invalidBlock.isValid()) << "\n";
	}

    return 0;
}