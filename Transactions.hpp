#pragma once
#include "Hash.hpp"

class Tx
{
public:
	Tx(std::string from, std::string to, unsigned amount)
	: from_(from)
	, to_(to)
	, amount_(amount)
	{
	}

	Hash calculateTxHash() const
    {
		Poco::Crypto::RSADigestEngine eng(Signatures::generateKeyPair(), "SHA256");
		eng.update(from_);
		eng.update(to_);
		eng.update(std::to_string(amount_));
		return eng.digest();
    }

private:
	std::string from_;
	std::string to_;
	unsigned amount_;
	std::vector<Signatures::Signature> sigs_;
};

class TxBlock
{
public:
	TxBlock(TxBlock* previousBlock) : previousBlock_(previousBlock)
	{
		if (previousBlock_)
			previousHash_ = previousBlock_->calculateBlockHash();
	}

	Hash calculateBlockHash()
    {
        Poco::Crypto::RSADigestEngine eng(Signatures::generateKeyPair(), "SHA256");
        eng.update(previousHash_.data(), previousHash_.size());
        for (const auto& tx : txs_)
		{
			auto txHash = tx.calculateTxHash();
			eng.update(txHash.data(), txHash.size());
		}
        return eng.digest();
    }

	TxBlock* previousBlock_;
	Hash previousHash_;
private:
	std::vector<Tx> txs_{};
};