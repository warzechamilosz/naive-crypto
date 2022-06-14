#pragma once
#include "Hash.hpp"
#include "Keys.hpp"

struct TxSource
{
    TxSource(const Signatures::Key& key, unsigned amount)
    : sourcePublicAddress_(Signatures::getPublicKey(key))
    , amount_(amount)
    {
    }

    std::string sourcePublicAddress_;
    unsigned amount_;

    Hash calculateSrcHash() const
    {
        Poco::Crypto::DigestEngine eng("SHA256");
		eng.update(sourcePublicAddress_);
		eng.update(amount_);
		return eng.digest();
    }
};

struct TxDestination
{
    TxDestination(const Signatures::Key& key, unsigned amount)
    : destinationPublicAddress_(Signatures::getPublicKey(key))
    , amount_(amount)
    {
    }

    std::string destinationPublicAddress_;
    unsigned amount_;

    Hash calculateDestHash() const
    {
        Poco::Crypto::DigestEngine eng("SHA256");
		eng.update(destinationPublicAddress_);
		eng.update(amount_);
		return eng.digest();
    }
};

class Tx
{
public:
    void addInput(TxSource txSource)
    {
        from_.emplace_back(std::move(txSource));
    }

    void addOutput(TxDestination txDestination)
    {
        to_.emplace_back(std::move(txDestination));
    }

	Hash calculateTxHash() const
    {
		Poco::Crypto::DigestEngine eng("SHA256");
		for (const auto& src : from_)
        {
            auto sourceHash = src.calculateSrcHash();
			eng.update(sourceHash.data(), sourceHash.size());
        }
		for (const auto& dest : to_)
        {
            auto destHash = dest.calculateDestHash();
			eng.update(destHash.data(), destHash.size());
        }
		return eng.digest();
    }

    void sign(const Signatures::Key& key)
    {
        sigs_.emplace_back(Signatures::sign(calculateTxHash(), key));
    }

    bool isValid() const
    {
        auto msg = calculateTxHash();
        bool signatureFound = false;
        for (const auto& src : from_)
        {
            for (const auto& s : sigs_)
                if (Signatures::verifySignature(msg, s, src.sourcePublicAddress_))
                    signatureFound = true;
            if (not signatureFound)
                return false;
        }
        return true;
    }

    const std::vector<TxSource>& getSourceTxs() const
    {
        return from_;
    }

    const std::vector<TxDestination>& getDestinationTxs() const
    {
        return to_;
    }

private:
	std::vector<TxSource> from_;
	std::vector<TxDestination> to_;
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

    void addTx(const Tx& tx)
    {
        txs_.emplace_back(tx);
    }

    std::pair<unsigned, unsigned> getTotalInputAndOutput()
    {
        unsigned totalInput = 0;
        unsigned totalOutput = 0;
        for (const auto& tx : txs_)
        {
            for (const auto& srcTx : tx.getSourceTxs())
            {
                totalInput += srcTx.amount_;
            }
            for (const auto& dstTx : tx.getDestinationTxs())
            {
                totalOutput += dstTx.amount_;
            }
        }
        return {totalInput, totalOutput};
    }

    bool isValid()
    {
        for (const auto& tx : txs_)
        {
            if (not tx.isValid())
                return false;
        }
        const auto& [in, out] = getTotalInputAndOutput();
        if (out > in)
            return false;
        return true;
    }

	Hash calculateBlockHash()
    {
        Poco::Crypto::DigestEngine eng("SHA256");
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