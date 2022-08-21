# Protocol
Alice (seller) has a digital good and she wants to exchange it for some digital currency (ETH, BTC, etc). Bob (buyer) has that digital currency and wishes to buy that what's Alice sells for it.

Bob does not want to trust Alice about the item she claims to sell and wether she provides him access to it after he makes the payment. At the same time, Alice does not want trusting Bob to pay before she reveals digital good to him.

They come to an agreement to do the exchange.

## Fair Exchange
An exchange protocol allows two or more parties to exchange items. It is fair when the exchange channel guarantees that either all parties receive their desired items or none of them receives any item.

> In the current version, library cares only about the 2-party exchange, but the multi-party variant should be possible too.

Library provides two implementations for this abstraction:

### Adaptor signatures
Adaptor Signatures were discovered by [Andrew Poelstra](https://github.com/apoelstra) and were quickly adopted by the Bitcoin community as a means of achieving "scriptless scripts" - a way of encoding rules by arranging cryptography primitives rather than relying on high-level scripting languages.

When an encrypted signature (adaptor) - owned by one party - is combined with a decrypted signature - revealed by another party - they yield some secret value and the computation can carry on. In this context, the buyer can reveal a signed payment transaction and be sure that once it appears on-chain they will recover a decryption key for the purchased data.

> The original proposal that introduces adaptor signatures is available here: https://hackmd.io/@timofey/ryqirvjdq

This method suits best for the UTXO chains, like Bitcoin, but has some fundamental flaws on the account-based blockchains. Namely, the buyer can front-run seller broadcasting signed transaction to the network, by publishing tx with same nonce shortly before. If seller miss noticing this and broadcast decrypted signature anyway, the buyer can grab failed tx from mempool and decrypt data they never paid for, thereby breaking fairness guarantee of our channel abstraction.

### Hash-lock Contract
The second is a hash-lock smart contract that atomically releases buyer's payment only when the seller publishes the decryption key being a pre-image to the commitment stored in the contract.

This approach is limited to the network that support scripting, and needed to be implemented separately for each the high-level scripting language inherent for its target network (family) (eg. Solidity for EVM-based chains).

## Zero-Knowledge Proofs
While the FE channel can guarantee perfect fairness when exchanging funds for the key needed to decrypt known ciphertext, the seller can still cheat and encrypt any random bytes and claim this being the data buyer is interested in.

To remove trust in seller's honesty, we introduce two zero-knowledge proofs:

### Proof of Encryption
Our efficient verifiable encryption scheme consists from two circuits:
- `ElGamalCircuit` implements an [ElGamal](http://wwwmayr.in.tum.de/konferenzen/Jass05/courses/1/papers/meier_paper.pdf) asymmetric encryption scheme using elliptic curve group elements and SNARK-friendly hash function (Poseidon Sponge).
  - It proves that the public `ciphertext_block` is an encryption of the private `plaintext_block` over the `public_key` and private `randomness` signals.
  - Many such proofs (for each of the $n$ blocks) can be computed in parallel to massively reduce up prover time.
- `EncryptionAggregatorCircuit` recursively aggregates an arbitrary number of proofs generated from `ElGamalCircuit` target circuit.

> More detailed specification coming soon.

### Proof of Property
The purpose of this class of proofs is to assert that the data, going to be encrypted, has certain properties, in which buyer is interested in.

This is of course much more ambiguous, so initially we plan to support simpler proof of membership, that can be used to attest that the one or more sample entries is a subset of data being sold.

We are doing research to found a developer-friendly way to write own proofs. The best option so far is embedding Circom R1CS representation into the arkworks or halo2 circuits.

> More detailed specification coming soon.
