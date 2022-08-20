# Protocol
Alice (seller) has a digital good and she wants to exchange it for some digital currency (ETH, BTC, etc). Bob (buyer) has that digital currency and wishes to buy that what Alice sells for it.

Bob doesn't trust Alice claiming the quality of item and wether she gets access to it before he makes the payment. At the same time, Alice doesn't trust Bob to pay before she reveals digital good to him.

They come to an agreement to do the exchange.

## Proof of Encryption
For the Proof of Encryption we introduce two circuits:
- `ElGamalCircuit` implements an [ElGamal](http://wwwmayr.in.tum.de/konferenzen/Jass05/courses/1/papers/meier_paper.pdf) asymmetric encryption scheme using elliptic curve group elements and SNARK-friendly hash function (Poseidon Sponge).
  - It proves that the public `ciphertext_block` is an encryption of the private `plaintext_block` over the `public_key` and private `randomness` signals.
  - Many such proofs can be computed in parallel for each of the $n$ blocks of the message.
- `EncryptionAggregatorCircuit` recursively aggregates an arbitrary number of proofs generated from `ElGamalCircuit` target circuit.

## Fair Exchange
An exchange protocol allows two or more parties to exchange items. It is fair when the exchange channel guarantees that either all parties receive their desired items or none of them receives any item.

> In the current version, library cares only about the two-party exchange, but the multi-party variant should be possible too.

Library provides two implementations for this abstraction. First being a scriptless channel based on Adaptor signatures. This one best suits UTXO chains like Bitcoin, but has some fundamental flaws on the account-based blockchains. We will discuss those in the section bellow.


### Adaptor signatures
Adaptor Signatures were discovered by [Andrew Poelstra](https://github.com/apoelstra) and were quickly adopted by the Bitcoin community as a means of achieving "scriptless scripts" - a way of encoding rules by arranging cryptography primitives rather than relying on high-level scripting languages.

When an encrypted signature (adaptor) - owned by one party - is combined with a decrypted signature - revealed by another party - they yield some secret value and the computation can carry on. In this context, the buyer can reveal a signed payment transaction and be sure that once it appears on-chain they will recover a decryption key for bought data.

The original proposal that introduces adaptor signatures is available here: https://hackmd.io/@timofey/ryqirvjdq

### Hash-lock Contract
Second is classical and uses hash-lock contract needed to be implemented in the high-level scripting language inherent for its target network (eg. Solidity).
