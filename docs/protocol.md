# Protocol
Alice (seller) has a digital good and she wants to exchange it for some digital currency (ETH, BTC, etc). Bob (buyer) has that digital currency and wishes to buy that what's Alice sells for it.

Bob does not want to trust Alice about the item she claims to sell and whether she provides him access to it after he makes the payment. At the same time, Alice does not want trusting Bob to pay before she reveals digital good to him.

They come to an agreement to do the exchange.

## Fair Exchange
An exchange protocol allows two or more parties to exchange items. It is fair when the exchange channel guarantees that either all parties receive their desired items or none of them receives any item.

> In the current version, library cares only about the 2-party exchange, but the multi-party variant should be possible too.

Library provides two implementations for this abstraction:

### Adaptor signatures
Adaptor Signatures were discovered by [Andrew Poelstra](https://github.com/apoelstra) and were quickly adopted by the Bitcoin community as a means of achieving "scriptless scripts" - a way of encoding rules by arranging cryptography primitives rather than relying on high-level scripting languages.

When an encrypted signature (adaptor) - owned by one party - is combined with a decrypted signature - revealed by another party - they yield some secret value and the computation can carry on. In this context, the buyer can reveal a signed payment transaction and be sure that once it appears on-chain they will recover a decryption key for the purchased data.

The updated flow for adaptor signature facilitated contingent payment channel is as follows:
1. Alice generates a key pair $(sk, pk)$ and encrypts data with $pk$ inside the circuit to generate Proof of Encryption (*PoE*) and Proof(s) of Property (*PoPRP*). She then sends proofs, and ciphertext to Bob.
2. Bob verifies given proofs and signs the transaction $tx$ that transfers coins to Alice’s address and encrypts it with $pk$.
3. Alice decrypts this signature and publishes it on-chain, thereby gets paid.
4. Due to the one-time property of the VES, Bob is able to recover $sk$ and decrypt desired data from the ciphertext.

> The original proposal that introduces adaptor signatures is available here: https://hackmd.io/@timofey/ryqirvjdq

#### Front-running attack
This method suits well for the UTXO chains, like Bitcoin, but has some fundamental flaws on the account-based blockchains, like Ethereum. Namely, the buyer can front-run seller broadcasting signed transaction to the network, by publishing tx with same nonce shortly before. If seller miss noticing this and broadcast decrypted signature anyway, the buyer can grab failed tx from mempool and decrypt data they never paid for, thereby breaking fairness guarantee of our channel abstraction.

As a mitigation we require setting up a shared account $S^{ab}$ based on the 2P-ECDSA public key $pk$ controlled by two shares $sk_a$ and $sk_b$ owned independently by each party. Bob will transfer funds into $S^{ab}$ and parties will together generate pre-signature for the $tx$. This seemingly redundant step prevents Bob from front-running Alice, since there's no way to sign a malicious tx other than by agreement of both parties.

We efficiently instantiate joint adaptor signing for Schnorr and ECDSA with the protocols from [\[1\]](https://eprint.iacr.org/2018/472). Based on the observations from [\[2\]](https://eprint.iacr.org/2021/1612) joint pre-signature generation for Schnorr requires 4.85 ms, while that for ECDSA requires 266.30 ms.

#### DOS/griefing attack
However, since 2PC does not guarantee output delivery, funds deposited to shared account potentially can become permanently locked if any party aborts early, e.g. if Alice will change her mind and go offline never submitting the adapted signature. This isn't a useful attack, rather a form of griefing, but it can discourage honest users from using Contangle, so should be seen as a potential DOS attack vector.

This problem is common to atomic swaps and can be solved with Hash Time Lock Contract (HTLC) script. However, to make our scheme universal it should remain scriptless, so instead we simulate HTLC with can simulate verifiable timed signatures (VTS) [\[3\]](https://dl.acm.org/doi/10.1145/3372297.3417263). A VTS lets one to generate a timed commitment $C$ of a signature $\sigma$ that can be opened after the time $T$. At the same time, the committer also generates a proof $\pi$ that proves that the commitment $C$ contains a valid signature $\sigma$.

We can go even further and instead of VTS generate commitments to a secret share $sk_{a|b}$ via a verifiable timed discrete logarithm (VDT) scheme [\[3\]](https://dl.acm.org/doi/10.1145/3372297.3417263), which is far more efficient than the VTS for Schnorr/ECDSA in terms of commitment generation and verification due to its algebraic simplicity. According to [\[3\]](https://dl.acm.org/doi/10.1145/3372297.3417263), a ECDSA-VTS requires approximately 7 seconds for the generate and 10 seconds for verify with a statistical parameter $n=30$, whereas VTD requires only below 0.04 seconds.

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
