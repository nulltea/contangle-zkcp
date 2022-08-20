# Contangle

This project provides a suite of cryptographic and networking components for enabling efficient zero-knowledge contingent payments (ZKCP).

ZKCP is a transaction protocol that was first proposed by [Gregory Maxwell](https://github.com/gmaxwell) as a means of making conditional payments on the Bitcoin network. More specifically, it allows a buyer to purchase information from a seller in a manner that is private, fair and doesn’t require trusting anyone: the expected information is transferred if and _only_ if the payment is made.

ZKCP was [first](https://bitcoincore.org/en/2016/02/26/zero-knowledge-contingent-payments-announcement/) put into use to buy solved Sudoku for 0.10 BTC. Since then the underlying cryptography matured and thereby the idea of fully trust-less conditional payments become much more practical.

The innovation of `Contangle` goes from employing multiple novel cryptographic protocols such as Adaptor Signatures \[[Fourn'19](https://github.com/LLFourn/one-time-VES/blob/master/main.pdf), [EEE'20](https://eprint.iacr.org/2020/845)\] for scriptless conditional payments, Recursive ZK-SNARKs \[[BCTV'14](https://eprint.iacr.org/2019/1021.pdf)\] for efficient proofs generation without trusted setup \[[BGH'19](https://eprint.iacr.org/2019/1021.pdf)\], which proved to be especially problematic in the context of real-world ZKCP protocols \[[CGGN'17](https://eprint.iacr.org/2017/566)\].


## Protocol
The high-level flow of ZKCP protocol is as such:
1. Alice generates a key pair $(sk, pk)$ and encrypts data with public key inside a ZK circuit to generate Proof of Encryption (*PoE*) and Proof(s) of Property (*PoPRP*). She then sends proofs, and ciphertext to Bob.
2. Bob verifies given proofs and signs transaction $tx$ that transfers coins to Alice’s address
3. Bob sends $tx$ into a special fair-exchange channel $C_{FE}$. Alice sends decryption key into $C_{FE}$. Channel ensures that either both parties receive desired or no one at all.
4. Bob uses $sk$ and decrypt purchased data from the ciphertext, while Alice broadcasts signed transaction $tx$ on Bob's behalf, thereby gets paid.

Please see the [protocol documentation](/blob/master/docs/protocol.md) for more details on how Contangle implements the framework above.

## License
MIT
