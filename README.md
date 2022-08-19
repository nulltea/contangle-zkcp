# Contangle

This project provides a suite of cryptographic and networking components for enabling efficient zero-knowledge contingent payments (ZKCP).

ZKCP is a transaction protocol that was first proposed by [Gregory Maxwell](https://github.com/gmaxwell) as a means of making conditional payments on the Bitcoin network. More specifically, it allows a buyer to purchase information from a seller in a manner that is private, fair and doesn’t require trusting anyone: the expected information is transferred if and _only_ if the payment is made.

ZKCP was [first](https://bitcoincore.org/en/2016/02/26/zero-knowledge-contingent-payments-announcement/) put into use to buy solved Sudoku for 0.10 BTC. Since then the underlying cryptography matured and thereby the idea of fully trust-less conditional payments become much more practical.

The innovation of `Contangle` goes from employing multiple novel cryptographic protocols such as Adaptor Signatures \[[Fourn'19](https://github.com/LLFourn/one-time-VES/blob/master/main.pdf), [EEE'20](https://eprint.iacr.org/2020/845)\] for scriptless conditional payments, Recursive ZK-SNARKs \[[BCTV'14](https://eprint.iacr.org/2019/1021.pdf)\] for efficient proofs generation without trusted setup \[[BGH'19](https://eprint.iacr.org/2019/1021.pdf)\], which proved to be especially problematic in the context of real-world ZKCP protocols \[[CGGN'17](https://eprint.iacr.org/2017/566)\].


## Protocol
Please see the [protocol documentation](/docs/protocol.md) for how it works.

## License
MIT
