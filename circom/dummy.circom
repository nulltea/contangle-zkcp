pragma circom 2.0.0;

template DummyProperty(n) {
    signal input something;
    signal input plaintext[n];
    signal input challenge;

    plaintext[0] === something;

    challenge === something * something;
}

component main = DummyProperty(100);
