pragma circom 2.0.0;

template DummyProperty(n) {
    signal input plaintext[n];
}

component main = DummyProperty(100);
