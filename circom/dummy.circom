pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/poseidon.circom";

template DummyProperty(n) {
    signal input plaintext[n];
    signal input challenge;

    plaintext[0] === challenge;
}

component main {public [challenge]} = DummyProperty(10);
