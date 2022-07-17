pragma circom 2.0.0;

template DummyProperty(n) {
    signal input plaintext[n];
    signal input challenge;

    challenge === plaintext[0]*plaintext[0]; // todo: challenge === plaintext goes unnotised with ark-circom 
}

component main = DummyProperty(1);
