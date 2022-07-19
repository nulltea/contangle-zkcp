pragma circom 2.0.0;

template DummyProperty(n) {
    signal input something;
    signal input plaintext[n];
    signal input challenge;

    signal inter;

    inter <== plaintext[0]*plaintext[1];

    challenge === inter*inter; // todo: challenge === plaintext goes unnotised with ark-circom 
}

component main = DummyProperty(2);
