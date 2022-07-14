// pub mod constraints;
pub mod constraints;
mod parameters;
pub mod poseidon;

use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{fields::PrimeField, UniformRand};
use ark_sponge::poseidon::{PoseidonParameters, PoseidonSponge};
use ark_sponge::{Absorb, CryptographicSponge};
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;

pub struct HashElGamal<C: ProjectiveCurve> {
    _group: PhantomData<C>,
}

#[derive(Clone, Debug)]
pub struct Parameters<C: ProjectiveCurve>
where
    <C as ProjectiveCurve>::BaseField: PrimeField,
{
    pub generator: C,
    pub poseidon: PoseidonParameters<C::BaseField>,
}

pub type PublicKey<C> = C;

pub struct SecretKey<C: ProjectiveCurve>(pub C::ScalarField);

pub struct Randomness<C: ProjectiveCurve>(pub C::ScalarField);

impl<C: ProjectiveCurve> UniformRand for Randomness<C> {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness(<C as ProjectiveCurve>::ScalarField::rand(rng))
    }
}

pub type Plaintext<C> = <C as ProjectiveCurve>::ScalarField;

pub type Ciphertext<C> = (C, <C as ProjectiveCurve>::ScalarField);

pub type Error = Box<dyn ark_std::error::Error>;

impl<C: ProjectiveCurve> AsymmetricEncryptionScheme for HashElGamal<C>
where
    C::BaseField: PrimeField,
    C::Affine: Absorb, // needed for Poseidon sponge
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Randomness = Randomness<C>;
    type Plaintext = Plaintext<C>;
    type Ciphertext = Ciphertext<C>;

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, Error> {
        panic!("unimplemented")
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        // get a random element from the scalar field
        let secret_key = C::ScalarField::rand(rng);

        // compute secret_key*generator to derive the public key
        let mut public_key = pp.generator;
        public_key.mul_assign(secret_key.clone());

        Ok((public_key, SecretKey(secret_key)))
    }

    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        msg: &Self::Plaintext,
        r: &Self::Randomness,
    ) -> Result<Self::Ciphertext, Error> {
        let mut c1 = pp.generator.clone();
        c1.mul_assign(r.0.clone());

        let mut p_r = pk.clone();
        p_r.mul_assign(r.0.clone());
        let p_ra = p_r.into_affine();

        let mut sponge = PoseidonSponge::new(&pp.poseidon);
        sponge.absorb(&p_ra);
        let dh = sponge.squeeze_field_elements::<C::ScalarField>(1)[0];

        let c2 = dh + msg;
        Ok((c1, c2))
    }

    fn decrypt(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Error> {
        let c1: C = ciphertext.0;
        let c2: <C as ProjectiveCurve>::ScalarField = ciphertext.1;

        // compute s = c1^secret_key
        let mut s = c1;
        s.mul_assign(sk.0);
        let sa = s.into_affine();

        // compute dh = H(s)
        let mut sponge = PoseidonSponge::new(&pp.poseidon);
        sponge.absorb(&sa);
        let dh = sponge.squeeze_field_elements::<C::ScalarField>(1)[0];

        // compute message = c2 - s
        let m = c2 - dh;

        Ok(m)
    }
}

#[cfg(test)]
mod test {
    use ark_std::{test_rng, UniformRand};

    use crate::elgamal::{poseidon, HashElGamal, Parameters, Randomness};
    use ark_bls12_377::{Fq, Fr, G1Projective as Bls12377};
    use ark_ec::ProjectiveCurve;

    use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
    use ark_ff::Field;

    #[test]
    fn test_elgamal_encryption() {
        let rng = &mut test_rng();

        // setup and key generation
        let parameters = Parameters::<Bls12377> {
            generator: Bls12377::prime_subgroup_generator(),
            poseidon: poseidon::get_bls12377_fq_params(2),
        };

        let (pk, sk) = HashElGamal::<Bls12377>::keygen(&parameters, rng).unwrap();

        // get msg and encryption randomness
        let bytes = [1, 2, 3];
        let msg = Fq::from_random_bytes(&bytes).unwrap();
        let msg = Fr::from_random_bytes(&bytes).unwrap();
        let r = Randomness::rand(rng);

        // encrypt and decrypt the message
        let cipher = HashElGamal::<Bls12377>::encrypt(&parameters, &pk, &msg, &r).unwrap();
        let check_msg = HashElGamal::<Bls12377>::decrypt(&parameters, &sk, &cipher).unwrap();

        assert_eq!(msg, check_msg);
    }
}
