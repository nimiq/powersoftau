//! This ceremony constructs the "powers of tau" for Jens Groth's 2016 zk-SNARK proving
//! system using the BLS12-381 pairing-friendly elliptic curve construction.
//!
//! # Overview
//!
//! Participants of the ceremony receive a "challenge" file containing:
//!
//! * the BLAKE2b hash of the last file entered into the transcript
//! * an `Accumulator` (with curve points encoded in uncompressed form for fast deserialization)
//!
//! The participant runs a tool which generates a random keypair (`PublicKey`, `PrivateKey`)
//! used for modifying the `Accumulator` from the "challenge" file. The keypair is then used to
//! transform the `Accumulator`, and a "response" file is generated containing:
//!
//! * the BLAKE2b hash of the "challenge" file (thus forming a hash chain over the entire transcript)
//! * an `Accumulator` (with curve points encoded in compressed form for fast uploading)
//! * the `PublicKey`
//!
//! This "challenge" file is entered into the protocol transcript. A given transcript is valid
//! if the transformations between consecutive `Accumulator`s verify with their respective
//! `PublicKey`s. Participants (and the public) can ensure that their contribution to the
//! `Accumulator` was accepted by ensuring the transcript contains their "response" file, ideally
//! by comparison of the BLAKE2b hash of the "response" file.
//!
//! After some time has elapsed for participants to contribute to the ceremony, a participant is
//! simulated with a randomness beacon. The resulting `Accumulator` contains partial zk-SNARK
//! public parameters for all circuits within a bounded size.

use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::*;
use ark_ff::fields::Field;
use ark_mnt6_753::*;
use ark_serialize::*;
use ark_std::UniformRand;
use blake2::{Blake2b512, Digest};
use generic_array::GenericArray;
use num_traits::identities::Zero;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use typenum::consts::U64;

/// The accumulator supports circuits with 2^21 multiplication gates.
const TAU_POWERS_LENGTH: usize = 1 << 21;
/// More tau powers are needed in G1 because the Groth16 H query
/// includes terms of the form tau^i * (tau^m - 1) = tau^(i+m) - tau^i
/// where the largest i = m - 2, requiring the computation of tau^(2m - 2)
/// and thus giving us a vector length of 2^22 - 1.
const TAU_POWERS_G1_LENGTH: usize = (TAU_POWERS_LENGTH << 1) - 1;

pub struct Sizes<P: Pairing> {
    g1_uncompressed_byte_size: usize,
    g2_uncompressed_byte_size: usize,
    g1_compressed_byte_size: usize,
    g2_compressed_byte_size: usize,
    _curve: PhantomData<P>,
}

impl<P: Pairing> Sizes<P> {
    pub fn new() -> Self {
        let g1 = <P as Pairing>::G1Affine::zero();
        let g2 = <P as Pairing>::G2Affine::zero();
        Self {
            g1_uncompressed_byte_size: g1.uncompressed_size(),
            g2_uncompressed_byte_size: g2.uncompressed_size(),
            g1_compressed_byte_size: g1.compressed_size(),
            g2_compressed_byte_size: g2.compressed_size(),
            _curve: PhantomData,
        }
    }

    /// The size of the accumulator on disk.
    pub fn accumulator_byte_size(&self) -> usize {
        (TAU_POWERS_G1_LENGTH * self.g1_uncompressed_byte_size) + // g1 tau powers
        (TAU_POWERS_LENGTH * self.g2_uncompressed_byte_size) + // g2 tau powers
        (TAU_POWERS_LENGTH * self.g1_uncompressed_byte_size) + // alpha tau powers
        (TAU_POWERS_LENGTH * self.g1_uncompressed_byte_size) // beta tau powers
        + self.g2_uncompressed_byte_size // beta in g2
        + 64 // blake2b hash of previous contribution
    }

    /// The "public key" is used to verify a contribution was correctly
    /// computed.
    pub fn public_key_size(&self) -> usize {
        PublicKey::default().uncompressed_size()
    }

    /// The size of the contribution on disk.
    pub fn contribution_byte_size(&self) -> usize {
        (TAU_POWERS_G1_LENGTH * self.g1_compressed_byte_size) + // g1 tau powers
        (TAU_POWERS_LENGTH * self.g2_compressed_byte_size) + // g2 tau powers
        (TAU_POWERS_LENGTH * self.g1_compressed_byte_size) + // alpha tau powers
        (TAU_POWERS_LENGTH * self.g1_compressed_byte_size) // beta tau powers
        + self.g2_compressed_byte_size // beta in g2
        + 64 // blake2b hash of input accumulator
        + self.public_key_size() // public key
    }
}

/// Hashes to G2 using the first 32 bytes of `digest`. Panics if `digest` is less
/// than 32 bytes.
fn hash_to_g2(digest: &[u8]) -> G2Projective {
    assert!(digest.len() >= 32);

    let mut seed = [0; 32];
    seed.copy_from_slice(&digest[..32]);

    ChaChaRng::from_seed(seed).gen()
}

#[test]
fn test_hash_to_g2() {
    assert!(
        hash_to_g2(&[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33
        ]) == hash_to_g2(&[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 34
        ])
    );

    assert!(
        hash_to_g2(&[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32
        ]) != hash_to_g2(&[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 33
        ])
    );
}

/// Contains terms of the form (s<sub>1</sub>, s<sub>1</sub><sup>x</sup>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub><sup>x</sup>)
/// for all x in τ, α and β, and some s chosen randomly by its creator. The function H "hashes into" the group G2. No points in the public key may be the identity.
///
/// The elements in G2 are used to verify transformations of the accumulator. By its nature, the public key proves
/// knowledge of τ, α and β.
///
/// It is necessary to verify `same_ratio`((s<sub>1</sub>, s<sub>1</sub><sup>x</sup>), (H(s<sub>1</sub><sup>x</sup>)<sub>2</sub>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub><sup>x</sup>)).
#[derive(Default, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey {
    tau_g1: (G1Affine, G1Affine),
    alpha_g1: (G1Affine, G1Affine),
    beta_g1: (G1Affine, G1Affine),
    tau_g2: G2Affine,
    alpha_g2: G2Affine,
    beta_g2: G2Affine,
}

/// Contains the secrets τ, α and β that the participant of the ceremony must destroy.
pub struct PrivateKey {
    tau: Fr,
    alpha: Fr,
    beta: Fr,
}

/// Constructs a keypair given an RNG and a 64-byte transcript `digest`.
pub fn keypair<R: Rng>(rng: &mut R, digest: &[u8]) -> (PublicKey, PrivateKey) {
    assert_eq!(digest.len(), 64);

    let tau = Fr::rand(rng);
    let alpha = Fr::rand(rng);
    let beta = Fr::rand(rng);

    let mut op = |x, personalization: u8| {
        // Sample random g^s
        let g1_s = G1Projective::rand(rng).into_affine();
        // Compute g^{s*x}
        let g1_s_x = (g1_s * x).into_affine();
        // Compute BLAKE2b(personalization | transcript | g^s | g^{s*x})
        let h = {
            let mut h = Blake2b512::default();
            h.update(&[personalization]);
            h.update(digest);
            g1_s.serialize_uncompressed(&mut h).unwrap();
            g1_s_x.serialize_uncompressed(&mut h).unwrap();
            h.finalize()
        };
        // Hash into G2 as g^{s'}
        let g2_s = hash_to_g2(h.as_ref()).into_affine();
        // Compute g^{s'*x}
        let g2_s_x = (g2_s * x).into_affine();

        ((g1_s, g1_s_x), g2_s_x)
    };

    let pk_tau = op(tau, 0);
    let pk_alpha = op(alpha, 1);
    let pk_beta = op(beta, 2);

    (
        PublicKey {
            tau_g1: pk_tau.0,
            alpha_g1: pk_alpha.0,
            beta_g1: pk_beta.0,
            tau_g2: pk_tau.1,
            alpha_g2: pk_alpha.1,
            beta_g2: pk_beta.1,
        },
        PrivateKey { tau, alpha, beta },
    )
}

#[test]
fn test_pubkey_serialization() {
    use rand::thread_rng;

    let rng = &mut thread_rng();
    let digest = (0..64).map(|_| rng.gen()).collect::<Vec<_>>();
    let (pk, _) = keypair(rng, &digest);
    let mut v = vec![];
    pk.serialize_uncompressed(&mut v).unwrap();
    assert_eq!(v.len(), Sizes::<MNT6_753>::new().public_key_size());
    // PITODO: checked or unchecked?
    let deserialized = PublicKey::deserialize_uncompressed(&mut &v[..]).unwrap();
    assert!(pk == deserialized);
}

/// The `Accumulator` is an object that participants of the ceremony contribute
/// randomness to. This object contains powers of trapdoor `tau` in G1 and in G2 over
/// fixed generators, and additionally in G1 over two other generators of exponents
/// `alpha` and `beta` over those fixed generators. In other words:
///
/// * (τ, τ<sup>2</sup>, ..., τ<sup>2<sup>22</sup> - 2</sup>, α, ατ, ατ<sup>2</sup>, ..., ατ<sup>2<sup>21</sup> - 1</sup>, β, βτ, βτ<sup>2</sup>, ..., βτ<sup>2<sup>21</sup> - 1</sup>)<sub>1</sub>
/// * (β, τ, τ<sup>2</sup>, ..., τ<sup>2<sup>21</sup> - 1</sup>)<sub>2</sub>
#[derive(PartialEq, Eq, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Accumulator {
    /// tau^0, tau^1, tau^2, ..., tau^{TAU_POWERS_G1_LENGTH - 1}
    pub tau_powers_g1: Vec<G1Affine>,
    /// tau^0, tau^1, tau^2, ..., tau^{TAU_POWERS_LENGTH - 1}
    pub tau_powers_g2: Vec<G2Affine>,
    /// alpha * tau^0, alpha * tau^1, alpha * tau^2, ..., alpha * tau^{TAU_POWERS_LENGTH - 1}
    pub alpha_tau_powers_g1: Vec<G1Affine>,
    /// beta * tau^0, beta * tau^1, beta * tau^2, ..., beta * tau^{TAU_POWERS_LENGTH - 1}
    pub beta_tau_powers_g1: Vec<G1Affine>,
    /// beta
    pub beta_g2: G2Affine,
}

impl Accumulator {
    /// Constructs an "initial" accumulator with τ = 1, α = 1, β = 1.
    pub fn new() -> Self {
        Accumulator {
            tau_powers_g1: vec![G1Affine::generator(); TAU_POWERS_G1_LENGTH],
            tau_powers_g2: vec![G2Affine::generator(); TAU_POWERS_LENGTH],
            alpha_tau_powers_g1: vec![G1Affine::generator(); TAU_POWERS_LENGTH],
            beta_tau_powers_g1: vec![G1Affine::generator(); TAU_POWERS_LENGTH],
            beta_g2: G2Affine::generator(),
        }
    }

    /// Transforms the accumulator with a private key.
    /// tau, tau^2, tau^3,...
    /// t, t^2, t^3,...
    /// tau^t, (tau^2)^(t^2),...
    pub fn transform(&mut self, key: &PrivateKey) {
        // Construct the powers of tau
        let mut taupowers = vec![Fr::zero(); TAU_POWERS_G1_LENGTH];
        let chunk_size = TAU_POWERS_G1_LENGTH / num_cpus::get();

        // Construct exponents in parallel
        crossbeam::scope(|scope| {
            for (i, taupowers) in taupowers.chunks_mut(chunk_size).enumerate() {
                scope.spawn(move |_| {
                    let mut acc = key.tau.pow(&[(i * chunk_size) as u64]);

                    for t in taupowers {
                        *t = acc;
                        acc *= key.tau;
                    }
                });
            }
        })
        .unwrap();

        /// Exponentiate a large number of points, with an optional coefficient to be applied to the
        /// exponent.
        fn batch_exp<C: SWCurveConfig>(
            bases: &mut [Affine<C>],
            exp: &[C::ScalarField],
            coeff: Option<&C::ScalarField>,
        ) {
            assert_eq!(bases.len(), exp.len());
            let mut projective = vec![Projective::<C>::zero(); bases.len()];
            let chunk_size = bases.len() / num_cpus::get();

            // Perform wNAF over multiple cores, placing results into `projective`.
            crossbeam::scope(|scope| {
                for ((bases, exp), projective) in bases
                    .chunks_mut(chunk_size)
                    .zip(exp.chunks(chunk_size))
                    .zip(projective.chunks_mut(chunk_size))
                {
                    scope.spawn(move |_| {
                        for ((base, exp), projective) in
                            bases.iter_mut().zip(exp.iter()).zip(projective.iter_mut())
                        {
                            let mut exp = *exp;
                            if let Some(coeff) = coeff {
                                exp *= coeff;
                            }

                            // PITODO: base * exp, check if arkworks does that efficiently already
                            // or whether we need to use some scalar-mul thingy
                            *projective = *base * exp;
                        }
                    });
                }
            })
            .unwrap();

            // Perform batch normalization
            // Turn it all back into affine points
            let affine = Projective::<C>::normalize_batch(&projective);
            bases.copy_from_slice(&affine);
        }

        batch_exp(&mut self.tau_powers_g1, &taupowers[0..], None);
        batch_exp(
            &mut self.tau_powers_g2,
            &taupowers[0..TAU_POWERS_LENGTH],
            None,
        );
        batch_exp(
            &mut self.alpha_tau_powers_g1,
            &taupowers[0..TAU_POWERS_LENGTH],
            Some(&key.alpha),
        );
        batch_exp(
            &mut self.beta_tau_powers_g1,
            &taupowers[0..TAU_POWERS_LENGTH],
            Some(&key.beta),
        );
        self.beta_g2 = (self.beta_g2 * key.beta).into_affine();
    }
}

/// Verifies a transformation of the `Accumulator` with the `PublicKey`, given a 64-byte transcript `digest`.
pub fn verify_transform(
    before: &Accumulator,
    after: &Accumulator,
    key: &PublicKey,
    digest: &[u8],
) -> bool {
    assert_eq!(digest.len(), 64);

    let compute_g2_s = |g1_s: G1Affine, g1_s_x: G1Affine, personalization: u8| {
        let mut h = Blake2b512::default();
        h.update(&[personalization]);
        h.update(digest);
        g1_s.serialize_uncompressed(&mut h).unwrap();
        g1_s_x.serialize_uncompressed(&mut h).unwrap();
        hash_to_g2(h.finalize().as_ref()).into_affine()
    };

    let tau_g2_s = compute_g2_s(key.tau_g1.0, key.tau_g1.1, 0);
    let alpha_g2_s = compute_g2_s(key.alpha_g1.0, key.alpha_g1.1, 1);
    let beta_g2_s = compute_g2_s(key.beta_g1.0, key.beta_g1.1, 2);

    // Check the proofs-of-knowledge for tau/alpha/beta
    if !same_ratio::<MNT6_753>(key.tau_g1, (tau_g2_s, key.tau_g2)) {
        return false;
    }
    if !same_ratio::<MNT6_753>(key.alpha_g1, (alpha_g2_s, key.alpha_g2)) {
        return false;
    }
    if !same_ratio::<MNT6_753>(key.beta_g1, (beta_g2_s, key.beta_g2)) {
        return false;
    }

    // Check the correctness of the generators for tau powers
    if after.tau_powers_g1[0] != G1Affine::generator() {
        return false;
    }
    if after.tau_powers_g2[0] != G2Affine::generator() {
        return false;
    }

    // Did the participant multiply the previous tau by the new one?
    if !same_ratio::<MNT6_753>(
        (before.tau_powers_g1[1], after.tau_powers_g1[1]),
        (tau_g2_s, key.tau_g2),
    ) {
        return false;
    }

    // Did the participant multiply the previous alpha by the new one?
    if !same_ratio::<MNT6_753>(
        (before.alpha_tau_powers_g1[0], after.alpha_tau_powers_g1[0]),
        (alpha_g2_s, key.alpha_g2),
    ) {
        return false;
    }

    // Did the participant multiply the previous beta by the new one?
    if !same_ratio::<MNT6_753>(
        (before.beta_tau_powers_g1[0], after.beta_tau_powers_g1[0]),
        (beta_g2_s, key.beta_g2),
    ) {
        return false;
    }
    if !same_ratio::<MNT6_753>(
        (before.beta_tau_powers_g1[0], after.beta_tau_powers_g1[0]),
        (before.beta_g2, after.beta_g2),
    ) {
        return false;
    }

    // Are the powers of tau correct?
    if !same_ratio::<MNT6_753>(
        power_pairs(&after.tau_powers_g1),
        (after.tau_powers_g2[0], after.tau_powers_g2[1]),
    ) {
        return false;
    }
    if !same_ratio::<MNT6_753>(
        (after.tau_powers_g1[0], after.tau_powers_g1[1]),
        power_pairs(&after.tau_powers_g2),
    ) {
        return false;
    }
    if !same_ratio::<MNT6_753>(
        power_pairs(&after.alpha_tau_powers_g1),
        (after.tau_powers_g2[0], after.tau_powers_g2[1]),
    ) {
        return false;
    }
    if !same_ratio::<MNT6_753>(
        power_pairs(&after.beta_tau_powers_g1),
        (after.tau_powers_g2[0], after.tau_powers_g2[1]),
    ) {
        return false;
    }

    true
}

/// Computes a random linear combination over v1/v2.
///
/// Checking that many pairs of elements are exponentiated by
/// the same `x` can be achieved (with high probability) with
/// the following technique:
///
/// Given v1 = [a, b, c] and v2 = [as, bs, cs], compute
/// (a*r1 + b*r2 + c*r3, (as)*r1 + (bs)*r2 + (cs)*r3) for some
/// random r1, r2, r3. Given (g, g^s)...
///
/// e(g, (as)*r1 + (bs)*r2 + (cs)*r3) = e(g^s, a*r1 + b*r2 + c*r3)
///
/// ... with high probability.
fn merge_pairs<C: SWCurveConfig>(v1: &[Affine<C>], v2: &[Affine<C>]) -> (Affine<C>, Affine<C>) {
    use rand::thread_rng;

    assert_eq!(v1.len(), v2.len());

    let chunk = (v1.len() / num_cpus::get()) + 1;

    let s = Arc::new(Mutex::new(Projective::<C>::zero()));
    let sx = Arc::new(Mutex::new(Projective::<C>::zero()));

    crossbeam::scope(|scope| {
        for (v1, v2) in v1.chunks(chunk).zip(v2.chunks(chunk)) {
            let s = s.clone();
            let sx = sx.clone();

            scope.spawn(move |_| {
                // We do not need to be overly cautious of the RNG
                // used for this check.
                let rng = &mut thread_rng();

                let mut local_s = Projective::<C>::zero();
                let mut local_sx = Projective::<C>::zero();

                for (v1, v2) in v1.iter().zip(v2.iter()) {
                    let rho = C::ScalarField::rand(rng);
                    let v1 = *v1 * rho;
                    let v2 = *v2 * rho;

                    local_s += v1;
                    local_sx += v2;
                }

                *s.lock().unwrap() += local_s;
                *sx.lock().unwrap() += local_sx;
            });
        }
    })
    .unwrap();

    let s = s.lock().unwrap().into_affine();
    let sx = sx.lock().unwrap().into_affine();

    (s, sx)
}

/// Construct a single pair (s, s^x) for a vector of
/// the form [1, x, x^2, x^3, ...].
fn power_pairs<C: SWCurveConfig>(v: &[Affine<C>]) -> (Affine<C>, Affine<C>) {
    merge_pairs(&v[0..(v.len() - 1)], &v[1..])
}

#[test]
fn test_power_pairs() {
    use ark_std::One;
    use rand::thread_rng;

    let rng = &mut thread_rng();

    let mut v = vec![];
    let x = Fr::rand(rng);
    let mut acc = Fr::one();
    for _ in 0..100 {
        v.push((G1Affine::generator() * acc).into_affine());
        acc *= x;
    }

    let gx = (G2Affine::generator() * x).into_affine();

    assert!(same_ratio::<MNT6_753>(
        power_pairs(&v),
        (G2Affine::generator(), gx)
    ));

    v[1] = (v[1] * Fr::rand(rng)).into_affine();

    assert!(!same_ratio::<MNT6_753>(
        power_pairs(&v),
        (G2Affine::generator(), gx)
    ));
}

/// Checks if pairs have the same ratio.
fn same_ratio<P: Pairing>(g1: (P::G1Affine, P::G1Affine), g2: (P::G2Affine, P::G2Affine)) -> bool {
    P::pairing(g1.0, g2.1) == P::pairing(g1.1, g2.0)
}

#[test]
fn test_same_ratio() {
    use rand::thread_rng;

    let rng = &mut thread_rng();

    let s = Fr::rand(rng);
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let g1_s = (g1 * s).into_affine();
    let g2_s = (g2 * s).into_affine();

    assert!(same_ratio::<MNT6_753>((g1, g1_s), (g2, g2_s)));
    assert!(!same_ratio::<MNT6_753>((g1_s, g1), (g2, g2_s)));
}

#[test]
fn test_accumulator_serialization() {
    use rand::thread_rng;

    let rng = &mut thread_rng();
    let mut digest = (0..64).map(|_| rng.gen()).collect::<Vec<_>>();

    let mut acc = Accumulator::new();
    let before = acc.clone();
    let (pk, sk) = keypair(rng, &digest);
    acc.transform(&sk);
    assert!(verify_transform(&before, &acc, &pk, &digest));
    digest[0] = !digest[0];
    assert!(!verify_transform(&before, &acc, &pk, &digest));
    let mut v = Vec::with_capacity(Sizes::<MNT6_753>::new().accumulator_byte_size() - 64);
    acc.serialize_with_mode(&mut v, Compress::No).unwrap();
    assert_eq!(
        v.len(),
        Sizes::<MNT6_753>::new().accumulator_byte_size() - 64
    );
    let deserialized =
        Accumulator::deserialize_with_mode(&mut &v[..], Compress::No, Validate::No).unwrap();
    assert!(acc == deserialized);
}

/// Compute BLAKE2b("")
pub fn blank_hash() -> GenericArray<u8, U64> {
    Blake2b512::new().finalize()
}

/// Abstraction over a reader which hashes the data being read.
pub struct HashReader<R: Read> {
    reader: R,
    hasher: Blake2b512,
}

impl<R: Read> HashReader<R> {
    /// Construct a new `HashReader` given an existing `reader` by value.
    pub fn new(reader: R) -> Self {
        HashReader {
            reader: reader,
            hasher: Blake2b512::default(),
        }
    }

    /// Destroy this reader and return the hash of what was read.
    pub fn into_hash(self) -> GenericArray<u8, U64> {
        self.hasher.finalize()
    }
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes = self.reader.read(buf)?;

        if bytes > 0 {
            self.hasher.update(&buf[0..bytes]);
        }

        Ok(bytes)
    }
}

/// Abstraction over a writer which hashes the data being written.
pub struct HashWriter<W: Write> {
    writer: W,
    hasher: Blake2b512,
}

impl<W: Write> HashWriter<W> {
    /// Construct a new `HashWriter` given an existing `writer` by value.
    pub fn new(writer: W) -> Self {
        HashWriter {
            writer: writer,
            hasher: Blake2b512::default(),
        }
    }

    /// Destroy this writer and return the hash of what was written.
    pub fn into_hash(self) -> GenericArray<u8, U64> {
        self.hasher.finalize()
    }
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bytes = self.writer.write(buf)?;

        if bytes > 0 {
            self.hasher.update(&buf[0..bytes]);
        }

        Ok(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
