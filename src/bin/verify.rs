use ark_ec::short_weierstrass::Projective;
use ark_ec::{CurveGroup, Group};
use ark_mnt6_753::{G1Projective, G2Projective};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use powersoftau::*;

use std::fs::OpenOptions;
use std::io::{self, BufReader, BufWriter, Write};
use std::ops::Neg;

fn into_hex(h: &[u8]) -> String {
    let mut f = String::new();

    for byte in h {
        f += &format!("{:02x}", byte);
    }

    f
}

// Computes the hash of the challenge file for the player,
// given the current state of the accumulator and the last
// response file hash.
fn get_challenge_file_hash(acc: &Accumulator, last_response_file_hash: &[u8; 64]) -> [u8; 64] {
    let sink = io::sink();
    let mut sink = HashWriter::new(sink);

    sink.write_all(last_response_file_hash).unwrap();

    acc.serialize_uncompressed(&mut sink).unwrap();

    let mut tmp = [0; 64];
    tmp.copy_from_slice(sink.into_hash().as_slice());

    tmp
}

// Computes the hash of the response file, given the new
// accumulator, the player's public key, and the challenge
// file's hash.
fn get_response_file_hash(
    acc: &Accumulator,
    pubkey: &PublicKey,
    last_challenge_file_hash: &[u8; 64],
) -> [u8; 64] {
    let sink = io::sink();
    let mut sink = HashWriter::new(sink);

    sink.write_all(last_challenge_file_hash).unwrap();

    acc.serialize_compressed(&mut sink).unwrap();

    pubkey.serialize_uncompressed(&mut sink).unwrap();

    let mut tmp = [0; 64];
    tmp.copy_from_slice(sink.into_hash().as_slice());

    tmp
}

fn main() {
    // Try to load `./transcript` from disk.
    let reader = OpenOptions::new()
        .read(true)
        .open("transcript")
        .expect("unable open `./transcript` in this directory");

    let mut reader = BufReader::with_capacity(1024 * 1024, reader);

    // Initialize the accumulator
    let mut current_accumulator = Accumulator::new();

    // The "last response file hash" is just a blank BLAKE2b hash
    // at the beginning of the hash chain.
    let mut last_response_file_hash = [0; 64];
    last_response_file_hash.copy_from_slice(blank_hash().as_slice());

    // There were 89 rounds.
    for _ in 0..89 {
        // Compute the hash of the challenge file that the player
        // should have received.
        let last_challenge_file_hash =
            get_challenge_file_hash(&current_accumulator, &last_response_file_hash);

        // Deserialize the accumulator provided by the player in
        // their response file. It's stored in the transcript in
        // uncompressed form so that we can more efficiently
        // deserialize it.
        let response_file_accumulator =
            Accumulator::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes)
                .expect("unable to read uncompressed accumulator");

        // Deserialize the public key provided by the player.
        let response_file_pubkey = PublicKey::deserialize_uncompressed(&mut reader)
            .expect("wasn't able to deserialize the response file's public key");

        // Compute the hash of the response file. (we had it in uncompressed
        // form in the transcript, but the response file is compressed to save
        // participants bandwidth.)
        last_response_file_hash = get_response_file_hash(
            &response_file_accumulator,
            &response_file_pubkey,
            &last_challenge_file_hash,
        );

        print!("{}", into_hex(&last_response_file_hash));

        // Verify the transformation from the previous accumulator to the new
        // one. This also verifies the correctness of the accumulators and the
        // public keys, with respect to the transcript so far.
        if !verify_transform(
            &current_accumulator,
            &response_file_accumulator,
            &response_file_pubkey,
            &last_challenge_file_hash,
        ) {
            println!(" ... FAILED");
            panic!("INVALID RESPONSE FILE!");
        } else {
            println!();
        }

        current_accumulator = response_file_accumulator;
    }

    println!("Transcript OK!");

    // Create the parameters for various 2^m circuit depths.
    for m in 0..22 {
        let paramname = format!("phase1radix2m{}", m);
        println!("Creating {}", paramname);

        let degree = 1 << m;
        let domain =
            GeneralEvaluationDomain::<<G1Projective as Group>::ScalarField>::new(degree).unwrap();

        // PITODO: parallelize?
        let mut g1_coeffs: Vec<_> = current_accumulator.tau_powers_g1[0..degree]
            .iter()
            .map(|p| Projective::from(*p))
            .collect();
        let mut g2_coeffs: Vec<_> = current_accumulator.tau_powers_g2[0..degree]
            .iter()
            .map(|p| Projective::from(*p))
            .collect();
        let mut g1_alpha_coeffs: Vec<_> = current_accumulator.alpha_tau_powers_g1[0..degree]
            .iter()
            .map(|p| Projective::from(*p))
            .collect();
        let mut g1_beta_coeffs: Vec<_> = current_accumulator.beta_tau_powers_g1[0..degree]
            .iter()
            .map(|p| Projective::from(*p))
            .collect();

        // This converts all of the elements into Lagrange coefficients
        // for later construction of interpolation polynomials
        domain.ifft_in_place(&mut g1_coeffs);
        domain.ifft_in_place(&mut g2_coeffs);
        domain.ifft_in_place(&mut g1_alpha_coeffs);
        domain.ifft_in_place(&mut g1_beta_coeffs);

        assert_eq!(g1_coeffs.len(), degree);
        assert_eq!(g2_coeffs.len(), degree);
        assert_eq!(g1_alpha_coeffs.len(), degree);
        assert_eq!(g1_beta_coeffs.len(), degree);

        // Batch normalize
        let g1_coeffs = G1Projective::normalize_batch(&g1_coeffs);
        let g2_coeffs = G2Projective::normalize_batch(&g2_coeffs);
        let g1_alpha_coeffs = G1Projective::normalize_batch(&g1_alpha_coeffs);
        let g1_beta_coeffs = G1Projective::normalize_batch(&g1_beta_coeffs);

        // H query of Groth16 needs...
        // x^i * (x^m - 1) for i in 0..=(m-2) a.k.a.
        // x^(i + m) - x^i for i in 0..=(m-2)
        // for radix2 evaluation domains
        let mut h = Vec::with_capacity(degree - 1);
        for i in 0..(degree - 1) {
            let tmp = current_accumulator.tau_powers_g1[i + degree];
            let tmp2 = current_accumulator.tau_powers_g1[i].neg();

            h.push(tmp + tmp2);
        }

        // Batch normalize this as well
        let h = G1Projective::normalize_batch(&h);

        // Create the parameter file
        let writer = OpenOptions::new()
            .read(false)
            .write(true)
            .create_new(true)
            .open(paramname)
            .expect("unable to create parameter file in this directory");

        let mut writer = BufWriter::new(writer);

        // Write alpha (in g1)
        // Needed by verifier for e(alpha, beta)
        // Needed by prover for A and C elements of proof
        current_accumulator.alpha_tau_powers_g1[0]
            .serialize_uncompressed(&mut writer)
            .unwrap();

        // Write beta (in g1)
        // Needed by prover for C element of proof
        current_accumulator.beta_tau_powers_g1[0]
            .serialize_uncompressed(&mut writer)
            .unwrap();

        // Write beta (in g2)
        // Needed by verifier for e(alpha, beta)
        // Needed by prover for B element of proof
        current_accumulator
            .beta_g2
            .serialize_uncompressed(&mut writer)
            .unwrap();

        // Lagrange coefficients in G1 (for constructing
        // LC/IC queries and precomputing polynomials for A)
        for coeff in g1_coeffs {
            coeff.serialize_uncompressed(&mut writer).unwrap();
        }

        // Lagrange coefficients in G2 (for precomputing
        // polynomials for B)
        for coeff in g2_coeffs {
            coeff.serialize_uncompressed(&mut writer).unwrap();
        }

        // Lagrange coefficients in G1 with alpha (for
        // LC/IC queries)
        for coeff in g1_alpha_coeffs {
            coeff.serialize_uncompressed(&mut writer).unwrap();
        }

        // Lagrange coefficients in G1 with beta (for
        // LC/IC queries)
        for coeff in g1_beta_coeffs {
            coeff.serialize_uncompressed(&mut writer).unwrap();
        }

        // Bases for H polynomial computation
        for coeff in h {
            coeff.serialize_uncompressed(&mut writer).unwrap();
        }
    }
}
