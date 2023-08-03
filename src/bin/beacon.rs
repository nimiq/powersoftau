use ark_mnt6_753::MNT6_753;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use hex_literal::hex;
use powersoftau::*;

use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter, Read, Write};

fn main() {
    // Create an RNG based on the outcome of the random beacon
    let mut rng = {
        use crypto::digest::Digest;
        use crypto::sha2::Sha256;
        use rand::SeedableRng;
        use rand_chacha::ChaChaRng;

        // Place block hash here (block number #514200)
        let mut cur_hash: [u8; 32] =
            hex!("00000000000000000034b33e842ac1c50456abe5fa92b60f6b3dfc5d247f7b58");

        // Performs 2^n hash iterations over it
        const N: usize = 42;

        for i in 0..(1u64 << N) {
            // Print 1024 of the interstitial states
            // so that verification can be
            // parallelized
            if i % (1u64 << (N - 10)) == 0 {
                print!("{}: ", i);
                for b in cur_hash.iter() {
                    print!("{:02x}", b);
                }
                println!();
            }

            let mut h = Sha256::new();
            h.input(&cur_hash);
            h.result(&mut cur_hash);
        }

        print!("Final result of beacon: ");
        for b in cur_hash.iter() {
            print!("{:02x}", b);
        }
        println!();

        let mut seed = [0; 32];
        seed.copy_from_slice(&cur_hash[..32]);

        ChaChaRng::from_seed(seed)
    };

    // Try to load `./challenge` from disk.
    let reader = OpenOptions::new()
        .read(true)
        .open("challenge")
        .expect("unable open `./challenge` in this directory");

    {
        let metadata = reader
            .metadata()
            .expect("unable to get filesystem metadata for `./challenge`");
        if metadata.len() != (Sizes::<MNT6_753>::new().accumulator_byte_size_with_hash() as u64) {
            panic!(
                "The size of `./challenge` should be {}, but it's {}, so something isn't right.",
                Sizes::<MNT6_753>::new().accumulator_byte_size_with_hash(),
                metadata.len()
            );
        }
    }

    let reader = BufReader::new(reader);
    let mut reader = HashReader::new(reader);

    // Create `./response` in this directory
    let writer = OpenOptions::new()
        .read(false)
        .write(true)
        .create_new(true)
        .open("response")
        .expect("unable to create `./response` in this directory");

    let writer = BufWriter::new(writer);
    let mut writer = HashWriter::new(writer);

    println!("Reading `./challenge` into memory...");

    // Read the BLAKE2b hash of the previous contribution
    {
        // We don't need to do anything with it, but it's important for
        // the hash chain.
        let mut tmp = [0; 64];
        reader
            .read_exact(&mut tmp)
            .expect("unable to read BLAKE2b hash of previous contribution");
    }

    // Load the current accumulator into memory
    let mut current_accumulator =
        Accumulator::deserialize_with_mode(&mut reader, Compress::No, Validate::No)
            .expect("unable to read uncompressed accumulator");

    // Get the hash of the current accumulator
    let current_accumulator_hash = reader.into_hash();

    // Construct our keypair using the RNG we created above
    let (pubkey, privkey) = keypair(&mut rng, current_accumulator_hash.as_ref());

    // Perform the transformation
    println!("Computing, this could take a while...");
    current_accumulator.transform(&privkey);
    println!("Writing your contribution to `./response`...");

    // Write the hash of the input accumulator
    writer
        .write_all(current_accumulator_hash.as_ref())
        .expect("unable to write BLAKE2b hash of input accumulator");

    // Write the transformed accumulator (in compressed form, to save upload bandwidth for disadvantaged
    // players.)
    current_accumulator
        .serialize_compressed(&mut writer)
        .expect("unable to write transformed accumulator");

    // Write the public key
    pubkey
        .serialize_uncompressed(&mut writer)
        .expect("unable to write public key");

    // Get the hash of the contribution, so the user can compare later
    let contribution_hash = writer.into_hash();

    print!(
        "Done!\n\n\
              Your contribution has been written to `./response`\n\n\
              The BLAKE2b hash of `./response` is:\n"
    );

    for line in contribution_hash.as_slice().chunks(16) {
        print!("\t");
        for section in line.chunks(4) {
            for b in section {
                print!("{:02x}", b);
            }
            print!(" ");
        }
        println!();
    }

    println!("\n");
}
