use std::time::Instant;

use ark_mnt6_753::MNT6_753;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use powersoftau::{keypair, verify_transform, Accumulator, Sizes};
use rand::{thread_rng, Rng};

fn main() {
    let start = Instant::now();
    println!("Starting benchmark");
    println!(
        "Accumulator size: {}",
        Sizes::<MNT6_753>::new().accumulator_byte_size_with_hash() - 64
    );

    let rng = &mut thread_rng();
    let mut digest = (0..64).map(|_| rng.gen()).collect::<Vec<_>>();

    let mut acc = Accumulator::new();
    let before = acc.clone();
    let (pk, sk) = keypair(rng, &digest);

    println!("Time for setup: {:?}", start.elapsed());
    let start_intermediate = Instant::now();

    acc.transform(&sk);

    println!("Time for transform: {:?}", start_intermediate.elapsed());
    let start_intermediate = Instant::now();

    assert!(verify_transform(&before, &acc, &pk, &digest));

    println!(
        "Time for verify transform: {:?}",
        start_intermediate.elapsed()
    );
    let start_intermediate = Instant::now();

    digest[0] = !digest[0];

    assert!(!verify_transform(&before, &acc, &pk, &digest));

    println!(
        "Time for verify transform: {:?}",
        start_intermediate.elapsed()
    );
    let start_intermediate = Instant::now();

    let mut v = Vec::with_capacity(Sizes::<MNT6_753>::new().accumulator_byte_size_with_hash() - 64);
    acc.serialize_with_mode(&mut v, Compress::No).unwrap();

    println!("Time for serialize: {:?}", start_intermediate.elapsed());
    let start_intermediate = Instant::now();

    assert_eq!(
        v.len(),
        Sizes::<MNT6_753>::new().accumulator_byte_size_with_hash() - 64
    );

    let deserialized =
        Accumulator::deserialize_with_mode(&mut &v[..], Compress::No, Validate::No).unwrap();
    assert!(acc == deserialized);

    println!("Time for deserialize: {:?}", start_intermediate.elapsed());
    println!("Overall time: {:?}", start.elapsed());
}
