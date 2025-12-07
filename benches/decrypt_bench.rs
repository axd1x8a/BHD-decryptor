use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use malachite::base::num::arithmetic::traits::ModPow;
use malachite::natural::Natural;
use malachite::platform::Limb;

struct RsaPublicKey {
    n: Natural,
    e: Natural,
    size: usize,
}

#[inline]
fn natural_from_bytes_be(bytes: &[u8]) -> Natural {
    const LIMB_SIZE: usize = size_of::<Limb>();

    let remainder_len = bytes.len() % LIMB_SIZE;

    let num_limbs = bytes.len().div_ceil(LIMB_SIZE);
    let mut limbs = Vec::with_capacity(num_limbs);

    for chunk in bytes[remainder_len..].rchunks_exact(LIMB_SIZE) {
        limbs.push(Limb::from_be_bytes(chunk.try_into().unwrap()));
    }

    if remainder_len > 0 {
        let mut limb = 0 as Limb;
        for &b in &bytes[..remainder_len] {
            limb = (limb << 8) | (b as Limb);
        }
        limbs.push(limb);
    }

    Natural::from_owned_limbs_asc(limbs)
}

#[inline]
fn natural_to_bytes_be_into(n: &Natural, output: &mut [u8]) {
    const LIMB_SIZE: usize = size_of::<Limb>();

    output.fill(0);

    for (chunk, limb) in output.rchunks_mut(LIMB_SIZE).zip(n.limbs()) {
        let bytes = limb.to_be_bytes();
        match chunk.first_chunk_mut() {
            Some(chunk) => *chunk = bytes,
            None => chunk.copy_from_slice(&bytes[LIMB_SIZE - chunk.len()..]),
        }
    }
}

fn parse_pem_public_key(pem: &str) -> RsaPublicKey {
    let base64_content: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    use base64::{Engine, engine::general_purpose::STANDARD};
    let der = STANDARD.decode(&base64_content).unwrap();

    parse_der_rsa_public_key(&der)
}

fn parse_der_rsa_public_key(der: &[u8]) -> RsaPublicKey {
    let mut pos = 0;
    assert_eq!(der[pos], 0x30);
    pos += 1;

    pos += parse_der_length(&der[pos..]).1;
    let (n_bytes, n_len) = parse_der_integer(&der[pos..]);
    pos += n_len;
    let (e_bytes, _) = parse_der_integer(&der[pos..]);

    let n = natural_from_bytes_be(&n_bytes);
    let e = natural_from_bytes_be(&e_bytes);
    let size = n_bytes.len();

    RsaPublicKey { n, e, size }
}

fn parse_der_length(der: &[u8]) -> (usize, usize) {
    if der[0] < 0x80 {
        (der[0] as usize, 1)
    } else {
        let num_bytes = (der[0] & 0x7F) as usize;
        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | (der[1 + i] as usize);
        }
        (length, 1 + num_bytes)
    }
}

fn parse_der_integer(der: &[u8]) -> (Vec<u8>, usize) {
    assert_eq!(der[0], 0x02);

    let (length, len_bytes) = parse_der_length(&der[1..]);
    let start = 1 + len_bytes;
    let mut bytes = der[start..start + length].to_vec();
    if !bytes.is_empty() && bytes[0] == 0x00 {
        bytes.remove(0);
    }

    (bytes, start + length)
}

#[inline]
fn raw_rsa_public_decrypt_into(block: &[u8], n: &Natural, e: &Natural, output: &mut [u8]) {
    let c = natural_from_bytes_be(block);
    let m = (&c).mod_pow(e, n);

    natural_to_bytes_be_into(&m, output);
}

fn decrypt_bhd(data: &[u8], public_key: &RsaPublicKey) -> Vec<u8> {
    use rayon::prelude::*;

    let in_block_size = public_key.size;
    let out_block_size = public_key.size - 1;

    if data.len() < in_block_size {
        return data.to_vec();
    }

    let n = &public_key.n;
    let e = &public_key.e;

    let block_count = data.len().div_ceil(in_block_size);
    let mut result = vec![0u8; block_count * out_block_size];

    let in_chunk_iter = data.par_chunks_exact(in_block_size);
    let last_in_chunk = in_chunk_iter.remainder();

    in_chunk_iter
        .zip(result.par_chunks_exact_mut(out_block_size))
        .for_each(|(in_chunk, out_chunk)| {
            raw_rsa_public_decrypt_into(in_chunk, n, e, out_chunk);
        });

    if !last_in_chunk.is_empty()
        && let Some(last_out_chunk) = result.chunks_mut(out_block_size).last()
    {
        let mut padded_block = Vec::with_capacity(in_block_size);
        padded_block.extend_from_slice(last_in_chunk);
        padded_block.resize(in_block_size, 0);

        raw_rsa_public_decrypt_into(&padded_block, n, e, last_out_chunk);
    }

    result
}

fn decrypt_bhd_sequential(data: &[u8], public_key: &RsaPublicKey) -> Vec<u8> {
    let in_block_size = public_key.size;
    let out_block_size = public_key.size - 1;

    if data.len() < in_block_size {
        return data.to_vec();
    }

    let n = &public_key.n;
    let e = &public_key.e;

    let block_count = data.len().div_ceil(in_block_size);

    let padded_len = block_count * in_block_size;
    let input_data: Vec<u8> = if data.len() == padded_len {
        data.to_vec()
    } else {
        let mut padded = vec![0u8; padded_len];
        padded[..data.len()].copy_from_slice(data);
        padded
    };

    let mut result = vec![0u8; block_count * out_block_size];

    for (i, out_chunk) in result.chunks_mut(out_block_size).enumerate() {
        let in_start = i * in_block_size;
        let in_end = in_start + in_block_size;
        let block = &input_data[in_start..in_end];

        raw_rsa_public_decrypt_into(block, n, e, out_chunk);
    }

    result
}

fn get_game_dir() -> Option<std::path::PathBuf> {
    std::env::var("ELDENRING_EXE")
        .ok()
        .map(|exe| Path::new(&exe).parent().unwrap().to_path_buf())
}

fn load_test_data() -> Option<(Vec<u8>, RsaPublicKey)> {
    let game_dir = get_game_dir()?;
    let keys_dir = Path::new("keys");
    if !keys_dir.exists() {
        return None;
    }

    for entry in fs::read_dir(keys_dir).ok()? {
        let entry = entry.ok()?;
        let path = entry.path();

        if path.extension().is_some_and(|ext| ext == "pem") {
            let name = path.file_stem()?.to_str()?;
            let bhd_path = game_dir.join(format!("{}.bhd", name));

            if bhd_path.exists() {
                let key_pem = fs::read_to_string(&path).ok()?;
                let public_key = parse_pem_public_key(&key_pem);

                let mut file = File::open(&bhd_path).ok()?;
                let mut data = Vec::new();
                file.read_to_end(&mut data).ok()?;

                println!("Loaded {} ({} bytes)", name, data.len());
                return Some((data, public_key));
            }
        }
    }

    None
}

fn bench_single_block(c: &mut Criterion) {
    let Some((data, public_key)) = load_test_data() else {
        println!("Skipping benchmark: ELDENRING_EXE not set or no test data found");
        return;
    };

    let in_block_size = public_key.size;
    let out_block_size = public_key.size - 1;
    let block = &data[..in_block_size];

    let mut group = c.benchmark_group("single_block");
    group.throughput(Throughput::Bytes(in_block_size as u64));

    group.bench_function("decrypt_block", |b| {
        let mut output = vec![0u8; out_block_size];
        b.iter(|| {
            raw_rsa_public_decrypt_into(
                black_box(block),
                &public_key.n,
                &public_key.e,
                &mut output,
            );
            black_box(&output);
        });
    });

    group.finish();
}

fn bench_full_file(c: &mut Criterion) {
    let Some((data, public_key)) = load_test_data() else {
        println!("Skipping benchmark: ELDENRING_EXE not set or no test data found");
        return;
    };

    let mut group = c.benchmark_group("full_file");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.sample_size(10);

    group.bench_function("decrypt_parallel", |b| {
        b.iter(|| {
            let result = decrypt_bhd(black_box(&data), &public_key);
            black_box(result);
        });
    });

    group.bench_function("decrypt_sequential", |b| {
        b.iter(|| {
            let result = decrypt_bhd_sequential(black_box(&data), &public_key);
            black_box(result);
        });
    });

    group.finish();
}

fn bench_byte_conversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_conversion");

    let bytes_128 = vec![0xFFu8; 128];
    let bytes_256 = vec![0xFFu8; 256];

    group.bench_function("natural_from_bytes_128", |b| {
        b.iter(|| {
            let n = natural_from_bytes_be(black_box(&bytes_128));
            black_box(n);
        });
    });

    group.bench_function("natural_from_bytes_256", |b| {
        b.iter(|| {
            let n = natural_from_bytes_be(black_box(&bytes_256));
            black_box(n);
        });
    });

    let n_128 = natural_from_bytes_be(&bytes_128);
    let n_256 = natural_from_bytes_be(&bytes_256);

    group.bench_function("natural_to_bytes_128", |b| {
        let mut output = vec![0u8; 128];
        b.iter(|| {
            natural_to_bytes_be_into(black_box(&n_128), &mut output);
            black_box(&output);
        });
    });

    group.bench_function("natural_to_bytes_256", |b| {
        let mut output = vec![0u8; 256];
        b.iter(|| {
            natural_to_bytes_be_into(black_box(&n_256), &mut output);
            black_box(&output);
        });
    });

    group.finish();
}

// fn bench_thread_scaling(c: &mut Criterion) {
//     let Some((data, public_key)) = load_test_data() else {
//         println!("Skipping benchmark: ELDENRING_EXE not set or no test data found");
//         return;
//     };

//     let mut group = c.benchmark_group("thread_scaling");
//     group.throughput(Throughput::Bytes(data.len() as u64));
//     group.sample_size(10);

//     let max_threads = rayon::current_num_threads();

//     for threads in [1, 2, 4, 8, 12, 16, 24, 32]
//         .iter()
//         .filter(|&&t| t <= max_threads)
//     {
//         let pool = rayon::ThreadPoolBuilder::new()
//             .num_threads(*threads)
//             .build()
//             .unwrap();

//         group.bench_function(format!("{}_threads", threads), |b| {
//             b.iter(|| {
//                 pool.install(|| {
//                     let result = decrypt_bhd(black_box(&data), &public_key);
//                     black_box(result)
//                 })
//             });
//         });
//     }

//     group.finish();
// }

criterion_group!(
    benches,
    bench_byte_conversion,
    bench_single_block,
    bench_full_file,
    // bench_thread_scaling,
);
criterion_main!(benches);
