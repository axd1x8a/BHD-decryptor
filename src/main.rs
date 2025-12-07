use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

use clap::Parser;
use malachite::base::num::arithmetic::traits::ModPow;
use malachite::natural::Natural;
use malachite::platform::Limb;
use rayon::prelude::*;

#[derive(Parser)]
#[command(name = "BHD decryptor")]
struct Args {
    /// Input directory containing encrypted .bhd files
    #[arg(short, long, default_value = ".")]
    input: String,

    /// Output directory for decrypted files
    #[arg(short, long, default_value = "output")]
    output: String,

    /// Keys directory containing .pem files
    #[arg(short, long, default_value = "keys")]
    keys: String,
}

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    fs::create_dir_all(&args.output)?;

    let keys = load_keys(&args.keys)?;
    println!("Loaded {} keys", keys.len());

    keys.par_iter().for_each(|(name, public_key)| {
        let input_path = Path::new(&args.input).join(format!("{}.bhd", name));

        if input_path.exists() {
            if let Err(e) = process_file(&input_path, &args.output, public_key) {
                eprintln!("Error processing {:?}: {}", input_path, e);
            }
        } else {
            println!("Skipping {}.bhd (not found)", name);
        }
    });

    println!("Done!");
    Ok(())
}

fn load_keys(keys_dir: &str) -> Result<Vec<(String, RsaPublicKey)>, Box<dyn std::error::Error>> {
    let mut keys = Vec::new();

    for entry in fs::read_dir(keys_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().is_some_and(|ext| ext == "pem") {
            let name = path.file_stem().unwrap().to_str().unwrap().to_string();

            let key_pem = fs::read_to_string(&path)?;
            let public_key = parse_pem_public_key(&key_pem)?;

            println!("Loaded key: {}", name);
            keys.push((name, public_key));
        }
    }

    Ok(keys)
}

fn parse_pem_public_key(pem: &str) -> Result<RsaPublicKey, Box<dyn std::error::Error>> {
    let base64_content: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    use base64::{Engine, engine::general_purpose::STANDARD};
    let der = STANDARD.decode(&base64_content)?;

    parse_der_rsa_public_key(&der)
}

fn parse_der_rsa_public_key(der: &[u8]) -> Result<RsaPublicKey, Box<dyn std::error::Error>> {
    let mut pos = 0;
    if der[pos] != 0x30 {
        return Err("Expected SEQUENCE".into());
    }
    pos += 1;

    pos += parse_der_length(&der[pos..])?.1;
    let (n_bytes, n_len) = parse_der_integer(&der[pos..])?;
    pos += n_len;
    let (e_bytes, _) = parse_der_integer(&der[pos..])?;

    let n = natural_from_bytes_be(&n_bytes);
    let e = natural_from_bytes_be(&e_bytes);

    let size = n_bytes.len();

    Ok(RsaPublicKey { n, e, size })
}

#[inline]
fn parse_der_length(der: &[u8]) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    if der[0] < 0x80 {
        Ok((der[0] as usize, 1))
    } else {
        let num_bytes = (der[0] & 0x7F) as usize;
        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | (der[1 + i] as usize);
        }
        Ok((length, 1 + num_bytes))
    }
}

#[inline]
fn parse_der_integer(der: &[u8]) -> Result<(Vec<u8>, usize), Box<dyn std::error::Error>> {
    if der[0] != 0x02 {
        return Err("Expected INTEGER".into());
    }

    let (length, len_bytes) = parse_der_length(&der[1..])?;
    let start = 1 + len_bytes;
    let mut bytes = der[start..start + length].to_vec();
    if !bytes.is_empty() && bytes[0] == 0x00 {
        bytes.remove(0);
    }

    Ok((bytes, start + length))
}

fn process_file(
    input_path: &Path,
    output_dir: &str,
    public_key: &RsaPublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Processing: {:?}", input_path);

    let encrypted_data = fs::read(input_path)?;

    let decrypted_data = decrypt_bhd(&encrypted_data, public_key);

    if decrypted_data.len() >= 4 && &decrypted_data[0..4] == b"BHD5" {
        println!("  -> Valid BHD5 header");
    } else {
        println!(
            "  -> Warning: No BHD5 magic found (got {:02X?})",
            &decrypted_data[..4.min(decrypted_data.len())]
        );
    }

    let output_path = Path::new(output_dir).join(input_path.file_name().unwrap());

    let output_file = File::create(&output_path)?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, output_file);
    writer.write_all(&decrypted_data)?;

    println!(
        "  -> Saved to {:?} ({} bytes)",
        output_path,
        decrypted_data.len()
    );
    Ok(())
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

#[inline]
fn raw_rsa_public_decrypt_into(block: &[u8], n: &Natural, e: &Natural, output: &mut [u8]) {
    let c = natural_from_bytes_be(block);
    let m = (&c).mod_pow(e, n);

    natural_to_bytes_be_into(&m, output);
}
