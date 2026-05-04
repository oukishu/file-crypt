use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use clap::Parser;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;
const SALT_SIZE: usize = 16;
const MASTER_NONCE_SIZE: usize = 8;

#[derive(Parser)]
struct Cli {
    #[arg(short, long)] mode: String, // enc or dec
    #[arg(short, long)] password: String,
    #[arg(short, long)] input: PathBuf,
    #[arg(short, long)] output: PathBuf,
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::<Sha256>(password.as_bytes(), salt, 100_000, &mut key);
    key
}

fn encrypt_action(src: &Path, dst: &Path, password: &str) -> anyhow::Result<()> {
    let mut salt = [0u8; SALT_SIZE];
    let mut master_nonce = [0u8; MASTER_NONCE_SIZE];
    getrandom::getrandom(&mut salt)?;
    getrandom::getrandom(&mut master_nonce)?;

    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    
    let mut f_in = BufReader::new(File::open(src)?);
    let mut f_out = BufWriter::new(File::create(dst)?);

    f_out.write_all(&salt)?;
    f_out.write_all(&master_nonce)?;

    let mut buffer = [0u8; CHUNK_SIZE];
    let mut counter: u32 = 0;
    let mut nonce_buf = [0u8; 12];
    nonce_buf[..8].copy_from_slice(&master_nonce);

    while let Ok(n) = f_in.read(&mut buffer) {
        if n == 0 { break; }
        nonce_buf[8..].copy_from_slice(&counter.to_be_bytes());
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_buf), &buffer[..n])
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
        f_out.write_all(&ciphertext)?;
        counter += 1;
    }
    Ok(())
}

fn decrypt_action(src: &Path, dst: &Path, password: &str) -> anyhow::Result<()> {
    let mut f_in = BufReader::new(File::open(src)?);
    let mut salt = [0u8; SALT_SIZE];
    let mut master_nonce = [0u8; MASTER_NONCE_SIZE];
    f_in.read_exact(&mut salt)?;
    f_in.read_exact(&mut master_nonce)?;

    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let mut f_out = BufWriter::new(File::create(dst)?);

    let mut buffer = vec![0u8; CHUNK_SIZE + TAG_SIZE];
    let mut counter: u32 = 0;
    let mut nonce_buf = [0u8; 12];
    nonce_buf[..8].copy_from_slice(&master_nonce);

    while let Ok(n) = f_in.read(&mut buffer) {
        if n == 0 { break; }
        nonce_buf[8..].copy_from_slice(&counter.to_be_bytes());
        let plaintext = cipher.decrypt(Nonce::from_slice(&nonce_buf), &buffer[..n])
            .map_err(|_| anyhow::anyhow!("Auth failed at chunk {}", counter))?;
        f_out.write_all(&plaintext)?;
        counter += 1;
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    for entry in WalkDir::new(&cli.input).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let rel = entry.path().strip_prefix(&cli.input)?;
            let mut out_path = cli.output.join(rel);
            fs::create_dir_all(out_path.parent().unwrap())?;

            if cli.mode == "enc" {
                out_path.set_extension(format!("{}.enc", out_path.extension().unwrap_or_default().to_str().unwrap()));
                encrypt_action(entry.path(), &out_path, &cli.password)?;
            } else {
                let mut p = out_path.clone();
                p.set_extension(""); // 简单处理后缀
                decrypt_action(entry.path(), &p, &cli.password)?;
            }
        }
    }
    Ok(())
}