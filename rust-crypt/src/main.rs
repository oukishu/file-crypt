use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use clap::Parser;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{Read, Write, BufReader, BufWriter, Error, ErrorKind};
use std::path::{Path, PathBuf};

const CHUNK_SIZE: usize = 64 * 1024; // 64KB
const TAG_SIZE: usize = 16;
const SALT_SIZE: usize = 16;
const MASTER_NONCE_SIZE: usize = 8;

#[derive(Parser)]
#[command(author, version, about = "High-performance file encryption tool (Rust version)")]
struct Cli {
    /// Operation mode: enc or dec
    #[arg(short, long)]
    mode: String,

    /// Password for key derivation
    #[arg(short, long)]
    password: String,

    /// Input file path
    #[arg(short, long)]
    input: PathBuf,

    /// Output directory
    #[arg(short, long)]
    output: PathBuf,
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, 100_000, &mut key)
        .expect("PBKDF2 derivation failed");
    key
}

fn encrypt_file(src: &Path, dst: &Path, password: &str) -> anyhow::Result<()> {
    let mut salt = [0u8; SALT_SIZE];
    let mut master_nonce = [0u8; MASTER_NONCE_SIZE];
    getrandom::getrandom(&mut salt)?;
    getrandom::getrandom(&mut master_nonce)?;

    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    
    let mut f_in = BufReader::new(File::open(src)?);
    let mut f_out = BufWriter::new(File::create(dst)?);

    // Write Header: Salt(16B) + MasterNonce(8B)
    f_out.write_all(&salt)?;
    f_out.write_all(&master_nonce)?;

    let mut buffer = [0u8; CHUNK_SIZE];
    let mut counter: u32 = 0;
    let mut nonce_buf = [0u8; 12];
    nonce_buf[..8].copy_from_slice(&master_nonce);

    while let Ok(n) = f_in.read(&mut buffer) {
        if n == 0 { break; }
        
        // Construct Nonce: MasterNonce + 4-byte Big-Endian Counter
        nonce_buf[8..].copy_from_slice(&counter.to_be_bytes());
        
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_buf), &buffer[..n])
            .map_err(|_| Error::new(ErrorKind::Other, "AES-GCM encryption failed"))?;
        
        f_out.write_all(&ciphertext)?;
        counter += 1;
    }
    f_out.flush()?;
    Ok(())
}

fn decrypt_file(src: &Path, dst: &Path, password: &str) -> anyhow::Result<()> {
    let mut f_in = BufReader::new(File::open(src)?);
    let mut salt = [0u8; SALT_SIZE];
    let mut master_nonce = [0u8; MASTER_NONCE_SIZE];
    
    f_in.read_exact(&mut salt)?;
    f_in.read_exact(&mut master_nonce)?;

    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let mut f_out = BufWriter::new(File::create(dst)?);

    // Decryption buffer must accommodate Chunk Data + 16-byte Tag
    let mut buffer = vec![0u8; CHUNK_SIZE + TAG_SIZE];
    let mut counter: u32 = 0;
    let mut nonce_buf = [0u8; 12];
    nonce_buf[..8].copy_from_slice(&master_nonce);

    loop {
        let n = f_in.read(&mut buffer)?;
        if n == 0 { break; }
        
        nonce_buf[8..].copy_from_slice(&counter.to_be_bytes());
        let plaintext = cipher.decrypt(Nonce::from_slice(&nonce_buf), &buffer[..n])
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Integrity check failed: Wrong password or data corruption"))?;
        
        f_out.write_all(&plaintext)?;
        counter += 1;
    }
    f_out.flush()?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    fs::create_dir_all(&cli.output)?;

    let file_name = cli.input.file_name()
        .ok_or_else(|| anyhow::anyhow!("Could not determine filename from input path"))?;

    if cli.mode == "enc" {
        let mut target_path = cli.output.join(file_name);
        // Append .enc to the existing extension
        let current_ext = target_path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if current_ext.is_empty() {
            target_path.set_extension("enc");
        } else {
            target_path.set_extension(format!("{}.enc", current_ext));
        }
        
        println!("Encrypting: {:?} -> {:?}", cli.input, target_path);
        encrypt_file(&cli.input, &target_path, &cli.password)?;
    } else {
        // Strip .enc extension
        let mut target_path = cli.output.join(file_name);
        target_path.set_extension("");
        
        println!("Decrypting: {:?} -> {:?}", cli.input, target_path);
        decrypt_file(&cli.input, &target_path, &cli.password)?;
    }

    println!("Success: Operation finished.");
    Ok(())
}