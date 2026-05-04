# file-crypt Usage Guide
file-crypt is a high-performance, cross-platform streaming file encryption tool built with Go. It utilizes the AES-256-GCM encryption algorithm and PBKDF2 for key derivation, ensuring both data security and integrity verification.         

## Key Features
 * Streaming Process: Uses 64KB chunk-based encryption, supporting ultra-large files (GB/TB range) while maintaining a consistently low memory footprint (approx. 10MB).  

 * Cross-Platform Support: Supports Windows (x86/x64), Linux (amd64/arm64), and macOS (Intel/Apple Silicon).  

 * High Security:
   * Algorithm: AES-256-GCM (Authenticated Encryption).  
   * Key Derivation: PBKDF2-SHA256 with 100,000 iterations.  
   * Integrity Check: Decryption will fail immediately if the file has been tampered with or the wrong password is provided.  

Single Binary: No external dependencies; simply download and run.

## Command Line Usage
The program supports four main parameters:  
 * `-m`: Mode. Use `enc` for encryption and `dec` for decryption.  
 * `-p`: Password. A strong password used for the operation.  
 * `-i`: Input. The path to the file you want to process.  
 * `-o`: Output. The directory where the processed file will be saved.
 * `-compat`: Compatibility. Enables `Web Mode`.

1. Encrypt a File            
To encrypt `my_data.zip` and save it to the `./encrypted` folder:
```sh
./file-crypt -m enc -p "your-strong-password" -i "my_data.zip" -o "./encrypted"
```
Result: A file named `my_data.zip.enc` will be generated in the `./encrypted` directory.

2. Decrypt a File            
To restore an encrypted file to the `./restored` folder:
```sh
./file-crypt -m dec -p "your-strong-password" -i "./encrypted/my_data.zip.enc" -o "./restored"
```
Result: The original `my_data.zip` file will be restored in the `./restored` directory.