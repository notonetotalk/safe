use aesstream::{AesReader, AesWriter};
use anyhow::Result;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use brotli2::read::BrotliEncoder;
use brotli2::write::BrotliDecoder;
use crypto::aessafe::{AesSafe128Decryptor, AesSafe128Encryptor};
use rand::rngs::OsRng;
use rpassword::read_password_from_tty;
use secstr::SecStr;
use std::fs::File;
use std::io::{stdin, stdout, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::{env, fs, io, str};
use tar::{Archive, Builder};

struct Config {
    archives: Option<Vec<HashAr>>,
}

struct HashAr {
    name: String,
    salt_key: String,
    verify_phc: String,
}

impl Config {
    fn push_archive(&mut self, a: HashAr) {
        self.archives.as_mut().unwrap().push(a);
    }
}

fn main() {
    let mut exit: bool = false;
    let mut config: Config = match get_config() {
        Ok(ok) => ok,
        Err(e) => {
            println!("\n    Couldn't read safes in current directory.");
            println!("    Error message: {}\n", e);
            exit = true;
            Config { archives: None }
        }
    };
    if exit == false {
        let args: Vec<String> = env::args().collect();
        if args.len() > 1 {
            match args[1].as_str() {
                "new" => {
                    if args.len() > 2 {
                        new_archive(&mut config, Some(&args[2]));
                    } else {
                        new_archive(&mut config, None);
                    }
                }
                "view" => {
                    if args.len() > 2 {
                        unlock(&mut config, false, Some(&args[2]));
                    } else {
                        unlock(&mut config, false, None);
                    }
                }
                "open" => {
                    if args.len() > 2 {
                        unlock(&mut config, true, Some(&args[2]));
                    } else {
                        unlock(&mut config, true, None);
                    }
                }
                _ => {
                    println!("\n    Usage: safe [new|view|open] <name>");
                    println!("");
                    println!("    new:     Creates a new safe");
                    println!("    view:    View a safe without persistence");
                    println!("    open:    Opens a safe where all changes will be saved");
                    println!("");
                    println!("    name:    Name of the safe to create or open");
                }
            }
            end_line();
            exit = true;
        }
    }
    while exit == false {
        match config.archives {
            Some(_) => exit = menu(&mut config),
            None => {
                println!("\n    No safes found in the current directory.");
                print!("    Create a new safe? (y/n): ");
                io::stdout().flush().unwrap();
                let mut choice = String::new();
                match io::stdin().read_line(&mut choice) {
                    Ok(_) => match choice.trim() {
                        "y" | "Y" | "yes" | "YES" => new_archive(&mut config, None),
                        _ => {
                            end_line();
                            exit = true;
                        }
                    },
                    Err(_) => {
                        println!("\n    Error reading input.");
                        end_line();
                        exit = true;
                    }
                }
            }
        }
    }
}

fn path_exists(path: &str) -> bool {
    fs::metadata(path).is_ok()
}

fn get_config() -> Result<Config> {
    // new selection menu
    let mut archives = Vec::new();
    let current_dir = Path::new(".");
    for entry in current_dir.read_dir()? {
        if let Ok(entry) = entry {
            match entry.path().extension() {
                Some(a) => {
                    if a == "safe" {
                        let mut file = File::open(entry.path())?;
                        let mut sig = [0u8; 4];
                        let mut sk = [0u8; 22];
                        let mut vphc = [0u8; 96];
                        file.read_exact(&mut sig)?;
                        if sig == [80u8, 75u8, 3u8, 4u8] {
                            file.read_exact(&mut sk)?;
                            file.read_exact(&mut vphc)?;
                            let ar = HashAr {
                                name: entry
                                    .path()
                                    .file_stem()
                                    .unwrap()
                                    .to_str()
                                    .unwrap()
                                    .to_owned(),
                                salt_key: str::from_utf8(&sk)?.to_owned(),
                                verify_phc: str::from_utf8(&vphc)?.to_owned(),
                            };
                            archives.push(ar);
                        }
                    }
                }
                None => (),
            }
        }
    }
    if archives.len() > 0 {
        Ok(Config {
            archives: Some(archives),
        })
    } else {
        Ok(Config { archives: None })
    }
}

fn menu(config: &mut Config) -> bool {
    println!("\n    Main Menu:\n");
    println!("        new:     Create a new safe");
    println!("        view:    View a safe without persistence");
    println!("        open:    Open a safe where all changes will be saved");
    println!("        exit:    Exit program");
    print!("\n    Choose option: ");
    io::stdout().flush().unwrap();
    let mut choice = String::new();
    match io::stdin().read_line(&mut choice) {
        Ok(_) => (),
        Err(_) => {
            pause("    Error reading input. Press \"Enter\" to try again...");
            return false;
        }
    }
    match choice.trim() {
        "new" => new_archive(config, None),
        "view" => unlock(config, false, None),
        "open" => unlock(config, true, None),
        "exit" => {
            end_line();
            return true;
        }
        _ => pause("\n    Invalid input. Press \"Enter\" to try again..."),
    }
    false
}

fn new_archive(config: &mut Config, name_arg: Option<&str>) {
    let new_archive_name: String = match name_arg {
        Some(name) => {
            println!("");
            if path_exists(format!("{}.safe", &name).as_ref()) {
                println!("    Archive already exists!");
                return;
            } else {
                name.to_string()
            }
        }
        None => {
            let name = loop {
                print!("\n    Set new safe name: ");
                io::stdout().flush().unwrap();

                // take user unput
                let mut input = String::new();
                io::stdin().read_line(&mut input).expect("ERROR");
                if path_exists(format!("{}.safe", &input.trim()).as_ref()) {
                    pause("    Archive already exists! Press \"Enter\" to try again...")
                } else {
                    break input;
                }
            };
            name.trim().to_string()
        }
    };

    let password = loop {
        let input: SecStr =
            SecStr::from(match read_password_from_tty(Some("    Set password: ")) {
                Ok(ok) => ok,
                Err(_) => {
                    pause("    Error when reading input. Press \"Enter\" to continue...");
                    return;
                }
            });
        let confirm: SecStr = SecStr::from(
            match read_password_from_tty(Some("    Confirm password: ")) {
                Ok(ok) => ok,
                Err(_) => {
                    pause("    Error when reading input. Press \"Enter\" to continue...");
                    return;
                }
            },
        );
        if input == confirm {
            break input;
        } else {
            println!("\n    Passwords do not match! Please try again.");
        }
    };

    let argon2 = Argon2::default();
    // generate two salts
    // one for the generating the key
    // the other for hashing the key for verification
    let salt_key = SaltString::generate(&mut OsRng);
    let salt_verify = SaltString::generate(&mut OsRng);

    // note: do not store hash_key
    let hash_key = match argon2.hash_password_simple(password.unsecure(), salt_key.as_ref()) {
        Ok(ok) => ok,
        Err(_) => {
            println!("\n    Error occurred when hashing password.");
            pause("    Press \"Enter\" to continue...");
            return;
        }
    };

    // use hash as a password to hash itself
    let hash_key_hash = &hash_key.hash.unwrap();
    let hash_verify =
        match argon2.hash_password_simple(hash_key_hash.as_bytes(), salt_verify.as_ref()) {
            Ok(ok) => ok,
            Err(_) => {
                println!("\n    Error occurred when hashing hash key.");
                pause("    Press \"Enter\" to continue...");
                return;
            }
        };

    drop(argon2);

    let hash_key_hash_bytes = hash_key_hash.as_bytes();
    let aes_key = &hash_key_hash_bytes[0..16];

    // save as a struct
    let new_archive = HashAr {
        name: new_archive_name.to_owned(),
        salt_key: salt_key.as_ref().to_owned(),
        verify_phc: hash_verify.to_string(),
    };

    match fs::create_dir(new_archive_name) {
        Ok(_) => (),
        Err(e) => {
            println!("\n    Error when creating new archive directory: {}", e);
            pause("    Press \"Enter\" to continue...");
            return;
        }
    }

    match fs::write(
        format!("{}/read_me.txt", &new_archive.name), b"Files and directories dropped here will be moved into the safe.\nThis directory will be automatically deleted after its contents have been copied.") {
        Ok(_) => (),
        Err(_) => {
            println!("\n    Error occurred when writing read_me.txt into new archive.");
            pause("    Press \"Enter\" to continue...");
            return;
        }
    };

    println!(
        "\n    Place files you would like encrypted in \"{}\",",
        &new_archive.name
    );
    pause("    and then press \"Enter\" to continue...");

    match lock(&new_archive, &aes_key) {
        Ok(_) => (),
        Err(e) => {
            println!("    Error message: {}", e);
            pause("    Press \"Enter\" to continue...");
            return;
        }
    }

    match config.archives {
        Some(_) => {
            config.push_archive(new_archive);
        }
        None => {
            *config = Config {
                archives: Some(vec![new_archive]),
            };
        }
    }
}

fn lock(archive: &HashAr, aes_key: &[u8]) -> Result<()> {
    println!("\n    Locking safe...");

    // pack opened archive
    let file = match File::create(format!("{}.tar", &archive.name)) {
        Ok(ok) => ok,
        Err(e) => {
            println!("\n    Error occurred while initalizing archive!");
            return Err(From::from(e));
        }
    };
    let mut ar_to_pack = Builder::new(file);
    match ar_to_pack.append_dir_all("", &archive.name) {
        Ok(_) => (),
        Err(e) => {
            println!("\n    Error occurred while creating archive!");
            return Err(From::from(e));
        }
    }
    match ar_to_pack.finish() {
        Ok(_) => (),
        Err(e) => {
            println!("\n    Error occurred when finalizing unencrypted archive!");
            return Err(From::from(e));
        }
    }

    drop(ar_to_pack);

    let unencrypted_ar = match File::open(format!("{}.tar", &archive.name)) {
        Ok(ok) => ok,
        Err(e) => {
            println!("\n    Error occurred when reading from unencrypted archive.");
            return Err(From::from(e));
        }
    };

    let mut encrypted_ar = match File::create(format!("{}.safe", &archive.name)) {
        Ok(ok) => ok,
        Err(e) => {
            println!("\n    Error occurred when initalizing encrypted archive.");
            return Err(From::from(e));
        }
    };

    //embed keys in file
    match encrypted_ar.write_all(b"\x50\x4B\x03\x04") {
        Ok(_) => (),
        Err(e) => {
            println!("\n    Error occurred while writing encrypted archive.");
            return Err(From::from(e));
        }
    }
    match encrypted_ar.write_all(&archive.salt_key.as_bytes()) {
        Ok(_) => (),
        Err(e) => {
            println!("\n    Error occurred while writing encrypted archive.");
            return Err(From::from(e));
        }
    }
    match encrypted_ar.write_all(&archive.verify_phc.as_bytes()) {
        Ok(_) => (),
        Err(e) => {
            println!("\n    Error occurred while writing encrypted archive.");
            return Err(From::from(e));
        }
    }

    let mut ar_compressor = BrotliEncoder::new(unencrypted_ar, 2);
    let aes_encryptor = AesSafe128Encryptor::new(&aes_key);
    let mut aes_writer = match AesWriter::new(encrypted_ar, aes_encryptor) {
        Ok(ok) => ok,
        Err(e) => {
            println!("\n    Error occurred while initalizing encryptor.");
            return Err(From::from(e));
        }
    };

    let mut buffer = [0u8; 8192];
    let mut read_count: usize;
    loop {
        read_count = match ar_compressor.read(&mut buffer) {
            Ok(ok) => ok,
            Err(e) => {
                println!("\n    Error occurred while reading compressed archive.");
                return Err(From::from(e));
            }
        };
        if read_count != 0 {
            match aes_writer.write_all(&buffer[0..read_count]) {
                Ok(_) => (),
                Err(e) => {
                    println!("\n    Error occurred while writing encrypted archive.");
                    return Err(From::from(e));
                }
            }
        } else {
            // finish writing encrypted archive
            match aes_writer.flush() {
                Ok(_) => (),
                Err(e) => {
                    println!("\n    Error occurred while finalizing encrypted archive.");
                    return Err(From::from(e));
                }
            }
            drop(aes_writer);
            drop(aes_encryptor);
            drop(ar_compressor);
            drop(buffer);
            drop(read_count);
            break;
        }
    }

    match fs::remove_file(format!("{}.tar", &archive.name)) {
        Ok(_) => (),
        Err(_) => {
            println!("\n    Warning: Was unable to remove temporary unencrypted archive.");
            pause("    Press \"Enter\" to continue...");
        }
    }

    match fs::remove_dir_all(&archive.name) {
        Ok(_) => (),
        Err(_) => {
            println!("\n    Warning: Could not wipe opened safe folder.");
            pause("    Press \"Enter\" to continue...");
        }
    }
    println!("    Safe locked.");
    Ok(())
}

fn unlock(config: &mut Config, keep: bool, selection_arg: Option<&str>) {
    let archives: &mut Vec<HashAr> = match &mut config.archives {
        Some(a) => a,
        None => {
            println!("\n    No safes found in the current directory.");
            return;
        }
    };

    let has_selection: bool = match selection_arg {
        Some(_) => true,
        None => false,
    };

    // selection menu
    let opened_archive: &mut HashAr = if has_selection {
        // get selection from cli argument
        let mut i: usize = 0;
        for a in archives.iter() {
            if selection_arg.unwrap() == a.name {
                break;
            } else {
                i += 1;
            }
        }
        println!("");
        if i == archives.len() {
            println!(
                "    \"{}\" is not a valid safe in the current directory.",
                selection_arg.unwrap()
            );
            return;
        }
        &mut archives[i]
    } else if archives.len() > 1 {
        let selection_loop = loop {
            println!("\n    Available safes...\n");
            let mut index: usize = 0;
            for a in archives.iter() {
                index += 1;
                println!("        {}: {}", index, a.name);
            }
            let mut input = String::new();
            print!("\n    Choose selection: ");
            io::stdout().flush().unwrap();
            match io::stdin().read_line(&mut input) {
                Ok(_) => (),
                Err(e) => {
                    println!("\n    Error: {}", e);
                    pause("    Press \"Enter\" to try again...");
                    continue;
                }
            }
            let mut input: usize = match input.trim().parse() {
                Ok(ok) => ok,
                Err(_) => {
                    // let user input selection as a string
                    let mut i: usize = 0;
                    for a in archives.iter() {
                        if input.trim() == a.name {
                            break;
                        } else {
                            i += 1;
                        }
                    }
                    i += 1;
                    i
                }
            };
            if input > index || input == 0 {
                pause("    Not a valid selection. Press \"Enter\" to try again...");
                continue;
            } else {
                input -= 1;
                break &mut archives[input];
            }
        };
        selection_loop
    } else {
        println!("\n    Opening \"{}\"...", &archives[0].name);
        &mut archives[0]
    };

    // password verification
    let input_password: SecStr = SecStr::from(
        match read_password_from_tty(Some("    Verify password: ")) {
            Ok(ok) => ok,
            Err(_) => {
                println!("\n    Error: Could not read input.");
                pause("    Press \"Enter\" to continue...");
                return;
            }
        },
    );

    let argon2 = Argon2::default();
    let hash_verify = match PasswordHash::new(&opened_archive.verify_phc) {
        Ok(ok) => ok,
        Err(_) => {
            println!("\n    Error: Could not parse PHC string.");
            pause("    Press \"Enter\" to continue...");
            return;
        }
    };
    let hash_key = match argon2
        .hash_password_simple(input_password.unsecure(), opened_archive.salt_key.as_ref())
    {
        Ok(ok) => ok,
        Err(_) => {
            println!("\n    Error: Could not parse password or salt key.");
            pause("    Press \"Enter\" to continue...");
            return;
        }
    };
    let hash_key_hash = &hash_key.hash.unwrap();
    match argon2.verify_password(hash_key_hash.as_bytes(), &hash_verify) {
        Ok(_) => (),
        Err(_) => {
            pause("    Incorrect password. Press \"Enter\" to continue...");
            return;
        }
    }

    drop(argon2);

    println!("\n    Unlocking safe...");

    // decrypt and uncompress archive
    let hash_key_hash_bytes = hash_key_hash.as_bytes();
    let aes_key = &hash_key_hash_bytes[0..16];

    let mut encrypted_ar = match File::open(format!("{}.safe", &opened_archive.name)) {
        Ok(ok) => ok,
        Err(_) => {
            println!(
                "\n    Error occurred when opening \"{}.safe\".",
                &opened_archive.name
            );
            pause("    Press \"Enter\" to continue...");
            return;
        }
    };

    // skip over the password verification data
    match encrypted_ar.seek(SeekFrom::Start(122)) {
        Ok(_) => (),
        Err(_) => {
            println!("\n    Error occured while accessing encrypted archive.");
            pause("    Press \"Enter\" to continue...");
        }
    }

    // write temporary decrypted and uncompressed archive
    let decrypted_ar = match File::create(format!("{}.tar", &opened_archive.name)) {
        Ok(ok) => ok,
        Err(_) => {
            println!("\n    Error occurred when initalizing decrypted archive file!");
            pause("    Press \"Enter\" to continue...");
            return;
        }
    };

    let aes_decryptor = AesSafe128Decryptor::new(&aes_key);
    let mut aes_reader = match AesReader::new(encrypted_ar, aes_decryptor) {
        Ok(ok) => ok,
        Err(_) => {
            println!("\n    Error occurred while initalizing decryptor.");
            pause("    Press \"Enter\" to continue...");
            return;
        }
    };
    let mut ar_decompressor = BrotliDecoder::new(decrypted_ar);

    let mut buffer = [0u8; 8192];
    let mut read_count: usize;
    loop {
        read_count = match aes_reader.read(&mut buffer) {
            Ok(ok) => ok,
            Err(e) => {
                println!("\n    Error occurred while while decrypting archive.");
                println!("    {}", e);
                pause("    Press \"Enter\" to continue...");
                return;
            }
        };
        if read_count != 0 {
            match ar_decompressor.write_all(&buffer[0..read_count]) {
                Ok(_) => (),
                Err(_) => {
                    println!("\n    Error occurred while uncompressing archive.");
                    pause("    Press \"Enter\" to continue...");
                    return;
                }
            }
        } else {
            // finish writing decrypted archive
            match ar_decompressor.flush() {
                Ok(_) => (),
                Err(_) => {
                    println!("\n    Error occurred while finalizing unencrypted archive.");
                    pause("    Press \"Enter\" to continue...");
                    return;
                }
            }
            drop(aes_reader);
            drop(aes_decryptor);
            drop(ar_decompressor);
            drop(buffer);
            drop(read_count);
            break;
        }
    }

    // unpack uncompressed archive
    let file = match File::open(format!("{}.tar", &opened_archive.name)) {
        Ok(ok) => ok,
        Err(_) => {
            println!("\n    Error occurred when opening decrypted archive!");
            pause("    Press \"Enter\" to continue...");
            return;
        }
    };
    let mut ar_to_unpack = Archive::new(file);
    match ar_to_unpack.unpack(format!("{}", &opened_archive.name)) {
        Ok(_) => (),
        Err(_) => {
            println!("\n    Error occurred while unpacking archive!");
            pause("    Press \"Enter\" to continue...");
            return;
        }
    }
    drop(ar_to_unpack);
    match fs::remove_file(format!("{}.tar", &opened_archive.name)) {
        Ok(_) => (),
        Err(_) => {
            println!("\n    Error occurred when clearing temporary decrypted archive!");
            pause("    Press \"Enter\" to continue...");
            return;
        }
    }

    if keep == false {
        println!("    Warning: Changes will not be saved.");
        pause("    Safe contents have been copied. Press \"Enter\" to erase...");
    } else {
        pause("    Safe is now opened. Press \"Enter\" to close...");
    }

    if keep {
        // backup files into refreshed archive
        match lock(&opened_archive, &aes_key) {
            Ok(_) => (),
            Err(e) => {
                println!("    Error message: {}", e);
                pause("    Press \"Enter\" to continue...");
                return;
            }
        }
    } else {
        // delete extracted files without an archive refresh
        match fs::remove_dir_all(&opened_archive.name) {
            Ok(_) => (),
            Err(_) => {
                println!("\n    Warning: Could not wipe opened archive.");
                pause("    Press \"Enter\" to continue...");
                return;
            }
        }
    }
}

#[cfg(target_family = "unix")]
fn end_line() {
    println!("");
}

#[cfg(target_family = "windows")]
fn end_line() {}

#[cfg(target_family = "unix")]
fn pause(message: &str) {
    let mut stdout = stdout();
    stdout.write(message.as_bytes()).unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0u8]).unwrap();
}

#[cfg(target_family = "windows")]
fn pause(message: &str) {
    let mut stdout = stdout();
    let mut tmp = String::new();
    stdout.write(message.as_bytes()).unwrap();
    stdout.flush().unwrap();
    stdin().read_line(&mut tmp).unwrap();
}
