use std::fs;

use clap::{Parser, Subcommand};
use whoami;
use rpassword::prompt_password;
use crate::pwn::PasswordStore;

mod pwn;

#[derive(Parser)]
#[command(
    name = "pwn",
    author = "atom",
    version = "0.1.0",
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Write down the password
    Add {
        name: String,
        password: String,
    },

    /// Get a password
    Get {
        name: String,
    },
    
    /// Delete the password
    Delete {
        name: String,
    },

    /// Show all names
    Show,

    /// Delete everything
    DeleteAll,
}

fn main() {
    let args = Cli::parse();

    let username = whoami::username();
    let path = format!("/home/{}/.pwn.dat", username);

    let master_password = prompt_password("Enter the master password: ").expect("Input error");

    let mut store = PasswordStore::load(&path, &master_password)
        .unwrap_or_else(|_| PasswordStore::new());

    match args.command {
        Commands::Add { name, password } => {
            store.set(&name, &password);
            store.save(&path, &master_password)
                .expect("Error when saving");
            println!("The password for \"{}\" is saved", name);
        }

        Commands::Get { name } => {
            if let Some(pass) = store.get(&name) {
                println!("Password for \"{}\": {}", name, pass);
            } else {
                println!("The \"{}\" entry was not found", name);
            }
        }

        Commands::Delete { name } => {
            if store.get(&name).is_some() {
                store.remove(&name);
                store.save(&path, &master_password)
                    .expect("Error when saving");
                println!("The password for \"{}\" has been deleted", name);
            } else {
                println!("The \"{}\" entry was not found", name);
            }
        }

        Commands::Show => {
            let names = store.list_names();
            if names.is_empty() {
                println!("No passwords stored");
            } else {
                println!("Stored password names:");
                for name in names {
                    println!("- {}", name);
                }
            }
        }

        Commands::DeleteAll => {
            match fs::remove_file(path) {
                Ok(_) => println!("The data has been completely deleted"),
                Err(_) => println!("Couldn't find the data file")
            }
        }
    }
}