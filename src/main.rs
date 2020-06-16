#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate clap;

use std::io::{stdin, stdout, Write};
use std::ops::Deref;
use std::str::FromStr;

use bitcoin::hashes::hex::FromHex;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1;
use bitcoin::util::bip32::{ChainCode, ChildNumber, ExtendedPrivKey, ExtendedPubKey, Fingerprint};
use bitcoin::util::key::PublicKey;

use bip0039::{Language, Mnemonic, Seed};
use hmac::{Hmac, Mac};
use sha2::Sha512;

use magical_bitcoin_wallet::database::memory::MemoryDatabase;
use magical_bitcoin_wallet::types::ScriptType;
use magical_bitcoin_wallet::wallet::{OfflineWallet, Wallet};

lazy_static! {
    static ref GA_TESTNET: ExtendedPubKey = ExtendedPubKey {
        network: Network::Testnet,
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::Normal { index: 0 },
        public_key: PublicKey::from_str(
            "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3"
        )
        .unwrap(),
        chain_code: ChainCode::from_hex(
            "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04"
        )
        .unwrap(),
    };
    static ref GA_MAINNET: ExtendedPubKey = ExtendedPubKey {
        network: Network::Bitcoin,
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::Normal { index: 0 },
        public_key: PublicKey::from_str(
            "0322c5f5c9c4b9d1c3e22ca995e200d724c2d7d8b6953f7b38fddf9296053c961f"
        )
        .unwrap(),
        chain_code: ChainCode::from_hex(
            "e9a563d68686999af372a33157209c6860fe79197a4dafd9ec1dbaa49523351d"
        )
        .unwrap(),
    };
}

fn get_gait_path(input: &[u8]) -> Vec<u16> {
    let ga_key = b"GreenAddress.it HD wallet path";

    let mut hmac = Hmac::<Sha512>::new_varkey(ga_key).unwrap();
    hmac.input(&input);

    hmac.result()
        .code()
        .chunks_exact(2)
        .map(|i| i[1] as u16 | (i[0] as u16) << 8)
        .collect()
}

// Older "legacy" method
//
// use fastpbkdf2::pbkdf2_hmac_sha512;
// fn gait_path_from_mnemonic(mnemonic: &str) -> Vec<u16> {
//     let ga_path = b"greenaddress_path";
//
//     let mut out = [0u8; 64];
//     pbkdf2_hmac_sha512(mnemonic.as_bytes(), ga_path, 2048, &mut out);
//
//     get_gait_path(&out)
// }

fn gait_path_from_seed(xprv: &ExtendedPrivKey) -> Vec<u16> {
    let ctx = secp256k1::Secp256k1::new();

    let path = [ChildNumber::Hardened { index: 0x4741 }];
    let derived = xprv.derive_priv(&ctx, &path).unwrap();

    let mut buf = Vec::new();
    buf.extend_from_slice(derived.chain_code.as_bytes());
    buf.extend_from_slice(&derived.private_key.public_key(&ctx).to_bytes());

    get_gait_path(&buf)
}

fn derive_ga_xpub(
    gait_path: Vec<u16>,
    subaccount: Option<u16>,
    ga_xpub: &ExtendedPubKey,
) -> ExtendedPubKey {
    let ctx = secp256k1::Secp256k1::new();

    let full_path = match subaccount {
        Some(subaccount) => {
            let mut path = vec![3];
            path.extend(gait_path);
            path.push(subaccount);

            path
        }
        None => {
            let mut path = vec![1];
            path.extend(gait_path);

            path
        }
    };
    let full_path: Vec<ChildNumber> = full_path
        .into_iter()
        .map(|index| ChildNumber::Normal {
            index: index.into(),
        })
        .collect();

    ga_xpub.derive_pub(&ctx, &full_path).unwrap()
}

fn main() {
    let matches = clap_app!(gadescriptor =>
        (version: env!("CARGO_PKG_VERSION"))
        (author: env!("CARGO_PKG_AUTHORS"))
        (about: "Represents a GreenAddress/Blockstream Green wallet as a descriptor")
        (@setting DisableVersion)
        (@arg watch_only: -w --watch_only "Returns the public version of the descriptor")
        (@arg testnet: -t --testnet conflicts_with[mainnet] "Use the testnet network (default)")
        (@arg mainnet: -m --mainnet conflicts_with[testnet] "Use the mainnet network")
        // (@arg subaccount: -s --subaccount_index +takes_value "Returns the descriptor for a subaccount index instead of the main account") TODO: more testing
    )
    .get_matches();

    print!("Type your mnemonic: ");
    stdout().flush().unwrap();

    let mut mnemonic = String::new();
    stdin().read_line(&mut mnemonic).unwrap();

    let watch_only = matches.is_present("watch_only");
    let service = if matches.is_present("mainnet") {
        GA_MAINNET.deref()
    } else {
        GA_TESTNET.deref()
    };
    let subaccount: Option<u16> = matches
        .value_of("subaccount")
        .map(|s| s.parse().expect("Invalid subaccount index"));

    let mnemonic_bip39 = Mnemonic::from_phrase(mnemonic.trim(), Language::English).unwrap();
    let seed = Seed::new(&mnemonic_bip39, "");
    let seed_bytes: &[u8] = seed.as_bytes();
    let xprv = ExtendedPrivKey::new_master(Network::Testnet, seed_bytes).unwrap();

    let gait_path = gait_path_from_seed(&xprv);
    let derived_service_xpub = derive_ga_xpub(gait_path, subaccount, service);

    let descriptor_str = format!(
        "sh(wsh(thresh_m(2,{}/*,{}/1/*)))",
        derived_service_xpub, xprv
    );

    if watch_only {
        let wallet: OfflineWallet<MemoryDatabase> = Wallet::new_offline(
            &descriptor_str,
            None,
            Network::Testnet,
            MemoryDatabase::new(),
        )
        .unwrap();
        println!(
            "Watch-only descriptor: {}",
            wallet
                .public_descriptor(ScriptType::External)
                .unwrap()
                .unwrap()
        );
    } else {
        println!("Descriptor: {}", descriptor_str);
    }
}
