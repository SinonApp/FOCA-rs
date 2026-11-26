//! `.DS_Store` parser on fixtures (generated with the reference `ds_store` module, MIT):
//! valid, large (two-level B-tree, 600 Unicode names), corrupted and oversized inputs.

mod common;

use foca_fuzz::dsstore::{parse_ds_store, DsLimits, DsStoreError};

fn read(p: &str) -> Vec<u8> {
    std::fs::read(common::fixtures().join(p)).unwrap()
}

#[test]
fn valid_ds_store() {
    let n = parse_ds_store(&read("www/.DS_Store"), DsLimits::default()).unwrap();
    assert_eq!(
        n.names,
        vec![
            ".git",
            "docs",
            "files",
            "index.php",
            "index.php.bak",
            "secret-plan_2024.pdf"
        ]
    );
    assert!(!n.truncated);
}

#[test]
fn big_two_level_tree_unicode() {
    let n = parse_ds_store(&read("dsstore/big.DS_Store"), DsLimits::default()).unwrap();
    assert_eq!(n.names.len(), 600);
    assert!(n.names.contains(&"file_00000_юникод.txt".to_string()));
    assert!(n.names.contains(&"file_00599_юникод.txt".to_string()));
    // Name limit.
    let lim = DsLimits {
        max_names: 50,
        ..Default::default()
    };
    let n = parse_ds_store(&read("dsstore/big.DS_Store"), lim).unwrap();
    assert_eq!(n.names.len(), 50);
    assert!(n.truncated);
}

#[test]
fn broken_inputs_never_panic() {
    let good = read("dsstore/big.DS_Store");
    // Truncations.
    for cut in (0..good.len()).step_by(997) {
        let _ = parse_ds_store(&good[..cut], DsLimits::default());
    }
    // Byte corruption at various offsets (deterministic).
    let mut x: u64 = 0x1234_5678;
    for _ in 0..300 {
        let mut b = good.clone();
        for _ in 0..8 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let i = (x as usize) % b.len();
            b[i] = (x >> 32) as u8;
        }
        let _ = parse_ds_store(&b, DsLimits::default());
    }
    let small = read("www/.DS_Store");
    let mut b = small.clone();
    b[4] = b'X';
    assert_eq!(
        parse_ds_store(&b, DsLimits::default()),
        Err(DsStoreError::BadMagic)
    );
    assert!(parse_ds_store(&small[..small.len() / 2], DsLimits::default()).is_err());
}

#[test]
fn huge_input_rejected() {
    let mut b = read("www/.DS_Store");
    b.resize(5 * 1024 * 1024, 0);
    assert!(matches!(
        parse_ds_store(&b, DsLimits::default()),
        Err(DsStoreError::TooLarge(_))
    ));
}
