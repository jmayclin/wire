use std::{fs::File, io::Write, path::Path};

// build.rs can't take a normal code dependency on rust code because that would
// create a circular dependency. Instead we just "copy-paste" the code into build.rs
include! {"src/iana/definitions.rs"}

/// build.rs is used to code-gen all of the relevant IANA constants. This prevents
/// our codebase from becoming "stringly typed".
fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("iana_constants.rs");
    let mut f = File::create(&dest_path).unwrap();

    // uncomment to see the intermediate file that the code is written to
    // println!("cargo:warning=Generated file at: {}", &dest_path.display());

    writeln!(f, "pub use super::Cipher;").unwrap();
    writeln!(f, "pub use super::SignatureScheme;").unwrap();
    writeln!(f, "pub use super::Group;").unwrap();

    // Generate constants
    for &(value, description) in IANA_CIPHERS.iter() {
        writeln!(f, "#[allow(warnings)]").unwrap();
        writeln!(
            f,
            "pub const {}: Cipher = Cipher {{ value: [{}, {}] }};",
            description, value[0], value[1]
        )
        .unwrap();
    }

    for &(value, description) in IANA_SIGNATURE_SCHEMES.iter() {
        writeln!(f, "#[allow(warnings)]").unwrap();
        writeln!(
            f,
            "pub const {}: SignatureScheme = SignatureScheme {{ value: {} }};",
            description, value
        )
        .unwrap();
    }

    for &(value, description) in IANA_GROUPS.iter() {
        writeln!(f, "#[allow(warnings)]").unwrap();
        writeln!(
            f,
            "pub const {}: Group = Group {{ value: {} }};",
            description, value
        )
        .unwrap();
    }
}
