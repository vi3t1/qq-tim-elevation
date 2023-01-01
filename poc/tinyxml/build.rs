use std::env;
use std::path::*;

fn main() {
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-cdylib-link-arg=/DEF:{}", Path::new(&dir).join(r"src\lib.def").display());
}
