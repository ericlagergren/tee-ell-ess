//! Build script.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(tee_ell_ess_debug)");
}
