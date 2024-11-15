fn main() {
    if cfg!(target_arch = "x86_64") {
        println!("cargo::rerun-if-changed=code.asm");

        assert_eq!(
            std::process::Command::new("nasm")
                .arg("code.asm")
                .spawn()
                .unwrap()
                .wait()
                .unwrap()
                .code(),
            Some(0)
        );
    }
}
