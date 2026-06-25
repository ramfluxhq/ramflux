fn main() {
    println!("cargo:rerun-if-changed=src/c_abi");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    if std::env::var_os("CARGO_FEATURE_C_ABI").is_none() {
        return;
    }

    let manifest_dir = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(value) => value,
        Err(error) => {
            println!("cargo:warning=failed to locate manifest dir for cbindgen: {error}");
            return;
        }
    };
    let target_dir = std::path::Path::new(&manifest_dir).join("target/include");
    if let Err(error) = std::fs::create_dir_all(&target_dir) {
        println!("cargo:warning=failed to create cbindgen output dir: {error}");
        return;
    }
    let config_path = std::path::Path::new(&manifest_dir).join("cbindgen.toml");
    let output_path = target_dir.join("ramflux_sdk.h");
    let config = match cbindgen::Config::from_file(&config_path) {
        Ok(config) => config,
        Err(error) => {
            println!("cargo:warning=failed to read cbindgen config: {error}");
            return;
        }
    };
    match cbindgen::Builder::new().with_crate(&manifest_dir).with_config(config).generate() {
        Ok(bindings) => {
            let _written = bindings.write_to_file(output_path);
        }
        Err(error) => println!("cargo:warning=failed to generate cbindgen header: {error}"),
    }
}
