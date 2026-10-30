//! Static PyArmor recovery with an explicitly supplied companion runtime.
//! Usage: cargo run --example pyarmor-recover -- RUNTIME INPUT OUTPUT_DIRECTORY
use std::{env, fs, path::PathBuf};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err("expected RUNTIME INPUT OUTPUT_DIRECTORY".into());
    }
    let runtime = fs::read(&args[0])?;
    let input = fs::read(&args[1])?;
    let directory = PathBuf::from(&args[2]);
    let mut containers = filefacts::pyarmor::python_containers(&input);
    if containers.is_empty() {
        containers.push(input);
    }
    fs::create_dir_all(&directory)?;
    for (index, container) in containers.iter().enumerate() {
        let recovery = filefacts::pyarmor::recover(&runtime, container)
            .ok_or("unsupported container or runtime")?;
        let pyc = recovery.pyc()?;
        fs::write(directory.join(format!("{index}.analysis.pyc")), &pyc.data)?;
        println!(
            "{}",
            serde_json::json!({"container": index, "code_objects": pyc.code_objects,
            "decrypted_regions": pyc.decrypted_regions, "limitations": pyc.limitations})
        );
    }
    Ok(())
}
