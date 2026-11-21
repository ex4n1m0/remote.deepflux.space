//! Print the peer id of the installed app identity.
//! cargo run -p onlyhumans_core --example app_id -- [data_dir]
use onlyhumans_core::identity::Identity;

fn main() -> anyhow::Result<()> {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "C:/OHuman/onlyhumans".to_string());
    let id = Identity::load_or_create(dir.as_ref())?;
    println!("{}", id.id_string());
    Ok(())
}
