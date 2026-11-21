//! Print the room id derived from THIS build's global key, optionally for
//! a passcode word. Ops tool: compare across builds/clones — same hex =
//! same room; pass a word to inspect a passcode room.
//!   cargo run -p onlyhumans_core --example room_id [word]
use onlyhumans_core::rooms::{effective_gk, global_room_hex};

fn main() {
    let word = std::env::args().nth(1);
    let gk = onlyhumans_core::global_key();
    match word.as_deref().map(onlyhumans_core::rooms::normalize_passcode) {
        Some(w) if !w.is_empty() => {
            println!("{}", global_room_hex(&effective_gk(&gk, Some(&w))));
            eprintln!("passcode room for {:?}", w);
        }
        _ => {
            println!("{}", global_room_hex(&gk));
            eprintln!("main room");
        }
    }
}
