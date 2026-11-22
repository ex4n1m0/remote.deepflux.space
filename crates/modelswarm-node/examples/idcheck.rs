fn main() {
    let dir = std::path::PathBuf::from(std::env::var("MSP_DATA_DIR").unwrap());
    let logs = dir.join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    let sink = modelswarm_telemetry::FileSink::open(&logs.join("node.jsonl")).unwrap();
    let telemetry = modelswarm_telemetry::Telemetry::with_sink(Box::new(sink));
    let id = modelswarm_node::load_or_create_identity(&dir, &telemetry).unwrap();
    println!("installation_id: {}", id.installation_id());
    println!("pub_key_b58: {}", id.pub_key_b58());
}
