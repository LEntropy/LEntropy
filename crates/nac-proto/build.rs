fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = "../../proto";

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(
            &[
                &format!("{proto_dir}/policy.proto"),
                &format!("{proto_dir}/enforcement.proto"),
                &format!("{proto_dir}/agent.proto"),
                &format!("{proto_dir}/events.proto"),
            ],
            &[proto_dir],
        )?;

    Ok(())
}
