fn main() {
    let p = flowtcp_tls::chbuilder::ClientHelloParams::new("flowtcp.test", [0xAA; 32], [0x11; 32]);
    let ch = flowtcp_tls::chbuilder::build_client_hello(&p);
    println!("TOTAL={}", ch.len());
    for (i, b) in ch.iter().enumerate() {
        if i % 16 == 0 {
            print!("\n{:04x}: ", i);
        }
        print!("{:02x} ", b);
    }
    println!();
    std::fs::write("/tmp/ch.bin", &ch).unwrap();
}
