use chrono::Utc;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use rand::RngExt;

// Generate a domain based off the date & root
pub fn generate_domain(date: String, root: &str) -> String {
    // Seed for the random number generator
    let mut seedbytes = [0u8; 32];
    seedbytes[0] = 42;
    seedbytes[1..date.len()+1].copy_from_slice(date.as_bytes());

    let mut rng = StdRng::from_seed(seedbytes);

    // Vec of valid characters to use in domain
    let chars: Vec<char> =
        "0123456789abcdefghijklmnopqrstuvwxyz"
        .chars()
        .collect();

    // n character domain
    let domain: String = (0..32)
        .map(|_| chars[rng.random_range(0..chars.len())])
        .collect();

    return format!("{domain}.{root}");
}

// Generate today's domain using a root, i.e. myc2.com
pub fn generate_domain_now(root: &str) -> String {
    let date = Utc::now().date_naive().format("%Y%m%d").to_string();
    return generate_domain(date, root);
}
