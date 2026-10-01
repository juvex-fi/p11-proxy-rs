//! A deterministic, seeded mutation fuzzer over the fuzz targets' bodies, so that
//! `cargo test` alone covers them. The real thing (coverage guided, long
//! running) is in `fuzz/`; `FUZZ_ITERATIONS` raises the count here.

use p11_testkit::fuzz;
use p11_wire::calls::samples::{sample_requests, sample_responses};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..1 + rng.below(6) {
        match rng.below(6) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = rng.next() as u8;
            }
            2 if !v.is_empty() => {
                let i = rng.below(v.len());
                v.truncate(i);
            }
            3 => {
                let i = rng.below(v.len() + 1);
                let n = 1 + rng.below(8);
                for _ in 0..n {
                    v.insert(i, rng.next() as u8);
                }
            }
            4 if v.len() > 4 => {
                // a wild length in a random place
                let i = rng.below(v.len() - 3);
                let big = [0xffu8, 0xff, 0xff, 0xff][..1 + rng.below(4)].to_vec();
                for (k, b) in big.iter().enumerate() {
                    if i + k < v.len() {
                        v[i + k] = *b;
                    }
                }
            }
            _ if v.len() > 1 => {
                let i = rng.below(v.len());
                let j = rng.below(v.len());
                v.swap(i, j);
            }
            _ => {}
        }
    }
    v
}

fn iterations() -> usize {
    std::env::var("FUZZ_ITERATIONS").ok().and_then(|s| s.parse().ok()).unwrap_or(4000)
}

#[test]
fn request_and_response_decoders() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let reqs = sample_requests();
    let resps = sample_responses();
    for i in 0..iterations() {
        let k = i % reqs.len();
        let mut seed = reqs[k].call_id().to_be_bytes().to_vec();
        seed.extend(if i % 2 == 0 { reqs[k].encode_body() } else { resps[k].encode_body() });
        fuzz::request(&mutate(&mut rng, &seed));
    }
    // and pure noise
    for _ in 0..iterations() {
        let n = rng.below(200);
        let v: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        fuzz::request(&v);
    }
}

#[test]
fn frames() {
    use p11_wire::frame::{write_frame, Kind};
    let mut rng = Rng(42);
    let mut wire = Vec::new();
    write_frame(&mut wire, Kind::Request, &p11_wire::frame::build_request(1, 4, &sample_requests()[3].encode_body()))
        .unwrap();
    write_frame(
        &mut wire,
        Kind::Response,
        &p11_wire::frame::build_response(1, 0, Some(&sample_responses()[3].encode_body())),
    )
    .unwrap();
    for _ in 0..iterations() {
        fuzz::frame(&mutate(&mut rng, &wire));
    }
}

#[test]
fn dispatcher_sequences() {
    let mut rng = Rng(7);
    let reqs = sample_requests();
    // a plausible session: initialize, then the sample requests in order, then again mutated
    let mut seed = vec![1u8];
    for r in &reqs {
        let body = r.encode_body();
        seed.extend((r.call_id()).to_be_bytes());
        seed.extend((body.len() as u16).to_be_bytes());
        seed.extend(body);
    }
    for _ in 0..iterations() / 4 {
        fuzz::dispatch(&mutate(&mut rng, &seed));
    }
}

#[test]
fn mechanism_trees() {
    let mut rng = Rng(99);
    for _ in 0..iterations() * 4 {
        let n = 3 + rng.below(120);
        let v: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        fuzz::mech(&v);
    }
}

#[test]
fn whole_connections() {
    let mut rng = Rng(5);
    let reqs = sample_requests();
    let mut seed = vec![1u8];
    for (i, r) in reqs.iter().take(12).enumerate() {
        let payload = p11_wire::frame::build_request(i as u32, r.call_id(), &r.encode_body());
        let mut f = Vec::new();
        p11_wire::frame::write_frame(&mut f, p11_wire::frame::Kind::Request, &payload).unwrap();
        seed.extend(f);
    }
    for _ in 0..iterations() / 4 {
        fuzz::stream(&mutate(&mut rng, &seed));
    }
}
