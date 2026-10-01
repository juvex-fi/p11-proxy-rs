# Benchmarks

`scripts/bench.sh [seconds] [threads]` runs `p11-bench` (a loop of PKCS#11 calls
per thread, each on its own session) against SoftHSM directly, against this
proxy and against the C proxy, over a local unix socket, and prints operations
per second and the median and 99th percentile latency.

Numbers from one run on an Apple M1 (macOS), SoftHSM 2.7, release builds, the
daemon with `--sandbox off`, 2 seconds per operation. They are indicative:
run-to-run noise is a few per cent, and a real HSM or a network changes the
picture entirely, because then the module or the round trip dominates.

## One thread

| operation | SoftHSM directly | this proxy | C proxy |
|---|---:|---:|---:|
| `C_GetInfo` | 15 700 000 /s | 160 000 /s (p50 5 µs) | 151 000 /s (p50 6 µs) |
| `C_GenerateRandom` 32 bytes | 2 680 000 /s | 135 000 /s (6 µs) | 134 000 /s (7 µs) |
| SHA-256 of 1 KiB | 1 050 000 /s | 63 000 /s (15 µs) | 66 000 /s (14 µs) |
| HMAC-SHA256 of 1 KiB | 225 000 /s | 48 000 /s (20 µs) | 49 000 /s (19 µs) |
| RSA-2048 sign | 1 211 /s | 1 175 /s (848 µs) | 1 169 /s (849 µs) |

## Eight threads

| operation | SoftHSM directly | this proxy | C proxy |
|---|---:|---:|---:|
| `C_GetInfo` | 58 000 000 /s | 262 000 /s (p50 28 µs) | 259 000 /s (29 µs) |
| `C_GenerateRandom` 32 bytes | 864 000 /s | 232 000 /s (31 µs) | 238 000 /s (29 µs) |
| SHA-256 of 1 KiB | 378 000 /s | 120 000 /s (63 µs) | 128 000 /s (58 µs) |
| HMAC-SHA256 of 1 KiB | 97 000 /s | 65 000 /s (109 µs) | 64 000 /s (110 µs) |
| RSA-2048 sign | 5 746 /s | 5 122 /s (1.26 ms) | 5 355 /s (1.12 ms) |

## Reading them

- A proxied call costs one round trip: about 5 µs of latency over a local
  socket on top of the module's own time. Anything that takes the module
  longer than that (signatures, key generation) is dominated by the module.
- This proxy and the C one are within a few per cent of each other, either way.
- What made the small calls fast (measured, each step): reading a frame with
  one system call instead of one per field, setting socket timeouts only when
  they change, and probing an idle connection for a dead peer only after it has
  been idle for half a second. Before those, small calls were 10-20% slower
  than the C proxy.
- With eight threads the client's pool opens up to eight connections, each with
  its own daemon thread, so throughput scales with the module, not with the
  proxy.
