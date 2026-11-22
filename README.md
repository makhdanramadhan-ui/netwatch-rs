![Demo TUI netwatch-rs](docs/demo.gif)

> GIF di atas direkam dari sesi TUI asli saat replay `sample_scan.pcap`; rekaman terminal sumbernya ada di [`docs/demo.cast`](docs/demo.cast).

# netwatch-rs

Monitor paket jaringan real-time dan mini-IDS berbasis aturan yang berjalan di terminal. `netwatch-rs` menangkap paket dari interface langsung atau membaca file `.pcap`, membedah header Ethernet/IPv4/IPv6/TCP/UDP/ICMP dan query DNS, lalu menampilkan statistik, top talkers, dan alert anomaly di TUI `ratatui`.

Proyek ini dibuat untuk mendemonstrasikan pemahaman parsing paket Layer 2–4 dan DNS, desain pipeline capture yang tidak memblokir UI, serta deteksi anomali berbasis *sliding window* tanpa ketergantungan ML.

## Fitur

- Capture live lewat `pcap` dan replay offline `.pcap` (classic pcap, little/big endian, mikro/nanodetik).
- Parser aman untuk Ethernet, IPv4, IPv6, TCP flags, UDP, ICMP/ICMPv6, dan nama domain dari DNS query port 53.
- Statistik 60 detik: PPS, throughput, sparkline, distribusi protokol, dan top talkers.
- Mini-IDS: port scan, SYN spike tanpa pasangan ACK, dan DNS query burst.
- TUI interaktif: filter protokol, pause, tab alert, dan ekspor JSON/CSV.
- Pipeline capture → bounded channel → parser/stats/detector → state → TUI.

## Mulai cepat

### Replay offline (tanpa sudo/root)

```bash
cargo run --release -- --pcap tests/fixtures/sample_scan.pcap
cargo run --release -- --pcap tests/fixtures/sample_scan.pcap --export session.json
```

File fixture berisi 25 paket sintetis: port scan 20 port dari `10.0.0.99`, tiga DNS query, dan dua paket TCP balasan. Jalankan perintah di atas di terminal interaktif untuk melihat TUI. Jika stdout bukan TTY (misalnya di CI), aplikasi otomatis mencetak ringkasan teks dan keluar setelah replay selesai.

### Capture live

```bash
cargo run --release -- --interface eth0
```

`--interface` opsional; tanpa flag aplikasi memilih interface non-loopback pertama. Di Linux, izin raw capture biasanya memerlukan `sudo` atau capability `cap_net_raw,cap_net_admin`. Di Windows, install [Npcap](https://npcap.com/) terlebih dahulu.

## Opsi CLI

| Opsi | Fungsi |
| --- | --- |
| `-i, --interface NAME` | Interface live yang dipakai. |
| `--pcap FILE` | Replay file pcap offline; tidak memerlukan hak raw capture. |
| `-e, --export FILE` | Ekspor laporan saat keluar. `.csv` menulis alert; ekstensi lain menulis JSON lengkap. |

## Kontrol keyboard

| Tombol | Aksi |
| --- | --- |
| `q` / `Esc` | Keluar dan hentikan capture. |
| `p` / `Spasi` | Pause/resume tampilan; mesin capture tetap berjalan. |
| `f` | Ganti filter: ALL → TCP → UDP → DNS → ICMP. |
| `a` | Tampilkan tab Security Alerts. |
| `e` | Ketik nama file ekspor (JSON atau CSV), lalu Enter. |

## Aturan deteksi

| Aturan | Ambang bawaan | Window | Severity |
| --- | --- | --- | --- |
| Port Scan | lebih dari 15 port tujuan unik per IP sumber | 5 detik | WARN |
| SYN Spike | lebih dari 50 SYN tanpa pasangan ACK | 1 detik | CRIT |
| DNS Burst | lebih dari 50 query DNS per host | 10 detik | WARN |

Pasangan ACK dicari dari arah sebaliknya pada 4-tuple yang sama. Alert diberi cooldown 10 detik per aturan dan per IP agar satu insiden tidak membanjiri panel. Ambang bisa diubah lewat `DetectorConfig` di `src/detector.rs`.

## Arsitektur

```text
[interface / .pcap]
        |
        v
capture thread --bounded mpsc (4096)--> parser + stats + detector
        |                                      |
        |                                      v
        +------------------------------> Arc<AppState> (RwLock)
                                               |
                                               v
                                    TUI ratatui/crossterm (10 FPS)
```

Capture memakai `try_send`: jika antrean penuh, paket dihitung sebagai drop, bukan memblokir loop penangkapan. UI hanya membaca snapshot state, sehingga render tidak pernah menahan parser.

## Performance benchmark

Pengukuran parser sintetis: `cargo test --release --test detector_tests parser_throughput -- --ignored --nocapture` memproses 100.000 frame Ethernet/IPv4/UDP.

```text
parser throughput: 19,600,541 packets/s (100,000 synthetic frames, release build, Windows x86_64, 2026-11-22)
```

Angka ini hanya mengukur parser, bukan kapasitas capture live dari interface.

## Known limitations

- Hanya membaca header dan metadata; tidak melakukan dekripsi TLS atau inspeksi payload aplikasi selain nama domain DNS query.
- Deteksi berbasis rule dan threshold, bukan ML; threshold perlu disesuaikan dengan trafik normal lingkungan nyata.
- Reassembly IP fragments tidak dilakukan; paket fragmen masih dihitung sebagai trafik tetapi L4 tidak dibaca.
- Live capture pada Windows memerlukan driver Npcap; mode `--pcap` tetap bekerja tanpa driver.
- Timestamp TUI ditampilkan dalam UTC berdasarkan UNIX epoch, bukan timezone lokal.

## Build dan test

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

GitHub Actions menjalankan tiga perintah tersebut plus smoke test replay fixture. Dependensi utama: `pcap`, `etherparse`, `ratatui`, `crossterm`, `clap`, `serde`, dan `serde_json`.

## Simulasi lokal

```bash
python scripts/simulate_attack.py --mode all
python scripts/simulate_attack.py --mode scan --ports 20
python scripts/simulate_attack.py --mode dns --count 60
```

Skrip hanya mengirim trafik ke `127.0.0.1` atau `::1` dan menolak host lain.

## Lisensi

MIT. Lihat `LICENSE`.
