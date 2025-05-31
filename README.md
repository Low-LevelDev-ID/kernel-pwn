# kernel-pwn
# 🧠 Kernel Exploitation Roadmap – LowLevelDev ID

Selamat datang di **LowLevelDev ID Kernel Pwn Repo** – ini adalah repositori tantangan eksploitasi kernel Linux dari tingkat pemula hingga tingkat lanjutan, lengkap dengan materi dan skenario eksploitasi realistis.

Roadmap ini dirancang agar kamu bisa belajar **step-by-step** dengan mengikuti urutan tantangan, sambil memahami teknik eksploitasi, objek yang dieksploitasi, serta strategi untuk mendapatkan kontrol eksekusi atau eskalasi privilese di kernel Linux.

---

## 🔰 Level: Dasar (Pemula)

Dirancang untuk membangun fondasi eksploitasi kernel seperti buffer overflow, heap overflow, dan use-after-free tanpa mitigasi berat.

### 🧪 `pawnyable-LK01`
- **Bug**: Stack-based buffer overflow
- **Primitive**: Overwrite RIP
- **Teknik**: ROP chain via buffer overflow
- **Goal**: Mendapatkan shell via kontrol instruksi pointer

### 🧪 `pawnyable-LK01-2`
- **Bug**: Heap overflow
- **Objek**: `tty_struct`
- **Teknik**: Overwrite `tty_operations` → eksekusi fungsi arbitrary
- **Goal**: Gunakan ROP untuk mendapat shell

### 🧪 `pawnyable-LK01-3`
- **Bug**: Double free / Use-after-free
- **Objek & Teknik Alternatif**:
  - `msg_msg` + `pipe_buffer`
  - `sk_buff` + `pipe` + `modprobe_path`
  - `tty_struct`
- **Goal**: Reclaim objek dan kontrol RIP atau overwrite path

---

## ⚙️ Level: Menengah

Masuk ke skenario dunia nyata dengan mitigasi aktif seperti SLUB hardening dan validasi `list_head`.

### 🧪 `pawnyable-LK04-fuse`
- **Bug**: UAF + protected list corruption
- **Objek**: `tty_struct` dalam konteks FUSE
- **Teknik**: Reclaim + bypass list poisoning
- **Goal**: Eksekusi arbitrary melalui fungsi pointer

### 🧪 `pawnyable-LK04-uffd`
- **Bug**: UAF + list corruption
- **Objek**: `tty_struct`
- **Teknik**: `userfaultfd` untuk trigger race reclaim
- **Goal**: Eksploitasi UAF dengan timing presisi

### 🧪 `bilik_mod`
- **Bug**: UAF/double free
- **Objek**: `sk_buff` + `pipe_buffer page`
- **Teknik**: Reclaim + leak address fisik kaslr
- **Goal**: modprobe_path overwrite

### 🧪 `fire-of-salvation`
- **Bug**: Netfilter UAF sederhana
- **Objek**: `msg_msg`
- **Teknik**: `userfaultfd` + heap shaping
- **Goal**: Gunakan UAF untuk overwrite sensitive data

---

## 🔥 Level: Sulit

Didesain untuk peserta lanjutan atau praktisi profesional. Eksploitasi memerlukan chaining primitive kompleks dan pemahaman allocator.

### 🧪 `Cheminventory`
- **Bug**: UAF + list corruption
- **Objek**: `msg_msg` + `pipe_buffer` + `sk_buff`
- **Teknik**: Chaining reuse object dengan heap shaping
- **Goal**: Eksekusi arbitrary melalui objek reclaim kompleks

### 🧪 `Palindromatic_Bi0sCTF2024`
- **Bug**: UAF / double free dengan SLAB_VIRTUAL
- **Teknik**: Dirty Pipe leak + reclaim
- **Goal**: Eksploitasi SLAB_VIRTUAL yang hardened

### 🧪 `cache-of-castaways`
- **Bug**: Out-of-bounds 6-byte
- **Teknik**: Cross-cache (SLUB → Buddy allocator) → overwrite `cred`
- **Goal**: Privilege escalation ke root

### 🧪 `keasy`
- **Bug**: UAF pada objek file
- **Teknik**:
  - Dirty page table overwrite
  - `dmabuf_heaps` untuk memanipulasi PTE
  - Shellcode di userland
- **Goal**: Eksekusi arbitrary code di kernel mode

---

## 🧬 Level: Eksperimental / Real-world Inspired

Menggunakan skenario eksploitasi tingkat lanjut yang terinspirasi dari teknik exploitasi baru dan exploitasi cve kernel linux yang populer.

### 🧪 `bamcross`
- **Bug**: OOB 0-byte
- **Teknik**: Pagejack + pipe UAF
- **Goal**: Overwrite `/etc/shadow` untuk mengganti password root

### 🧪 `bamcache`
- **Bug**: OOB 0-byte
- **Teknik**: Cross-cache + pagejack + pipe UAF
- **Goal**: Elevate privilege via page hijack

### 🧪 `bampage`
- **Bug**: UAF (order-0 page)
- **Teknik**: Dirty page table overwrite
- **Objek**: `modprobe_path`
- **Goal**: Arbitrary code execution via modprobe hijack

---

## 📘 Tips Belajar
- 🧠 Pelajari objek kernel: `msg_msg`, `pipe_buffer`, `tty_struct`, `sk_buff`
- 📊 Cek cache: `cat /sys/kernel/slab/*/aliases`, `slabinfo`, dan `kmem_cache`
- 🔐 Lihat struktur `cred`, `task_struct`, dan path seperti `modprobe_path`

---

## 🤝 Kontribusi & Komunitas

Kami membuka kontribusi dari siapa pun yang ingin membuat tantangan, writeup, atau modul kernel baru. Silakan join komunitas Telegram kami:  
👉 [t.me/lowleveldevID](https://t.me/lowleveldevID)

Atau kunjungi blog writeup kami:  
👉 [https://bam0x7.github.io/](https://bam0x7.github.io/)

---

## 🎁 Bonus

### 🧪 `bamfile`
- **Bug**: ???
- **Status**: Belum diketahui – tantangan misterius
- **Goal**: Tantangan bonus spesial untuk penggemar kernel pwn sejati 💀
- **Catatan**: Tidak ada petunjuk di awal. Eksplorasi, analisis source, dan temukan sendiri vektornya!

🧠 Jika kamu berhasil menyelesaikannya, silakan share writeup-mu ke komunitas!

---

---



