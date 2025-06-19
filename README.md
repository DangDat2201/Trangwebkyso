# 🔐 Ứng Dụng Truyền File An Toàn: Ký Số & Mã Hóa

## 🧩 Giới thiệu

Đây là một ứng dụng web demo minh họa cách **ký số**, **xác minh**, **mã hóa** và **giải mã** dữ liệu file một cách an toàn bằng các thuật toán mã hóa hiện đại. Ứng dụng sử dụng giao diện trực quan và đẹp mắt (HTML/CSS/JS) kết hợp với backend bảo mật bằng Python Flask.

> ⚠️ **Cảnh báo bảo mật:** Ứng dụng này chỉ mang tính chất minh họa và giáo dục. KHÔNG nên sử dụng với dữ liệu hoặc khóa thực trong môi trường sản xuất.

---

## 🚀 Chức năng chính

1. **Tạo cặp khóa RSA**
   - Tạo khóa công khai và khóa riêng (có thể bảo vệ bằng mật khẩu).
   - Xuất chuỗi PEM dùng để ký số hoặc mã hóa.

2. **Ký số file**
   - Dùng khóa riêng để tạo chữ ký số.
   - Trả về chữ ký dạng Base64.

3. **Xác minh chữ ký**
   - Dùng khóa công khai và chữ ký để xác minh tính toàn vẹn file.

4. **Mã hóa file**
   - Mã hóa nội dung file bằng AES (khóa phiên), sau đó mã hóa khóa phiên bằng RSA công khai.

5. **Giải mã file**
   - Giải mã khóa phiên bằng khóa riêng RSA, sau đó giải mã nội dung file AES.

---

## 🛠 Công nghệ sử dụng

- **Frontend**: `HTML`, `CSS` thuần, `JavaScript`
- **Backend**: `Python 3`, `Flask`
- **Mã hóa & Ký số**: `cryptography`, `RSA`, `AES`, `SHA256`, `PSS`, `OAEP`
- **Khác**: `base64`, `secrets`, `tempfile`, `logging`

---



