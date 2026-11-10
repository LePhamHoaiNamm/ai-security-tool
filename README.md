# ai-security-tool

Giai đoạn 1: Nền tảng và Thiết lập môi trường (Tuần 1 - 3)
Mục tiêu: Xây dựng bộ khung ứng dụng, thiết lập môi trường Lab và cơ sở dữ liệu.
Sprint 1 (20/10 – 26/10): Khởi tạo dự án, Thiết kế Kiến trúc & Môi trường.
Chốt công nghệ: PHP (XAMPP), CSDL MySQL, API Groq AI.
Tạo kho lưu trữ GitHub, lập đề cương chi tiết.
Thiết kế kiến trúc hệ thống 3 lớp (Regex -> AI -> Hậu xử lý).
Thiết kế CSDL lưu lịch sử quét. Phác thảo giao diện UI/UX.
Cài đặt và cấu hình môi trường Lab DVWA (local) làm mục tiêu kiểm thử.
Sprint 2 (03/11 – 09/11): Dựng khung ứng dụng (Frontend & Backend).
Xây dựng giao diện Web với 2 phân hệ: Phân tích Tĩnh (SAST) và Phân tích Động (DAST).
Kết nối thành công với CSDL MySQL để lưu trữ lịch sử.
Giai đoạn 2: Phát triển các Module cốt lõi (Tuần 4 - 7)
Mục tiêu: Hiện thực hóa các tính năng phân tích và tích hợp Trí tuệ Nhân tạo.
Sprint 3 (10/11 – 16/11): Phân tích Tĩnh (SAST).
Phát triển module đọc mã nguồn PHP, sử dụng bộ lọc Regex để phát hiện các hàm nguy hiểm tiềm ẩn (SQLi, XSS, Upload file).
Sprint 4 (17/11 – 23/11): Phân tích Động (DAST).
Phát triển module tự động tạo Payload và gửi Request đến mục tiêu (thông qua cURL).
Thu thập phản hồi (Response) từ server mục tiêu.
Sprint 5 (24/11 – 30/11): Tích hợp Trí tuệ Nhân tạo (Groq API).
Kết nối Tool với API Groq (Model Llama-3).
Thiết kế Prompt Engineering để AI phân tích dữ liệu từ SAST/DAST, trả về chuẩn JSON (OWASP, CWE, giải thích).
Sprint 6 (01/12 – 07/12): Xử lý kết quả & Trải nghiệm Vibecoder.
Xây dựng giao diện cảnh báo trực quan (Đỏ: Lỗi, Xanh: Giải pháp).
Tích hợp nút "Copy Code An Toàn" để người dùng dán đè lên code cũ.
Giai đoạn 3: Báo cáo và Tính năng mở rộng (Tuần 8)
Mục tiêu: Nâng cao tính ứng dụng của sản phẩm.
Sprint 7 (08/12 – 14/12): Dashboard & Xuất báo cáo.
Xây dựng trang Dashboard thống kê kết quả quét từ Database.
Phát triển tính năng xuất báo cáo ra file PDF/Word.
Bổ sung module quét HTTP Security Headers & SSL.
Giai đoạn 4: Kiểm thử, Đóng gói và Bảo vệ (Tuần 9 - 11)
Mục tiêu: Đánh giá độ chính xác của AI trên môi trường thực tế và hoàn thiện hồ sơ.
Sprint 8 (15/12 – 21/12): Kiểm thử hệ thống trên DVWA.
Chạy Tool để quét các lỗ hổng (SQLi, XSS, Command Injection) có sẵn trên DVWA.
Đối chiếu kết quả AI trả về với kết quả kiểm tra thủ công.
Lập bảng đánh giá độ chính xác và sửa các lỗi phát sinh (Bug fixing).
Sprint 9 (22/12 – 28/12): Hoàn thiện Tài liệu.
Tối ưu giao diện (Responsive).
Viết file hướng dẫn sử dụng (README.md).
Hoàn thiện toàn bộ Báo cáo đồ án (từ Chương 1 đến Chương 5).
Sprint 10 (29/12 – 01/01/2027): Tổng duyệt & Nộp bài.
Xây dựng Slide thuyết trình.
Chuẩn bị kịch bản Demo (sử dụng DVWA để demo trực tiếp).
Đóng gói sản phẩm và nộp bài.
