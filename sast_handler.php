<?php
require 'analyzer.php';
require 'db.php';

// Badge mau theo muc do (AI tra ve High/Medium/Low; Regex mac dinh High)
function severityBadge($severity) {
    $s = strtolower(trim($severity ?? ''));
    if ($s === 'high')   return "<span class='badge bg-danger'>High</span>";
    if ($s === 'medium') return "<span class='badge bg-warning text-dark'>Medium</span>";
    if ($s === 'low')    return "<span class='badge bg-info text-dark'>Low</span>";
    return "<span class='badge bg-secondary'>" . htmlspecialchars($severity ?? 'N/A') . "</span>";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['code_file'])) {
    $file = $_FILES['code_file']['tmp_name'];
    $code = file_get_contents($file);

    // Lop 1: Quet Regex
    $suspicious = regexPreFilter($code);

    echo "<!DOCTYPE html><html><head><meta charset='UTF-8'><link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'></head><body class='bg-light'><div class='container mt-5'>";
    echo "<h2>📁 Kết quả Phân tích Tĩnh (SAST) — Sprint 6 (Groq AI)</h2><hr>";

    if (empty($suspicious)) {
        echo "<div class='alert alert-success'>✅ Code của bạn an toàn! Không phát hiện Regex nguy hiểm.</div>";
    } else {
        echo "<div class='alert alert-warning'>⚠️ Phát hiện " . count($suspicious) . " dòng code nghi vấn. Đang gửi AI phân tích...</div>";
        // Lop 2 (Sprint 5): Goi Groq AI tren du lieu SAST
        $result = analyzeSASTWithAI($code, $suspicious);
        $ai_failed = !empty($result['ai_error']);
        if ($ai_failed) {
            // Roi ve Regex de van co ket qua, khong mat lan quet.
            echo "<div class='alert alert-warning'>⚠️ AI chưa phân tích được (" . htmlspecialchars($result['reason']) . "). Hiển thị kết quả Regex tạm thời — kiểm tra key Groq rồi quét lại.</div>";
            // classifySuspicious() tra ve dung dang {has_vulnerability, vulnerabilities:[...]},
            // khong boc them lop nua.
            $result = classifySuspicious($suspicious);
        }
        // --- LỚP 2: GỌI AI PHÂN TÍCH ---
        // Sửa lỗi: Gọi đúng tên hàm callGroqAI với 2 tham số
        $result = callGroqAI($code, $suspicious);

        // --- LUU VAO DATABASE ---
        try {
            $vuln_count = 0;
            if (!empty($result['has_vulnerability']) && isset($result['vulnerabilities'])) {
                $vuln_count = count($result['vulnerabilities']);
            }

            // Chèn vào bảng scan_history
            $stmt = $pdo->prepare("INSERT INTO scan_history (scan_type, target, vuln_count, details) VALUES (?, ?, ?, ?)");
            $stmt->execute([
                'SAST',
                $_FILES['code_file']['name'],
                $vuln_count,
                json_encode($result)
            ]);
        } catch (Exception $e) {
            echo "<div class='alert alert-danger'>Lỗi lưu DB: " . $e->getMessage() . "</div>";
        }
        // -------------------------

        // Hiển thị kết quả
        if (isset($result['has_vulnerability']) && $result['has_vulnerability'] === true) {
            // Tom tat theo muc do (Sprint 6: nguoi dung thay ngay muc do nghiem trong)
            $countHigh = $countMedium = $countLow = 0;
            foreach ($result['vulnerabilities'] as $v) {
                $s = strtolower(trim($v['severity'] ?? ''));
                if ($s === 'high') $countHigh++;
                elseif ($s === 'medium') $countMedium++;
                elseif ($s === 'low') $countLow++;
            }
            echo "<div class='alert alert-danger'>🔴 Phát hiện " . count($result['vulnerabilities']) . " lỗ hổng: "
                . $countHigh . " Nghiêm trọng (High) &nbsp;|&nbsp; "
                . $countMedium . " Trung bình (Medium) &nbsp;|&nbsp; "
                . $countLow . " Thấp (Low)</div>";

            foreach ($result['vulnerabilities'] as $i => $vuln) {
                echo "<div class='card mb-4 border-danger shadow-sm'>";
                // --- VUNG DO: LOI ---
                echo "<div class='card-header bg-danger text-white'><h5 class='mb-0'>🔴 " . htmlspecialchars($vuln['type']) . " (" . htmlspecialchars($vuln['owasp']) . ")</h5></div>";
                echo "<div class='card-body'>";
                echo "<p><strong>Vị trí:</strong> Dòng " . htmlspecialchars($vuln['line']) . "</p>";
                echo "<p><strong>CWE:</strong> " . htmlspecialchars($vuln['cwe'] ?? 'N/A') . " &nbsp;|&nbsp; <strong>Mức độ:</strong> " . severityBadge($vuln['severity'] ?? '') . "</p>";
                echo "<p><strong>Giải thích:</strong> " . htmlspecialchars($vuln['explain']) . "</p>";
                if (!empty($vuln['recommendation'])) {
                    echo "<p><strong>Khuyến nghị:</strong> " . htmlspecialchars($vuln['recommendation']) . "</p>";
                }
                // --- VUNG XANH: GIAI PHAP ---
                if (!empty($vuln['fixed_code'])) {
                    echo "<div class='border border-success rounded p-3 mt-3' style='background:#eaf7ee;'>";
                    echo "<div class='d-flex justify-content-between align-items-center mb-2'>";
                    echo "<h6 class='mb-0 text-success'>✅ Giải pháp (Code an toàn):</h6>";
                    echo "<button class='btn btn-sm btn-success' onclick=\"copySafeCode('code-" . $i . "', this)\">📋 Copy Code An Toàn</button>";
                    echo "</div>";
                    echo "<pre class='bg-dark text-light p-3 rounded mb-0'><code id='code-" . $i . "'>" . htmlspecialchars($vuln['fixed_code']) . "</code></pre>";
                    echo "</div>";
                }
                echo "<h6 class='mt-4 text-success'>✅ Giải pháp (Code an toàn):</h6>";
                echo "<div class='position-relative'>";
                // Tạo ID ngẫu nhiên cho thẻ code để nút Copy hoạt động
                $code_id = "code-" . md5($vuln['fixed_code']);
                echo "<pre class='bg-dark text-light p-3 rounded'><code id='$code_id'>" . htmlspecialchars($vuln['fixed_code']) . "</code></pre>";
                echo "<button class='btn btn-sm btn-success position-absolute top-0 end-0 m-2' onclick=\"navigator.clipboard.writeText(document.getElementById('$code_id').innerText); this.innerText='✅ Đã Copy!'; setTimeout(() => this.innerText='📋 Copy Code', 2000);\">📋 Copy Code</button>";
                echo "</div>";
                echo "</div></div>";
            }
            // JS copy: dung navigator.clipboard, co fallback cho trinh duyet cu / khong phai HTTPS
            echo "<script>
function copySafeCode(id, btn) {
    var text = document.getElementById(id).innerText;
    var done = function () {
        var old = btn.innerHTML;
        btn.innerHTML = '✅ Đã Copy!';
        btn.disabled = true;
        setTimeout(function () { btn.innerHTML = old; btn.disabled = false; }, 2000);
    };
    var fail = function () {
        btn.innerHTML = '❌ Copy lỗi, thử lại';
        setTimeout(function () { btn.innerHTML = '📋 Copy Code An Toàn'; }, 2000);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(function () { fallbackCopy(text, done, fail); });
    } else {
        fallbackCopy(text, done, fail);
    }
}
function fallbackCopy(text, done, fail) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); done(); } catch (e) { fail(); }
    document.body.removeChild(ta);
}
</script>";
        } else {
            echo "<div class='alert alert-success'>✅ AI kết luận: Code không có lỗ hổng nghiêm trọng.</div>";
=======
            // Nếu AI trả về lỗi
            if (isset($result['error'])) {
                echo "<div class='alert alert-danger'>❌ Lỗi từ AI: " . htmlspecialchars($result['error']) . "</div>";
            } else {
                echo "<div class='alert alert-success'>✅ AI kết luận: Code không có lỗ hổng nghiêm trọng.</div>";
            }

        }
    }
    echo "<a href='index.php' class='btn btn-primary mt-3 mb-5'>Quay lại Trang chủ</a>";
    echo "</div></body></html>";
} else {
    echo "Không nhận được file.";
}
?>