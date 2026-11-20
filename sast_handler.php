<?php
// Sprint 5 — SAST only (phan DAST de Nam lam, file nay khong dung DAST).
// Luong: Regex (lop 1) -> Groq Llama-3 (lop 2, analyzeSASTWithAI)
// -> JSON chuan {owasp, cwe, severity, explain, recommendation, fixed_code}
// Neu Groq loi (chua co key / het quota / sai model) thi roi ve Regex
// (classifySuspicious, da them CWE) + hien the vang, khong bao xanh sai.
require 'analyzer.php';
require 'db.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['code_file'])) {
    $file = $_FILES['code_file']['tmp_name'];
    $code = file_get_contents($file);

    // Lop 1: Quet Regex
    $suspicious = regexPreFilter($code);

    echo "<!DOCTYPE html><html><head><meta charset='UTF-8'><link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'></head><body class='bg-light'><div class='container mt-5'>";
    echo "<h2>📁 Kết quả Phân tích Tĩnh (SAST) — Sprint 5 (Groq AI)</h2><hr>";

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

        // --- LUU VAO DATABASE ---
        try {
            $vuln_count = 0;
            if (!empty($result['has_vulnerability']) && isset($result['vulnerabilities'])) {
                $vuln_count = count($result['vulnerabilities']);
            }
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

        if (isset($result['has_vulnerability']) && $result['has_vulnerability'] === true) {
            foreach ($result['vulnerabilities'] as $vuln) {
                echo "<div class='card mb-4 border-danger shadow-sm'>";
                echo "<div class='card-header bg-danger text-white'><h5>🔴 " . htmlspecialchars($vuln['type']) . " (" . htmlspecialchars($vuln['owasp']) . ")</h5></div>";
                echo "<div class='card-body'>";
                echo "<p><strong>Vị trí:</strong> Dòng " . htmlspecialchars($vuln['line']) . "</p>";
                echo "<p><strong>CWE:</strong> " . htmlspecialchars($vuln['cwe'] ?? 'N/A') . " &nbsp;|&nbsp; <strong>Mức độ:</strong> " . htmlspecialchars($vuln['severity'] ?? 'N/A') . "</p>";
                echo "<p><strong>Giải thích:</strong> " . htmlspecialchars($vuln['explain']) . "</p>";
                if (!empty($vuln['recommendation'])) {
                    echo "<p><strong>Khuyến nghị:</strong> " . htmlspecialchars($vuln['recommendation']) . "</p>";
                }
                echo "<h6 class='mt-4 text-success'>✅ Giải pháp (Code an toàn):</h6>";
                echo "<div class='position-relative'>";
                echo "<pre class='bg-dark text-light p-3 rounded'><code id='code-".md5($vuln['fixed_code'])."'>" . htmlspecialchars($vuln['fixed_code']) . "</code></pre>";
                echo "<button class='btn btn-sm btn-success position-absolute top-0 end-0 m-2' onclick=\"navigator.clipboard.writeText(document.getElementById('code-".md5($vuln['fixed_code'])."').innerText); this.innerText='✅ Đã Copy!';\">📋 Copy Code</button>";
                echo "</div>";
                echo "</div></div>";
            }
        } else {
            echo "<div class='alert alert-success'>✅ AI kết luận: Code không có lỗ hổng nghiêm trọng.</div>";
        }
    }
    echo "<a href='index.php' class='btn btn-primary mt-3'>Quay lại Trang chủ</a>";
    echo "</div></body></html>";
} else {
    echo "Không nhận được file.";
}
?>
