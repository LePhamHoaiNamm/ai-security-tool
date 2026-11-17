<?php
require 'analyzer.php';
require 'db.php';

// Bật hiển thị lỗi để dễ debug
ini_set('display_errors', 1);
error_reporting(E_ALL);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // 1. KIỂM TRA DỮ LIỆU ĐẦU VÀO
    if (empty($_POST['target_url'])) {
        die("<div class='alert alert-danger'>Lỗi: Không nhận được URL. Vui lòng nhập lại!</div>");
    }

    $url = trim($_POST['target_url']);
    
    // Xử lý Cookie (Nếu người dùng chỉ nhập session, tự động thêm PHPSESSID và security)
    $raw_cookie = trim($_POST['cookie_data'] ?? '');
    $cookie = '';
    if (!empty($raw_cookie)) {
        if (strpos($raw_cookie, '=') === false && strlen($raw_cookie) > 20) {
            $cookie = "PHPSESSID=" . $raw_cookie . "; security=low";
        } else {
            $cookie = $raw_cookie;
        }
    }
    
    // 2. KIỂM TRA URL HỢP LỆ
    $parsed_url = parse_url($url);
    if ($parsed_url === false || !isset($parsed_url['host'])) {
        die("<div class='alert alert-danger'>Lỗi: URL không hợp lệ. Hãy chắc chắn URL có dạng <strong>http://...</strong></div>");
    }

    // Lấy Query String
    $query_string = $parsed_url['query'] ?? '';
    if (empty($query_string)) {
        die("<div class='alert alert-danger'>Lỗi: URL phải có tham số (VD: ?id=1) để Tool có thể chèn Payload!</div>");
    }

    parse_str($query_string, $query_params);
    if (empty($query_params)) {
        die("<div class='alert alert-danger'>Lỗi: Không đọc được tham số từ URL!</div>");
    }

    // Lấy tham số đầu tiên để test
    $param_key = array_key_first($query_params);
    
    // Bộ Payload tấn công
    $payloads = [
        'SQL Injection' => "1' OR '1'='1", 
        'Cross-Site Scripting (XSS)' => "<script>alert('XSS')</script>",
        'Command Injection' => "127.0.0.1; whoami",
        'Local File Inclusion (LFI)' => "../../../../etc/passwd"
    ];

    $all_results = [];
    $total_vulns = 0;

    echo "<h4 class='mb-3'>🎯 Kết quả Phân tích Động (DAST)</h4>";
    echo "<p>Mục tiêu: <strong>" . htmlspecialchars($url) . "</strong></p>";
    echo "<p>Tham số test: <code>" . htmlspecialchars($param_key) . "</code></p><hr>";

    // 3. VÒNG LẶP GỬI PAYLOAD
    foreach ($payloads as $type => $payload) {
        
        // --- SỬA LỖI MALFORMED URL: Mã hóa payload trước khi ghép vào URL ---
        $encoded_payload = urlencode($payload);
        $new_query = preg_replace(
            '/(^|&)' . preg_quote($param_key, '/') . '=[^&]*/',
            '$1' . $param_key . '=' . $encoded_payload,
            $query_string
        );

        $scheme = $parsed_url['scheme'] ?? 'http';
        $port = isset($parsed_url['port']) ? ':' . $parsed_url['port'] : '';
        $path = $parsed_url['path'] ?? '';
        
        // Tạo URL Test hoàn chỉnh
        $test_url = $scheme . '://' . $parsed_url['host'] . $port . $path . '?' . $new_query;

        echo "<div class='card mb-4 shadow-sm border-secondary'>";
        echo "<div class='card-header bg-dark text-white'>Đang test: <strong class='text-warning'>$type</strong></div>";
        echo "<div class='card-body'>";
        echo "<p><strong>Payload:</strong> <code>" . htmlspecialchars($payload) . "</code></p>";
        echo "<p class='text-muted small'><strong>URL Test:</strong> " . htmlspecialchars($test_url) . "</p>";

        $ch = curl_init($test_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); // Tắt follow để biết nếu bị redirect
        curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4); 
        
        if (!empty($cookie)) {
            curl_setopt($ch, CURLOPT_COOKIE, $cookie);
        }
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if ($response === false) {
            echo "<div class='alert alert-danger'>Lỗi cURL: " . curl_error($ch) . "</div>";
            curl_close($ch);
            echo "</div></div>";
            continue;
        }
        curl_close($ch);

        if ($http_code == 302) {
            echo "<div class='alert alert-warning'>Cảnh báo: Bị Redirect (302). Có thể bạn chưa đăng nhập, hãy kiểm tra lại Cookie PHPSESSID!</div>";
            echo "</div></div>";
            continue;
        } elseif ($http_code != 200) {
            echo "<div class='alert alert-warning'>Lỗi: Server trả về HTTP $http_code</div>";
            echo "</div></div>";
            continue;
        }

        echo "<p class='text-muted'>⏳ AI đang phân tích phản hồi...</p>";

        // Gọi AI Phân tích
        $ai_result = analyzeDASTWithAI($test_url, $type, $payload, $response, $http_code);
        
        $all_results[] = ['type' => $type, 'result' => $ai_result];
        
        $is_vuln = isset($ai_result['is_vulnerable']) && ($ai_result['is_vulnerable'] === true || $ai_result['is_vulnerable'] === 'true');
        
        if ($is_vuln) {
            $total_vulns++;
            echo "<div class='alert alert-danger border-danger'>";
            echo "<h5 class='fw-bold'>🚨 PHÁT HIỆN LỖ HỔNG: " . strtoupper($type) . "</h5>";
            echo "<p><strong>Mức độ:</strong> <span class='badge bg-danger'>" . htmlspecialchars($ai_result['severity'] ?? 'High') . "</span></p>";
            echo "<p><strong>Bằng chứng:</strong> " . htmlspecialchars($ai_result['reason'] ?? 'N/A') . "</p>";
            echo "<hr>";
            echo "<p class='mb-0'><strong>💡 Cách khắc phục:</strong> " . htmlspecialchars($ai_result['recommendation'] ?? 'N/A') . "</p>";
            echo "</div>";
        } else {
            echo "<div class='alert alert-success'>";
            echo "<h6 class='fw-bold'>✅ Không phát hiện lỗ hổng $type rõ ràng.</h6>";
            echo "<p class='mb-0 small'>Lý do: " . htmlspecialchars($ai_result['reason'] ?? 'Server phản hồi bình thường.') . "</p>";
            echo "</div>";
        }

        echo "</div></div>"; 
    }
    
    // Lưu vào Database
    try {
        $stmt = $pdo->prepare("INSERT INTO scan_history (scan_type, target, vuln_count, details) VALUES (?, ?, ?, ?)");
        $stmt->execute(['DAST', $url, $total_vulns, json_encode($all_results)]);
    } catch (Exception $e) {
        echo "<div class='alert alert-danger mt-3'>Lỗi lưu DB: " . $e->getMessage() . "</div>";
    }

    echo "<div class='text-center mt-4 mb-5'><a href='scan.php' class='btn btn-primary px-4'>Quay lại Quét</a></div>";

} else {
    header("Location: scan.php");
    exit;
}
?>