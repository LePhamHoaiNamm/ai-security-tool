<?php
require_once 'config.php';

// LỚP 1: HÀM LỌC THÔ BẰNG REGEX
function regexPreFilter($code) {
    $patterns = [
        '/(mysqli_query|mysql_query)\s*\(/i' => 'Hàm truy vấn SQL thô (Nguy cơ SQL Injection)',
        '/\$_(GET|POST|REQUEST|COOKIE)\s*\[/i' => 'Nhận dữ liệu người dùng trực tiếp',
        '/(eval|system|exec|shell_exec|passthru)\s*\(/i' => 'Hàm thực thi lệnh nguy hiểm',
        '/md5\s*\(/i' => 'Hàm băm mật khẩu yếu (MD5)',
        '/file_get_contents\s*\(/i' => 'Đọc file từ URL (Nguy cơ SSRF)',
        '/(include|require)(_once)?\s*\(\s*\$/i' => 'Include file từ biến (Nguy cơ LFI)'
    ];

    $found_lines = [];
    $lines = explode("\n", (string)$code); 
    
    foreach ($lines as $idx => $line) {
        foreach ($patterns as $pattern => $desc) {
            if (preg_match($pattern, $line)) {
                $found_lines[] = [
                    'line' => $idx + 1,
                    'code' => trim($line),
                    'reason' => $desc
                ];
                break; 
            }
        }
    }
    return $found_lines;
}

// HÀM PHỤ: Bóc tách JSON từ câu trả lời của AI
function extractJson($string) {
    // Tìm khối JSON từ dấu { đầu tiên đến dấu } cuối cùng
    if (preg_match('/\{.*\}/s', $string, $matches)) {
        return $matches[0];
    }
    return '{}';
}

// LỚP 2: HÀM GỌI AI CHO SAST (Upload file)
function callGroqAI($code, $suspicious) {
    $context = "Mã nguồn PHP cần phân tích:\n```php\n" . (string)$code . "\n```\n";
    $context .= "Các dòng nghi vấn do Regex tìm thấy:\n";
    foreach ($suspicious as $s) {
        $line_num = (string)($s['line'] ?? 'N/A');
        $line_code = (string)($s['code'] ?? '');
        $context .= "- Dòng {$line_num}: {$line_code}\n";
    }

    // LỜI NHẮC CỰC GẮT
    $prompt = "Bạn là chuyên gia bảo mật. Hãy tìm lỗ hổng trong mã nguồn PHP sau:\n"
        . $context
        . "\nYÊU CẦU BẮT BUỘC:\n"
        . "1. Trả lời HOÀN TOÀN BẰNG TIẾNG VIỆT (trừ tên lỗ hổng và code).\n"
        . "2. Phải tìm ra lỗi (không được nói code an toàn).\n"
        . "3. Chỉ trả về JSON, KHÔNG kèm text giải thích bên ngoài.\n"
        . "Định dạng JSON:\n"
        . "{\n"
        . "  \"has_vulnerability\": true,\n"
        . "  \"vulnerabilities\": [\n"
        . "    {\n"
        . "      \"type\": \"SQL Injection\",\n"
        . "      \"owasp\": \"A03:2021\",\n"
        . "      \"line\": 10,\n"
        . "      \"explain\": \"(Giải thích lỗi bằng tiếng Việt ở đây)\",\n"
        . "      \"fixed_code\": \"<?php // Code đã sửa ?>\n\"\n"
        . "    }\n"
        . "  ]\n"
        . "}";

    $data = [
        'model' => 'openai/gpt-oss-120b', // Dùng lại model cũ vì nó chạy ổn định
        'messages' => [['role' => 'user', 'content' => $prompt]],
        'temperature' => 0.1
    ];

    $ch = curl_init(GROQ_API_URL);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Authorization: Bearer ' . GROQ_API_KEY
    ]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 60);
    
    $response = curl_exec($ch);
    
    if ($response === false) {
        curl_close($ch);
        return ['has_vulnerability' => false, 'vulnerabilities' => [], 'error' => 'Lỗi kết nối API: ' . curl_error($ch)];
    }
    curl_close($ch);

    $json = json_decode($response, true);
    if (isset($json['error'])) {
        return ['has_vulnerability' => false, 'vulnerabilities' => [], 'error' => 'Groq API: ' . $json['error']['message']];
    }

    $ai_content = $json['choices'][0]['message']['content'] ?? '{}';
    $json_string = extractJson($ai_content); // Dùng hàm bóc tách JSON
    $decoded = json_decode($json_string, true);

    return is_array($decoded) ? $decoded : ['has_vulnerability' => false, 'vulnerabilities' => [], 'error' => 'AI trả về dữ liệu không hợp lệ'];
}

// LỚP 2: HÀM GỌI AI CHO DAST (Quét URL)
function analyzeDASTWithAI($url, $payload_type, $payload, $response_body, $http_code) {
    $response_snippet = substr(strip_tags((string)$response_body), 0, 1000);
    
    $prompt = "Bạn là một chuyên gia kiểm thử xâm nhập (Pentester).\n";
    $prompt .= "Tôi vừa thực hiện tấn công thử nghiệm lỗi **{$payload_type}** vào đường dẫn sau:\n";
    $prompt .= "URL: {$url}\n";
    $prompt .= "Payload sử dụng: {$payload}\n";
    $prompt .= "Mã HTTP trả về: {$http_code}\n\n";
    $prompt .= "Đây là một đoạn trích xuất nội dung (HTML/Text) mà server trả về:\n";
    $prompt .= "```html\n{$response_snippet}\n```\n\n";
    $prompt .= "Dựa vào phản hồi trên, hãy kết luận xem trang web có bị dính lỗ hổng {$payload_type} không.\n";
    $prompt .= "YÊU CẦU: Trường \"reason\" và \"recommendation\" PHẢI VIẾT BẰNG TIẾNG VIỆT. Chỉ trả về JSON.\n";
    $prompt .= "{\n";
    $prompt .= "  \"is_vulnerable\": true,\n";
    $prompt .= "  \"severity\": \"High\",\n";
    $prompt .= "  \"reason\": \"(Giải thích lý do bằng tiếng Việt)\",\n";
    $prompt .= "  \"recommendation\": \"(Lời khuyên khắc phục bằng tiếng Việt)\"\n";
    $prompt .= "}";

    $data = [
        'model' => 'openai/gpt-oss-120b', 
        'messages' => [['role' => 'user', 'content' => $prompt]],
        'temperature' => 0.1
    ];

    $ch = curl_init(GROQ_API_URL);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Authorization: Bearer ' . GROQ_API_KEY
    ]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 60);
    
    $response = curl_exec($ch);
    curl_close($ch);

    $json = json_decode($response, true);
    $ai_content = $json['choices'][0]['message']['content'] ?? '{}';
    $json_string = extractJson($ai_content);
    $decoded = json_decode($json_string, true);

    return is_array($decoded) ? $decoded : ['is_vulnerable' => false, 'reason' => 'AI không phản hồi'];
}
?>
