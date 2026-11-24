<?php
// Sprint 5 (SAST only — phan DAST de Nam lam, khong sua):
//   Lop 2 SAST moi: analyzeSASTWithAI() goi Groq Llama-3, prompt engineering
//   tren du lieu SAST (cac dong nghi van cua Regex), tra JSON chuan gom
//   OWASP + CWE + giai thich + fixed_code. Neu Groq loi, sast_handler.php
//   roi ve classifySuspicious (Regex, da them CWE) de khong mat ket qua.
// Sprint 4: Phan tich Dong (DAST) - Gop 2 lop:
//   Lop 1 (Sprint 3): Regex loc tho + classifySuspicious (khong dung AI).
//   Lop 2 (Sprint 4): analyzeDASTWithAI goi Groq de phan tich phan hoi
//   cua server sau khi gui Payload (lay doan quanh payload lam bang chung,
//   KHONG dung strip_tags de khoi mat the <script>).
// Khong gom callGroqAI (AI cho SAST, da thay bang Regex o Sprint 3).
// config.php chi duoc nap khi goi analyzeDASTWithAI, de SAST van chay
// duoc khi chua co config.php (config.php chi o may local, khong commit).

// LOP 1: HAM LOC THO BANG REGEX
function regexPreFilter($code) {
    // Thu tu pattern quan trong: pattern cu the duoc kiem tra truoc.
    // Vi du: dong move_uploaded_file(...$_FILES...) phai nhan la Upload,
    // khong phai la nhan du lieu nguoi dung chung chung.
    $patterns = [
        'sqli'   => ['/(mysqli_query|mysql_query)\s*\(/i', 'Ham truy van SQL tho (Nguy co SQL Injection)'],
        'upload' => ['/move_uploaded_file\s*\(/i', 'Upload file khong kiem tra dinh dang (Nguy co Upload file doc hai)'],
        'cmdi'   => ['/(eval|system|exec|shell_exec|passthru)\s*\(/i', 'Ham thuc thi lenh nguy hiem'],
        'md5'    => ['/md5\s*\(/i', 'Ham bam mat khau yeu (MD5)'],
        'input'  => ['/\$_(GET|POST|REQUEST|COOKIE|FILES)\s*\[/i', 'Nhan du lieu nguoi dung truc tiep'],
        'ssrf'   => ['/file_get_contents\s*\(/i', 'Doc file tu URL (Nguy co SSRF)'],
        'lfi'    => ['/(include|require)(_once)?\s*\(\s*\$/i', 'Include file tu bien (Nguy co LFI)']
    ];

    $found_lines = [];
    $lines = explode("\n", (string)$code);

    foreach ($lines as $idx => $line) {
        foreach ($patterns as $kind => $p) {
            if (preg_match($p[0], $line)) {
                $found_lines[] = [
                    'line' => $idx + 1,
                    'code' => trim($line),
                    'reason' => $p[1],
                    'kind' => $kind
                ];
                break;
            }
        }
    }
    return $found_lines;
}

// LOP 1 (tiep): Phan loai dong nghi van thanh lo hong cu the (khong dung AI)
// Tra ve cung dinh dang JSON nhu ban dung AI, de dashboard/history khong phai sua.
function classifySuspicious($suspicious) {
    $findings = [];
    foreach ($suspicious as $s) {
        $code = $s['code'] ?? '';
        $line = $s['line'] ?? 0;
        switch ($s['kind'] ?? '') {
            case 'sqli':
                $findings[] = [
                    'type' => 'SQL Injection',
                    'owasp' => 'A03:2021',
                    'cwe' => 'CWE-89',
                    'severity' => 'High',
                    'line' => $line,
                    'explain' => 'Cau truy van SQL duoc noi chuoi truc tiep tu du lieu nguoi dung ma khong dung prepared statement, ke tan cong co the chen cau lenh SQL vao de doc, sua hoac xoa du lieu.',
                    'fixed_code' => "\$stmt = \$conn->prepare(\"SELECT * FROM users WHERE id = ?\");\n\$stmt->bind_param(\"i\", \$id);\n\$stmt->execute();"
                ];
                break;
            case 'upload':
                $findings[] = [
                    'type' => 'Unrestricted File Upload',
                    'owasp' => 'A03:2021',
                    'cwe' => 'CWE-434',
                    'severity' => 'High',
                    'line' => $line,
                    'explain' => 'File upload khong kiem tra dinh dang va ten file, ke tan cong co the tai len file PHP doc hai roi chay no tren server.',
                    'fixed_code' => "\$allowed = ['jpg', 'png', 'pdf'];\n\$ext = strtolower(pathinfo(\$_FILES['file']['name'], PATHINFO_EXTENSION));\nif (!in_array(\$ext, \$allowed)) { die('Dinh dang file khong cho phep'); }\nmove_uploaded_file(\$_FILES['file']['tmp_name'], 'uploads/' . basename(\$_FILES['file']['name']));"
                ];
                break;
            case 'cmdi':
                $findings[] = [
                    'type' => 'Command Injection',
                    'owasp' => 'A03:2021',
                    'cwe' => 'CWE-78',
                    'severity' => 'High',
                    'line' => $line,
                    'explain' => 'Ham thuc thi lenh he thong nhan truc tiep du lieu nguoi dung, ke tan cong co the chen lenh he dieu hanh vao de chiem quyen server.',
                    'fixed_code' => "// Khong dung exec/system voi du lieu nguoi dung.\n// Neu bat buoc: \$cmd = 'ping ' . escapeshellarg(\$ip);"
                ];
                break;
            case 'md5':
                $findings[] = [
                    'type' => 'Weak Password Hashing',
                    'owasp' => 'A02:2021',
                    'cwe' => 'CWE-327',
                    'severity' => 'Medium',
                    'line' => $line,
                    'explain' => 'MD5 la ham bam yeu, bi pha bang bang tra cuu (rainbow table) rat nhanh, khong du an toan de luu mat khau.',
                    'fixed_code' => "\$hash = password_hash(\$password, PASSWORD_DEFAULT);"
                ];
                break;
            case 'input':
                if (preg_match('/\b(echo|print)\b/i', $code)) {
                    $findings[] = [
                        'type' => 'Cross-Site Scripting (XSS)',
                        'owasp' => 'A03:2021',
                    'cwe' => 'CWE-79',
                        'severity' => 'High',
                        'line' => $line,
                        'explain' => 'Du lieu nguoi dung duoc in truc tiep ra trang ma khong ma hoa, ke tan cong co the chen ma JavaScript doc hai vao de danh cap phien dang nhap cua nguoi khac.',
                        'fixed_code' => "echo htmlspecialchars(\$_GET['name'], ENT_QUOTES, 'UTF-8');"
                    ];
                } else {
                    $findings[] = [
                        'type' => 'Unvalidated User Input',
                        'owasp' => 'A03:2021',
                    'cwe' => 'CWE-20',
                        'severity' => 'Medium',
                        'line' => $line,
                        'explain' => 'Du lieu nguoi dung duoc nhan truc tiep ma khong kiem tra dinh dang, co the la dau vao cho cac lo hong SQL Injection hoac XSS o dong khac.',
                        'fixed_code' => "\$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);\nif (\$id === false) { die('ID khong hop le'); }"
                    ];
                }
                break;
            case 'ssrf':
                $findings[] = [
                    'type' => 'Server-Side Request Forgery (SSRF)',
                    'owasp' => 'A10:2021',
                    'cwe' => 'CWE-918',
                    'severity' => 'Medium',
                    'line' => $line,
                    'explain' => 'Ham doc file co the doc noi dung tu URL do nguoi dung cung cap, ke tan cong co the dung server de quet dich vu noi bo.',
                    'fixed_code' => "if (!filter_var(\$url, FILTER_VALIDATE_URL)) { die('URL khong hop le'); }\n// Chi cho phep domain tin cay."
                ];
                break;
            case 'lfi':
                $findings[] = [
                    'type' => 'Local File Inclusion (LFI)',
                    'owasp' => 'A01:2021',
                    'cwe' => 'CWE-98',
                    'severity' => 'High',
                    'line' => $line,
                    'explain' => 'Ten file include lay tu bien do nguoi dung dieu khien, ke tan cong co the doi duong dan de doc file he thong.',
                    'fixed_code' => "\$allowed = ['home.php', 'about.php'];\n\$page = \$_GET['page'] ?? 'home.php';\nif (!in_array(\$page, \$allowed, true)) { die('Trang khong hop le'); }\ninclude \$page;"
                ];
                break;
        }
    }
    return ['has_vulnerability' => !empty($findings), 'vulnerabilities' => $findings];
}

// LỚP 2: HÀM GỌI AI CHO DAST (Quét URL)
// ================= SPRINT 5 — LOP 2 SAST: GROQ AI =================
// Nhiem vu Sprint 5 (chi SAST): ket noi Groq API (Llama-3), prompt
// engineering tren du lieu SAST, yeu cau AI tra JSON chuan gom OWASP,
// CWE va giai thich lo hong. Phan DAST khong dung ham nay (Nam lam).
// $suspicious: ket qua regexPreFilter($code) — moi phan tu co line/code/reason/kind.
// Tra ve: ['has_vulnerability'=>bool, 'vulnerabilities'=>[...]]
//   moi vulnerability: type, owasp, cwe, severity, line, explain,
//   recommendation, fixed_code.
//   Hoac ['ai_error'=>true, 'reason'=>...] khi Groq loi — de handler
//   roi ve Regex thay vi bao xanh sai.
function analyzeSASTWithAI($code, $suspicious) {
    if (!defined('GROQ_API_KEY') || !defined('GROQ_API_URL')) {
        $cfg = __DIR__ . '/config.php';
        if (file_exists($cfg)) { require_once $cfg; }
    }
    if (!defined('GROQ_API_KEY') || !defined('GROQ_API_URL') || stripos(GROQ_API_KEY, 'YOUR_') === 0 || GROQ_API_KEY === '') {
        return ['ai_error' => true, 'reason' => 'Chua co Groq API key trong config.php (copy config.example.php thanh config.php roi dien key moi).'];
    }

    // --- Prompt Engineering (Sprint 5) ---
    // Dua cho AI dung 2 thu: (1) toan bo code, (2) danh sach dong nghi van
    // cua Regex (line + code that). AI chi duoc ket luan tren cac dong nay,
    // khong duoc bia them lo hong o dong khac.
    $lines = [];
    foreach ($suspicious as $s) {
        $lines[] = 'Dong ' . ($s['line'] ?? '?') . ': ' . ($s['code'] ?? '') . '  // Regex: ' . ($s['reason'] ?? '');
    }
    $evidence = implode("\n", $lines);
    $prompt = "Ban la chuyen gia bao mat ung dung web. Phan tich doan code PHP duoi day. "
        . "Lop Regex da danh dau cac dong nghi van sau, hay dung chung lam bang chung chinh:\n"
        . $evidence . "\n\n"
        . "Code day du:\n```php\n" . $code . "\n```\n\n"
        . "Tra ve DUNG dinh dang JSON nay, khong them text thua, khong markdown:\n"
        . "{\n"
        . '  "has_vulnerability": true,' . "\n"
        . '  "vulnerabilities": [' . "\n"
        . '    {"type": "SQL Injection", "owasp": "A03:2021", "cwe": "CWE-89", "severity": "High", "line": 12, "explain": "Giai thich ngan gon tai sao day la lo hong", "recommendation": "Cach khac phuc bang loi", "fixed_code": "<?php // Code PHP chay duoc, da sua an toan ?>"},' . "\n"
        . "  ]\n}\n"
        . "Quy tac:\n"
        . "1. Chi bao lo hong o cac dong Regex da danh dau. Neu dong do that ra an toan thi bo qua, khong co gang tim lo hong khac.\n"
        . "2. owasp theo OWASP Top 10 2021 (VD: SQL Injection/XSS/Upload la A03:2021, mat khau yeu la A02:2021, LFI la A01:2021, SSRF la A10:2021).\n"
        . "3. cwe la ma CWE chinh xac nhat (VD: SQL Injection CWE-89, XSS CWE-79, Upload CWE-434, Command Injection CWE-78, MD5 CWE-327, LFI CWE-98, SSRF CWE-918).\n"
        . "4. fixed_code phai la code PHP chay duoc, dung prepared statement / htmlspecialchars / password_hash / kiem tra dinh dang file tuy loai, khong de lai cho chong payload.\n"
        . "5. Neu khong co lo hong that thi tra has_vulnerability=false va vulnerabilities=[].";

    $model = 'openai/gpt-oss-120b'; // Groq da ngung Llama-3 tu 16/08/2026 (chi Enterprise); gpt-oss-120b la model thay the chinh thuc
    $data = [
        'model' => $model,
        'messages' => [['role' => 'user', 'content' => $prompt]],
        'temperature' => 0.1,
        'response_format' => ['type' => 'json_object'],
    ];
    $ch = curl_init(GROQ_API_URL);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_TIMEOUT, 60);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json', 'Authorization: Bearer ' . GROQ_API_KEY]);
    $response = curl_exec($ch);
    if ($response === false) {
        $err = curl_error($ch); curl_close($ch);
        return ['ai_error' => true, 'reason' => 'Loi ket noi Groq API: ' . $err];
    }
    curl_close($ch);
    $json = json_decode($response, true);
    if (!isset($json['choices'][0]['message']['content'])) {
        $err = $json['error']['message'] ?? 'Groq khong tra ve ket qua';
        if (stripos($err, 'model') !== false) {
            // Model bi ngung: thu lai 1 lan voi model du phong.
            $data['model'] = 'openai/gpt-oss-20b';
            $ch = curl_init(GROQ_API_URL);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            curl_setopt($ch, CURLOPT_TIMEOUT, 60);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json', 'Authorization: Bearer ' . GROQ_API_KEY]);
            $response = curl_exec($ch); curl_close($ch);
            $json = json_decode($response, true);
            if (!isset($json['choices'][0]['message']['content'])) {
                return ['ai_error' => true, 'reason' => 'Loi Groq API: ' . ($json['error']['message'] ?? 'khong tra ve ket qua')];
            }
        } else {
            return ['ai_error' => true, 'reason' => 'Loi Groq API: ' . $err . ' — hay chay lai.'];
        }
    }
    $parsed = json_decode($json['choices'][0]['message']['content'], true);
    if (!is_array($parsed) || !array_key_exists('has_vulnerability', $parsed)) {
        return ['ai_error' => true, 'reason' => 'AI tra ve khong dung dinh dang JSON yeu cau — hay chay lai.'];
    }
    // Kiem tra du truong bat buoc cho tung finding; thieu thi coi nhu loi.
    foreach ($parsed['vulnerabilities'] ?? [] as $v) {
        foreach (['type', 'owasp', 'cwe', 'explain', 'fixed_code'] as $f) {
            if (empty($v[$f])) {
                return ['ai_error' => true, 'reason' => "AI tra ve thieu truong '{$f}' — hay chay lai."];
            }
        }
    }
    return $parsed;
}

// --- Phan DAST (Nam lam, Sprint 5 khong sua) ---
function analyzeDASTWithAI($url, $payload_type, $payload, $response_body, $http_code) {
    // Nap config Groq khi can (khong require o dau file de SAST van chay duoc
    // khi chua co config.php — config.php chi nam o may local, khong commit).
    if (!defined('GROQ_API_KEY') || !defined('GROQ_API_URL')) {
        if (file_exists(__DIR__ . '/config.php')) {
            require_once __DIR__ . '/config.php';
        }
    }
    if (!defined('GROQ_API_KEY') || !defined('GROQ_API_URL')) {
        return ['ai_error' => true, 'reason' => 'Chua cau hinh Groq API key (thieu config.php) — hay tao config.php tu key da xoay.'];
    }

    // Lay doan phan hoi quanh payload lam bang chung. KHONG dung strip_tags:
    // strip_tags se xoa mat the <script> - chinh la bang chung cua XSS phan xa.
    $body_text = (string)$response_body;
    $needle = substr($payload, 0, 20);
    $pos = ($needle !== '') ? stripos($body_text, $needle) : false;
    if ($pos !== false) {
        $response_snippet = substr($body_text, max(0, $pos - 500), 1500);
    } else {
        $response_snippet = substr($body_text, 0, 1500);
    }
    if (trim(strip_tags($response_snippet)) === '' && trim($response_snippet) === '') {
        $response_snippet = '[Server tra ve HTTP ' . $http_code . ', body rong]';
    }
    
    $prompt = "Bạn là một chuyên gia kiểm thử xâm nhập (Pentester).\n";
    $prompt .= "Tôi vừa thực hiện tấn công thử nghiệm lỗi **{$payload_type}** vào đường dẫn sau:\n";
    $prompt .= "URL: {$url}\n";
    $prompt .= "Payload sử dụng: {$payload}\n";
    $prompt .= "Mã HTTP trả về: {$http_code}\n\n";
    $prompt .= "Đây là một đoạn trích xuất nội dung (HTML/Text) mà server trả về:\n";
    $prompt .= "```html\n{$response_snippet}\n```\n\n";
    // Goi y bang chung theo tung loai (tranh AI ket luan sai):
    // - SQLi can bang chung SQL (loi cu phap SQL hoac du lieu tra ve bat thuong),
    //   chi thay payload phan xa lai nguyen ven thi CHUA du — do la dau hieu XSS.
    // - XSS: payload (the <script>...) xuat hien nguyen ven trong HTML tra ve.
    // - Command Injection: ket qua lenh (ten user he thong, danh sach file...) xuat hien.
    // - LFI: noi dung file he thong (VD: root:x:0:0...) xuat hien.
    $evidence_hint = [
        'SQL Injection' => "Bang chung SQLi la: thong bao loi SQL, hoac du lieu tra ve thay doi bat thuong (VD: liet ke nhieu ban ghi hon binh thuong). Chi thay payload phan xa lai nguyen ven trong HTML thi CHUA du ket luan SQLi.",
        'Cross-Site Scripting (XSS)' => "Bang chung XSS la: payload (the <script>...) xuat hien nguyen ven trong HTML tra ve.",
        'Command Injection' => "Bang chung Command Injection la: ket qua cua lenh (VD: ten user he thong, danh sach file) xuat hien trong phan hoi.",
        'Local File Inclusion (LFI)' => "Bang chung LFI la: noi dung file he thong (VD: root:x:0:0:...) xuat hien trong phan hoi.",
    ];
    $prompt .= "Chú ý về bằng chứng cho lỗi {$payload_type}: " . ($evidence_hint[$payload_type] ?? "chi ket luan co lo hong khi phan hoi chua bang chung ro rang.") . "\n";
    $prompt .= "Dựa vào phản hồi trên, hãy kết luận xem trang web có bị dính lỗ hổng {$payload_type} không.\n";
    $prompt .= "Trả về ĐÚNG định dạng JSON sau (không kèm text thừa):\n";
    $prompt .= "{\n";
    $prompt .= "  \"is_vulnerable\": true,\n";
    $prompt .= "  \"severity\": \"High\",\n";
    $prompt .= "  \"reason\": \"Giải thích lý do...\",\n";
    $prompt .= "  \"recommendation\": \"Lời khuyên khắc phục...\"\n";
    $prompt .= "}";

    $data = [
        'model' => 'openai/gpt-oss-120b', // ĐÃ ĐỔI SANG MODEL MỚI
        'messages' => [['role' => 'user', 'content' => $prompt]],
        'temperature' => 0.1,
        'response_format' => ['type' => 'json_object']
    ];

    $ch = curl_init(GROQ_API_URL);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Authorization: Bearer ' . GROQ_API_KEY
    ]);
    
    $response = curl_exec($ch);
    curl_close($ch);

    $json = json_decode($response, true);
    // Neu Groq loi (VD: json_validate_failed, rate limit) thi bao loi ro rang
    // thay vi tra ve rong — neu khong, tool se hien nham "An toan".
    if (!isset($json['choices'][0]['message']['content'])) {
        $err = $json['error']['message'] ?? 'Groq khong tra ve ket qua';
        return ['ai_error' => true, 'reason' => 'Loi Groq API: ' . $err . ' — hay chay lai lan quet.'];
    }
    $ai_content = $json['choices'][0]['message']['content'];
    $parsed = json_decode($ai_content, true);
    if (!is_array($parsed) || !isset($parsed['is_vulnerable'])) {
        return ['ai_error' => true, 'reason' => 'AI tra ve khong dung dinh dang JSON yeu cau — hay chay lai lan quet.'];
    }
    return $parsed;
}
?>