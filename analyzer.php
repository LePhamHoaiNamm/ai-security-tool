<?php
// Sprint 3: Phan tich Tinh (SAST) - Lop 1: Loc bang Regex
// Chi dung Regex de phat hien ham nguy hiem (SQLi, XSS, Upload file).
// Chua dung AI (AI tich hop o Sprint 5 - Groq API).

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
                        'severity' => 'High',
                        'line' => $line,
                        'explain' => 'Du lieu nguoi dung duoc in truc tiep ra trang ma khong ma hoa, ke tan cong co the chen ma JavaScript doc hai vao de danh cap phien dang nhap cua nguoi khac.',
                        'fixed_code' => "echo htmlspecialchars(\$_GET['name'], ENT_QUOTES, 'UTF-8');"
                    ];
                } else {
                    $findings[] = [
                        'type' => 'Unvalidated User Input',
                        'owasp' => 'A03:2021',
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
?>
