<?php
// ==========================================
// PHẦN 1: LOGIC PHP (XỬ LÝ BACKEND)
// ==========================================
session_start();
if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }

require 'layout.php'; // Gọi thanh menu
require 'db.php';     // Gọi Database

// Lấy ID trên URL để lọc (nếu bấm từ chuông thông báo)
$filter_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

// Truy vấn Database
$query = "SELECT * FROM scan_history WHERE vuln_count > 0";
if ($filter_id > 0) {
    $query .= " AND id = $filter_id";
}
$query .= " ORDER BY scan_date DESC";

$stmt = $pdo->query($query);
$records = $stmt->fetchAll();

// Hàm xử lý bóc tách JSON (dùng PHP để xử lý)
function extract_vulns($row) {
    $data = json_decode($row['details'], true);
    $vulns = [];
    if ($row['scan_type'] == 'SAST' && isset($data['vulnerabilities'])) {
        return $data['vulnerabilities'];
    } 
    if ($row['scan_type'] == 'DAST' && is_array($data)) {
        foreach ($data as $item) {
            if (isset($item['result']['is_vulnerable']) && $item['result']['is_vulnerable'] === true) {
                $vulns[] = [
                    'type' => $item['type'] ?? 'Unknown',
                    'owasp' => 'N/A',
                    'line' => 'URL',
                    'explain' => $item['result']['reason'] ?? 'Không có giải thích',
                    'fixed_code' => $item['result']['recommendation'] ?? 'Không có khuyến nghị'
                ];
            }
        }
    }
    return $vulns;
}
?>

<!-- ==========================================
     PHẦN 2: HTML + PHP HIỂN THỊ (FRONTEND)
     ========================================== -->
<div class="mb-4 d-flex justify-content-between align-items-end">
    <div>
        <h2 class="fw-bold">Danh sách Lỗ hổng</h2>
        <p class="text-muted">Chi tiết các lỗ hổng được phát hiện bởi AI.</p>
    </div>
    <?php if($filter_id > 0): ?>
        <a href="vulnerabilities.php" class="btn btn-outline-secondary"><i class="bi bi-arrow-left"></i> Xem tất cả lỗi</a>
    <?php endif; ?>
</div>

<div class="row">
    <?php if(empty($records)): ?>
        <div class="col-12"><div class="alert alert-success">✅ Tuyệt vời! Không có lỗ hổng nào.</div></div>
    <?php else: ?>
        
        <?php foreach($records as $row): 
            // Gọi hàm PHP ở trên để lấy danh sách lỗi
            $vulns = extract_vulns($row);
        ?>
            <div class="col-md-12 mb-4">
                <div class="stat-card p-0 overflow-hidden border-top border-4 border-danger">
                    <div class="p-4 bg-light border-bottom d-flex justify-content-between align-items-center">
                        <div>
                            <h5 class="fw-bold mb-1"><i class="bi bi-file-earmark-code text-primary me-2"></i><?= htmlspecialchars($row['target']) ?></h5>
                            <span class="text-muted small">Quét lúc: <?= date('d/m/Y H:i', strtotime($row['scan_date'])) ?> | Phương thức: <strong><?= $row['scan_type'] ?></strong></span>
                        </div>
                        <span class="badge bg-danger fs-6"><?= $row['vuln_count'] ?> lỗi</span>
                    </div>
                    
                    <div class="p-4">
                        <?php if(empty($vulns)): ?>
                            <p class="text-muted mb-0">Không có chi tiết JSON.</p>
                        <?php else: ?>
                            <?php foreach($vulns as $v): ?>
                                <div class="card mb-3 border-danger shadow-sm">
                                    <div class="card-header bg-danger text-white fw-bold">
                                        🔴 <?= htmlspecialchars($v['type']) ?> (<?= htmlspecialchars($v['owasp']) ?>)
                                    </div>
                                    <div class="card-body">
                                        <p class="mb-2"><strong>Vị trí:</strong> Dòng <?= htmlspecialchars($v['line']) ?></p>
                                        <p class="mb-3"><strong>Giải thích:</strong> <?= htmlspecialchars($v['explain']) ?></p>
                                        
                                        <h6 class="text-success fw-bold">✅ Code vá lỗi:</h6>
                                        <div class="position-relative">
                                            <pre class="bg-dark text-light p-3 rounded mb-0"><code id="code-<?= md5($v['fixed_code']) ?>"><?= htmlspecialchars($v['fixed_code']) ?></code></pre>
                                            <button class="btn btn-sm btn-success position-absolute top-0 end-0 m-2" onclick="navigator.clipboard.writeText(document.getElementById('code-<?= md5($v['fixed_code']) ?>').innerText); this.innerText='✅ Đã Copy!'; setTimeout(()=>this.innerText='📋 Copy Code', 2000);">📋 Copy Code</button>
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
        
    <?php endif; ?>
</div>

</div> <!-- Đóng thẻ main-content từ layout.php -->
</body>
</html>