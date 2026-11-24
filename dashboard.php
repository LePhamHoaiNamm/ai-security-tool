<?php 
session_start();
if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
require 'db.php'; 

// ==========================================
// 1. LOGIC LẤY DỮ LIỆU TỪ DATABASE (ĐÃ ĐỒNG BỘ)
// ==========================================
$total_scans = $pdo->query("SELECT COUNT(*) FROM scan_history")->fetchColumn();
$safe_scans = $pdo->query("SELECT COUNT(*) FROM scan_history WHERE vuln_count = 0")->fetchColumn();

// Khởi tạo biến đếm
$sev_critical = 0; 
$sev_high = 0; 
$sev_medium = 0; 
$sev_low = 0;
$table_data = [];

// Lấy dữ liệu chi tiết
$stmt = $pdo->query("SELECT id, scan_type, target, details, scan_date FROM scan_history WHERE vuln_count > 0 ORDER BY scan_date DESC LIMIT 50");
while ($row = $stmt->fetch()) {
    $data = json_decode($row['details'], true);
    
    // Xử lý SAST
    if ($row['scan_type'] == 'SAST' && isset($data['vulnerabilities'])) {
        foreach ($data['vulnerabilities'] as $v) {
            $sev_en = strtolower($v['severity'] ?? 'high');
            $sev_vi = 'Cao'; $badge = 'bg-danger';
            
            // Phân loại chuẩn xác
            if (strpos($sev_en, 'critical') !== false || strpos($sev_en, 'nghiêm trọng') !== false) {
                $sev_critical++; $sev_vi = 'Nghiêm trọng';
            } elseif (strpos($sev_en, 'high') !== false || strpos($sev_en, 'cao') !== false) {
                $sev_high++; $sev_vi = 'Cao';
            } elseif (strpos($sev_en, 'medium') !== false || strpos($sev_en, 'trung bình') !== false) {
                $sev_medium++; $sev_vi = 'Trung bình'; $badge = 'bg-warning text-dark';
            } else {
                $sev_low++; $sev_vi = 'Thấp'; $badge = 'bg-info text-dark';
            }

            $table_data[] = [
                'name' => $v['type'] ?? 'Unknown',
                'owasp' => $v['owasp'] ?? 'N/A',
                'target' => $row['target'],
                'line' => $v['line'] ?? 'N/A',
                'severity' => $sev_vi,
                'badge' => $badge,
                'type' => 'SAST',
                'date' => $row['scan_date']
            ];
        }
    } 
    // Xử lý DAST
    elseif ($row['scan_type'] == 'DAST' && is_array($data)) {
        foreach ($data as $item) {
            if (isset($item['result']['is_vulnerable']) && $item['result']['is_vulnerable'] === true) {
                $sev_en = strtolower($item['result']['severity'] ?? 'high');
                $sev_vi = 'Cao'; $badge = 'bg-danger';
                
                if (strpos($sev_en, 'critical') !== false || strpos($sev_en, 'nghiêm trọng') !== false) {
                    $sev_critical++; $sev_vi = 'Nghiêm trọng';
                } elseif (strpos($sev_en, 'high') !== false || strpos($sev_en, 'cao') !== false) {
                    $sev_high++; $sev_vi = 'Cao';
                } elseif (strpos($sev_en, 'medium') !== false || strpos($sev_en, 'trung bình') !== false) {
                    $sev_medium++; $sev_vi = 'Trung bình'; $badge = 'bg-warning text-dark';
                } else {
                    $sev_low++; $sev_vi = 'Thấp'; $badge = 'bg-info text-dark';
                }

                $table_data[] = [
                    'name' => $item['type'] ?? 'Unknown',
                    'owasp' => 'N/A',
                    'target' => $row['target'],
                    'line' => 'URL',
                    'severity' => $sev_vi,
                    'badge' => $badge,
                    'type' => 'DAST',
                    'date' => $row['scan_date']
                ];
            }
        }
    }
}

// Tổng số lỗ hổng thực tế (Khớp với biểu đồ)
$total_vulnerabilities = $sev_critical + $sev_high + $sev_medium + $sev_low;
$resolved_scans = $safe_scans; // Tạm tính số lần quét an toàn là số đã khắc phục

require 'layout.php'; 
?>

<!-- NỘI DUNG CHÍNH -->
<div class="d-flex justify-content-between align-items-end mb-4">
    <div>
        <div class="text-primary fw-bold mb-1" style="font-size:0.8rem;">
            <?= mb_strtoupper("THỨ " . date('N') . ", " . date('d') . " THÁNG " . date('m')) ?>
        </div>
        <?php
        date_default_timezone_set('Asia/Ho_Chi_Minh');
        $hour = date('H');
        if ($hour < 24) { $greeting = "Chào buổi sáng"; } 
        elseif ($hour < 18) { $greeting = "Chào buổi chiều"; } 
        else { $greeting = "Chào buổi tối"; }
        $user_name = ucfirst(htmlspecialchars($_SESSION['username'] ?? 'Admin'));
        ?>
        <h2 class="fw-bold mb-0"><?= $greeting ?>, <?= $user_name ?>.</h2>
        <p class="text-muted">Đây là tổng quan tình trạng bảo mật hệ thống của bạn hôm nay.</p>
    </div>
</div>

<!-- HÀNG 1: CÁC THẺ KPI (ĐÃ ĐỒNG BỘ SỐ LIỆU) -->
<div class="row g-3 mb-4">
    <div class="col-md-3">
        <div class="stat-card">
            <div class="icon-box bg-danger bg-opacity-10 text-danger"><i class="bi bi-exclamation-triangle"></i></div>
            <div class="stat-label mt-3">Lỗ hổng phát hiện</div>
            <!-- Lấy tổng số lỗ hổng thực tế giống biểu đồ -->
            <div class="stat-value"><?= str_pad($total_vulnerabilities, 2, '0', STR_PAD_LEFT) ?></div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-card">
            <div class="icon-box bg-info bg-opacity-10 text-info"><i class="bi bi-shield-check"></i></div>
            <div class="stat-label mt-3">Lượt quét an toàn</div>
            <div class="stat-value"><?= $safe_scans ?></div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-card">
            <div class="icon-box bg-primary bg-opacity-10 text-primary"><i class="bi bi-search"></i></div>
            <div class="stat-label mt-3">Tổng lượt quét</div>
            <div class="stat-value"><?= $total_scans ?></div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-card">
            <div class="icon-box bg-success bg-opacity-10 text-success"><i class="bi bi-check2-circle"></i></div>
            <div class="stat-label mt-3">Đã khắc phục</div>
            <div class="stat-value"><?= str_pad($resolved_scans, 2, '0', STR_PAD_LEFT) ?></div>
        </div>
    </div>
</div>

<!-- HÀNG 2: BẢNG & BIỂU ĐỒ -->
<div class="row g-4">
    
    <!-- CỘT TRÁI: BẢNG DANH SÁCH -->
    <div class="col-lg-8">
        <div class="stat-card p-0 overflow-hidden" style="height: 100%;">
            <div class="p-4 border-bottom d-flex justify-content-between align-items-center">
                <h5 class="fw-bold m-0"><i class="bi bi-shield-exclamation text-danger me-2"></i> Phát hiện cần xử lý</h5>
                <span class="badge bg-secondary"><?= count($table_data) ?> vị trí</span>
            </div>
            <div class="table-responsive" style="max-height: 500px; overflow-y: auto;">
                <table class="table table-hover align-middle mb-0">
                    <thead class="table-light" style="position: sticky; top: 0; z-index: 1;">
                        <tr>
                            <th class="ps-4 py-3">Lỗ hổng / Vị trí</th>
                            <th class="py-3">Mức độ</th>
                            <th class="py-3">Loại</th>
                            <th class="py-3">Mục tiêu</th>
                            <th class="pe-4 py-3 text-end">Thời gian</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($table_data)): ?>
                            <tr><td colspan="5" class="text-center py-5 text-muted"><i class="bi bi-check-circle fs-1 text-success d-block mb-3"></i> Tuyệt vời! Chưa phát hiện lỗ hổng nào.</td></tr>
                        <?php else: ?>
                            <?php foreach ($table_data as $vuln): ?>
                                <tr>
                                    <td class="ps-4 py-3">
                                        <div class="fw-bold text-dark"><?= htmlspecialchars($vuln['name']) ?></div>
                                        <div class="text-muted small"><i class="bi bi-link-45deg"></i> <?= htmlspecialchars($vuln['owasp']) ?> | Dòng: <?= htmlspecialchars($vuln['line']) ?></div>
                                    </td>
                                    <td>
                                        <span class="badge <?= $vuln['badge'] ?> px-2 py-1 rounded"><?= htmlspecialchars($vuln['severity']) ?></span>
                                    </td>
                                    <td><span class="badge <?= $vuln['type'] == 'SAST' ? 'bg-primary' : 'text-white' ?>" style="<?= $vuln['type'] == 'DAST' ? 'background-color: #8b5cf6;' : '' ?>"><?= $vuln['type'] ?></span></td>
                                    <td class="text-truncate" style="max-width: 150px;"><?= htmlspecialchars($vuln['target']) ?></td>
                                    <td class="pe-4 text-end text-muted small"><?= date('d/m H:i', strtotime($vuln['date'])) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            <div class="p-3 border-top text-center bg-light">
                <a href="history.php" class="text-decoration-none fw-bold text-primary">Xem toàn bộ lịch sử <i class="bi bi-arrow-right"></i></a>
            </div>
        </div>
    </div>

    <!-- CỘT PHẢI: BIỂU ĐỒ ĐỒNG BỘ -->
    <div class="col-lg-4">
        <div class="stat-card p-4" style="height: 100%;">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h6 class="fw-bold m-0 text-dark">Mức độ nghiêm trọng</h6>
                <i class="bi bi-info-circle text-muted"></i>
            </div>
            
            <div class="row align-items-center mb-4">
                <!-- Biểu đồ -->
                <div class="col-6 position-relative d-flex justify-content-center">
                    <div style="height: 120px; width: 120px;">
                        <canvas id="severityChart"></canvas>
                    </div>
                    <!-- Text ở giữa -->
                    <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center;">
                        <h3 class="mb-0 text-dark fw-bold" style="font-size: 1.5rem;"><?= $total_vulnerabilities ?></h3>
                    </div>
                </div>
                
                <!-- Chú thích (Số liệu lấy từ biến PHP) -->
                <div class="col-6">
                    <div class="d-flex justify-content-between mb-2">
                        <span style="font-size: 0.8rem; color: #374151;"><i class="bi bi-square-fill me-2" style="color: #ef4444;"></i>Nghiêm trọng</span>
                        <span class="fw-bold text-dark"><?= str_pad($sev_critical, 2, '0', STR_PAD_LEFT) ?></span>
                    </div>
                    <div class="d-flex justify-content-between mb-2">
                        <span style="font-size: 0.8rem; color: #374151;"><i class="bi bi-square-fill me-2" style="color: #f97316;"></i>Cao</span>
                        <span class="fw-bold text-dark"><?= str_pad($sev_high, 2, '0', STR_PAD_LEFT) ?></span>
                    </div>
                    <div class="d-flex justify-content-between mb-2">
                        <span style="font-size: 0.8rem; color: #374151;"><i class="bi bi-square-fill me-2" style="color: #eab308;"></i>Trung bình</span>
                        <span class="fw-bold text-dark"><?= str_pad($sev_medium, 2, '0', STR_PAD_LEFT) ?></span>
                    </div>
                    <div class="d-flex justify-content-between">
                        <span style="font-size: 0.8rem; color: #374151;"><i class="bi bi-square-fill me-2" style="color: #3b82f6;"></i>Thấp</span>
                        <span class="fw-bold text-dark"><?= str_pad($sev_low, 2, '0', STR_PAD_LEFT) ?></span>
                    </div>
                </div>
            </div>

            <!-- Khung cảnh báo -->
            <div class="mt-4 p-3 rounded" style="background-color: #fef2f2; border: 1px solid #fecaca;">
                <p class="mb-0" style="color: #b91c1c; font-size: 0.85rem;">
                    <i class="bi bi-exclamation-triangle me-2"></i> 
                    <strong><?= $sev_critical ?> nghiêm trọng + <?= $sev_high ?> cao</strong> cần ưu tiên.
                </p>
            </div>
        </div>
    </div>
</div>

<!-- Chart.js -->
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
    const ctx = document.getElementById('severityChart').getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Nghiêm trọng', 'Cao', 'Trung bình', 'Thấp', 'An Toàn'],
            datasets: [{
                data: [<?= $sev_critical ?>, <?= $sev_high ?>, <?= $sev_medium ?>, <?= $sev_low ?>],
                backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
                borderWidth: 2, 
                borderColor: '#ffffff',
                cutout: '75%' 
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { 
                legend: { display: false } 
            }
        }
    });
</script>

</div> <!-- Đóng thẻ main-content từ layout.php -->
</body>
</html>