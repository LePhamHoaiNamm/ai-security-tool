<?php 
session_start();
if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
require 'layout.php'; 
require 'db.php';
?>

<div class="d-flex justify-content-between align-items-end mb-4">
    <div>
        <h2 class="fw-bold mb-0">Quét bảo mật</h2>
        <p class="text-muted">Sử dụng AI để phân tích mã nguồn hoặc tấn công thử nghiệm website.</p>
    </div>
</div>

<div class="row g-4">
    <div class="col-md-12">
        <div class="stat-card">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="fw-bold m-0"><i class="bi bi-cpu text-primary me-2"></i> Trung tâm phân tích AI</h5>
                <span class="badge bg-success bg-opacity-25 text-success rounded-pill px-3 py-2"><i class="bi bi-circle-fill" style="font-size:8px;"></i> AI ENGINE ONLINE</span>
            </div>
            
            <!-- Tabs -->
            <div class="d-flex bg-light rounded p-1 mb-4">
                <button class="btn btn-white w-50 fw-bold shadow-sm" onclick="switchTab('sast')" id="btn-sast">Phân tích tĩnh (Code)</button>
                <button class="btn btn-light w-50 text-muted fw-bold" onclick="switchTab('dast')" id="btn-dast">Phân tích động (URL)</button>
            </div>

            <!-- Form SAST -->
            <div id="form-sast">
                <form id="sast-form" enctype="multipart/form-data">
                    <div class="border border-2 border-dashed rounded-3 p-5 text-center bg-light mb-3" style="border-style: dashed !important;">
                        <i class="bi bi-cloud-arrow-up text-primary fs-1"></i>
                        <h6 class="fw-bold mt-3">Kéo thả mã nguồn vào đây</h6>
                        <p class="text-muted small">hoặc nhấn để chọn file từ máy tính (Hỗ trợ PHP, JS, TXT - Tối đa 50MB)</p>
                        <input class="form-control d-none" type="file" id="code_file" name="code_file" accept=".php,.txt" onchange="document.getElementById('file-name').innerText = this.files[0].name">
                        <label for="code_file" class="btn btn-outline-primary mt-2">Chọn File</label>
                        <div id="file-name" class="text-success mt-2 fw-bold"></div>
                    </div>
                    <button type="submit" class="btn btn-primary-custom w-100 py-3 text-white">Bắt đầu phân tích bằng AI <i class="bi bi-arrow-right"></i></button>
                </form>
            </div>

            <!-- Form DAST -->
            <div id="form-dast" style="display: none;">
                <form id="dast-form">
                    <div class="mb-4 p-3 bg-light rounded">
                        <label class="form-label fw-bold text-muted">Nhập URL cần quét (VD: http://localhost/dvwa/...):</label>
                        <input class="form-control form-control-lg" type="url" id="target_url" name="target_url" placeholder="http://" required>
                    </div>
                    <button type="submit" class="btn btn-danger w-100 py-3 fw-bold">Bắt đầu tấn công thử nghiệm <i class="bi bi-crosshair"></i></button>
                </form>
            </div>
            
            <div id="result-area" class="mt-4"></div>
        </div>
    </div>
</div>

<script>
    function switchTab(type) {
        if(type === 'sast') {
            document.getElementById('form-sast').style.display = 'block';
            document.getElementById('form-dast').style.display = 'none';
            document.getElementById('btn-sast').className = 'btn btn-white w-50 fw-bold shadow-sm';
            document.getElementById('btn-dast').className = 'btn btn-light w-50 text-muted fw-bold';
        } else {
            document.getElementById('form-sast').style.display = 'none';
            document.getElementById('form-dast').style.display = 'block';
            document.getElementById('btn-dast').className = 'btn btn-white w-50 fw-bold shadow-sm';
            document.getElementById('btn-sast').className = 'btn btn-light w-50 text-muted fw-bold';
        }
    }

    document.getElementById('sast-form').addEventListener('submit', function(e) {
        e.preventDefault();
        let resultArea = document.getElementById('result-area');
        resultArea.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div><p class="mt-2 text-muted">AI đang phân tích mã nguồn...</p></div>';
        fetch('sast_handler.php', { method: 'POST', body: new FormData(this) })
        .then(res => res.text()).then(html => { resultArea.innerHTML = html; });
    });

    document.getElementById('dast-form').addEventListener('submit', function(e) {
        e.preventDefault();
        let resultArea = document.getElementById('result-area');
        resultArea.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-danger"></div><p class="mt-2 text-muted">Đang gửi Payload tấn công...</p></div>';
        fetch('dast_handler.php', { method: 'POST', body: new FormData(this) })
        .then(res => res.text()).then(html => { resultArea.innerHTML = html; });
    });
</script>

</div> <!-- Đóng main-content -->
</body>
</html>