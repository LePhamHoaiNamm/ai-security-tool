<?php
// File demo co y chua lo hong de kiem tra module SAST (Sprint 3 - chi dung Regex)
// Ket qua mong doi: 4 the do (SQL Injection, XSS, Weak Password Hashing, Unrestricted File Upload)
$conn = mysqli_connect('localhost', 'root', '', 'demo');

// 1. SQL Injection: noi truc tiep $_GET vao cau truy van
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);

// 2. XSS: in truc tiep du lieu nguoi dung ra trang
echo $_GET['name'];

// 3. Bam mat khau yeu bang MD5
$hash = md5($_POST['password']);

// 4. Upload file khong kiem tra dinh dang
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);
?>
