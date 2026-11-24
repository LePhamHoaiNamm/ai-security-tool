-- Sprint 5: chi can cot details (JSON) trong scan_history.
-- Neu da import ai_security_tool-khoi-phuc.sql hoac sprint3/sprint4-setup.sql
-- thi bang da du cot, chay lai cung khong hai (IF NOT EXISTS).
ALTER TABLE scan_history
  ADD COLUMN IF NOT EXISTS details JSON NULL,
  ADD COLUMN IF NOT EXISTS scan_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;
