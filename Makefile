.PHONY: help install demo-all lint clean

help: ## Yardım menüsünü göster
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Bağımlılıkları yükle
	pip install -r requirements.txt

demo-all: ## Tüm demo'ları çalıştır
	@echo "=== Prompt Injection Filtre Demo ==="
	python examples/prompt_injection_filter_demo.py
	@echo ""
	@echo "=== Yapılandırılmış Çıktı Koruma Demo ==="
	python examples/structured_output_guard_demo.py
	@echo ""
	@echo "=== Araç İzin Koruma Demo ==="
	python examples/tool_permission_guard_demo.py
	@echo ""
	@echo "=== Maskeleme Politikası Demo ==="
	python examples/redaction_policy_demo.py
	@echo ""
	@echo "=== Onay Akışı Demo ==="
	python examples/approval_flow_demo.py
	@echo ""
	@echo "=== Denetim Logu Demo ==="
	python examples/audit_log_demo.py
	@echo ""
	@echo "=== Delege Erişim Demo ==="
	python examples/delegated_access_demo.py

demo-injection: ## Prompt injection demo'sunu çalıştır
	python examples/prompt_injection_filter_demo.py

demo-output: ## Yapılandırılmış çıktı demo'sunu çalıştır
	python examples/structured_output_guard_demo.py

demo-tools: ## Araç izin demo'sunu çalıştır
	python examples/tool_permission_guard_demo.py

demo-redaction: ## Maskeleme demo'sunu çalıştır
	python examples/redaction_policy_demo.py

demo-approval: ## Onay akışı demo'sunu çalıştır
	python examples/approval_flow_demo.py

demo-audit: ## Denetim logu demo'sunu çalıştır
	python examples/audit_log_demo.py

demo-delegation: ## Delege erişim demo'sunu çalıştır
	python examples/delegated_access_demo.py

lint: ## Kod kalitesi kontrolü
	python -m py_compile examples/prompt_injection_filter_demo.py
	python -m py_compile examples/structured_output_guard_demo.py
	python -m py_compile examples/tool_permission_guard_demo.py
	python -m py_compile examples/redaction_policy_demo.py
	python -m py_compile examples/approval_flow_demo.py
	python -m py_compile examples/audit_log_demo.py
	python -m py_compile examples/delegated_access_demo.py
	@echo "Tüm dosyalar başarıyla derlendi."

clean: ## Geçici dosyaları temizle
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.log" -delete 2>/dev/null || true
	@echo "Temizlik tamamlandı."
