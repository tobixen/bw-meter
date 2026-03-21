.PHONY: help install install-systemd dev lint format test clean

INSTALL_VENV   := /usr/local/lib/bw-meter
INSTALL_BIN    := /usr/local/bin
SYSTEMD_DIR    := /etc/systemd/system

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## Install the package (auto-detects root, uv, pipx, or pip)
	@if [ "$$(id -u)" = "0" ]; then \
		echo "Running as root — installing into $(INSTALL_VENV) ..."; \
		python3 -m venv $(INSTALL_VENV); \
		$(INSTALL_VENV)/bin/pip install --quiet .; \
		ln -sf $(INSTALL_VENV)/bin/bw-meter $(INSTALL_BIN)/bw-meter; \
		$(MAKE) install-systemd; \
	elif command -v uv >/dev/null 2>&1; then \
		echo "Installing with uv..."; \
		uv tool install .; \
	elif command -v pipx >/dev/null 2>&1; then \
		echo "Installing with pipx..."; \
		pipx install .; \
	else \
		echo "Tip: Install uv or pipx for isolated installs (pacman -S uv, apt install pipx, brew install uv)"; \
		echo "Falling back to pip install --user ..."; \
		PIP_BREAK_SYSTEM_PACKAGES=1 pip install --user .; \
	fi

install-systemd:  ## Install systemd unit files (requires root)
	@[ "$$(id -u)" = "0" ] || { echo "install-systemd requires root"; exit 1; }
	install -m 644 systemd/ptcpdump@.service    $(SYSTEMD_DIR)/
	install -m 644 systemd/bw-meter-distill.service $(SYSTEMD_DIR)/
	install -m 644 systemd/bw-meter-distill.timer   $(SYSTEMD_DIR)/
	systemctl daemon-reload
	@echo ""
	@echo "Systemd units installed.  Next steps:"
	@echo "  Enable capture per interface:"
	@echo "    systemctl enable --now ptcpdump@<interface>.service"
	@echo "  Enable the distiller timer:"
	@echo "    systemctl enable --now bw-meter-distill.timer"

dev:  ## Install with dev dependencies (editable)
	PIP_BREAK_SYSTEM_PACKAGES=1 pip install -e ".[dev]"

lint:  ## Run ruff linter and formatter check
	python -m ruff check src/ tests/
	python -m ruff format --check src/ tests/

format:  ## Auto-format code
	python -m ruff check --fix src/ tests/
	python -m ruff format src/ tests/

test:  ## Run tests
	python -m pytest

clean:  ## Remove build artifacts
	rm -rf dist/ build/ *.egg-info src/*.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
