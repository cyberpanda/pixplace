# Pixplace – helper targets. Run `make help`.
.DEFAULT_GOAL := help
SHELL := /bin/bash

APP      ?= pixplace
PREFIX   ?= /opt/$(APP)
SVC_USER ?= $(APP)
HOST     ?= 127.0.0.1
PORT     ?= 9998
PY       ?= python3

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	 awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n",$$1,$$2}'

run: ## Run in the foreground (http://127.0.0.1:9998)
	@cd server && $(PY) server.py --host $(HOST) --port $(PORT)

check: ## Syntax and language-file checks
	@tools/check.sh

install: ## Install as a systemd service (needs root)
	@[ "$$(id -u)" = "0" ] || { echo "Run with sudo."; exit 1; }
	@id -u $(SVC_USER) >/dev/null 2>&1 || useradd --system --home-dir $(PREFIX) --shell /usr/sbin/nologin $(SVC_USER)
	@$(MAKE) --no-print-directory _copy
	@sed -e 's#/opt/pixplace#$(PREFIX)#g' -e 's#^User=.*#User=$(SVC_USER)#' \
	     -e 's#--host [0-9.]* --port [0-9]*#--host $(HOST) --port $(PORT)#' \
	     deploy/pixplace.service > /etc/systemd/system/$(APP).service
	@systemctl daemon-reload && systemctl enable --now $(APP)
	@echo "Installed. Service listens on $(HOST):$(PORT) – put a TLS reverse proxy in front (see deploy/)."

update: ## Copy new program files and restart the service (needs root)
	@[ "$$(id -u)" = "0" ] || { echo "Run with sudo."; exit 1; }
	@$(MAKE) --no-print-directory _copy
	@systemctl restart $(APP)

_copy:
	@install -d -o $(SVC_USER) -g $(SVC_USER) $(PREFIX)/server $(PREFIX)/client $(PREFIX)/lang
	@install -m 0644 -o $(SVC_USER) -g $(SVC_USER) server/*.py $(PREFIX)/server/
	@install -m 0644 -o $(SVC_USER) -g $(SVC_USER) client/* $(PREFIX)/client/
	@install -m 0644 -o $(SVC_USER) -g $(SVC_USER) lang/*.lang $(PREFIX)/lang/
	@chmod 0750 $(PREFIX)

start stop restart: ## Control the service (needs root)
	@systemctl $@ $(APP)

status: ## Show service status
	@systemctl --no-pager status $(APP)

logs: ## Follow the service log
	@journalctl -u $(APP) -f -n 50 --no-pager

uninstall: ## Remove the service (data in $(PREFIX) is kept)
	@[ "$$(id -u)" = "0" ] || { echo "Run with sudo."; exit 1; }
	@-systemctl disable --now $(APP)
	@rm -f /etc/systemd/system/$(APP).service && systemctl daemon-reload
	@echo "Service removed. Data is still in $(PREFIX)."

docker-build: ## Build the Docker image
	docker build -t pixplace .

docker-run: ## Run the Docker image on port 9998
	docker run --rm -p 9998:9998 -v pixplace-data:/data pixplace

.PHONY: help run check install update _copy start stop restart status logs uninstall docker-build docker-run
