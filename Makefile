.PHONY: help setup run fase1 fase2 fase3 fase4 build clean clean-fase1 clean-fase2 all

GRUPO := 1
LAB := 1
FORMAT := grupo_$(GRUPO)_lab_$(LAB)

SYSTEM_PYTHON ?= $(firstword $(shell command -v python3 2>/dev/null) $(shell command -v python 2>/dev/null))
PIP = venv/bin/pip
PYTHON = venv/bin/python

help:
	@echo "Usage: make [target]"
	@echo "Targets:"
	@echo "  help    - Muestra esta ayuda"
	@echo "  setup   - Configura el entorno virtual e instala dependencias"
	@echo "  run     - Ejecuta las fases del laboratorio"
	@echo "  fase1   - Ejecuta solo la fase 1"
	@echo "  fase2   - Ejecuta solo la fase 2"
	@echo "  fase3   - Ejecuta solo la fase 3"
	@echo "  fase4   - Ejecuta solo la fase 4"
	@echo "  build   - Genera el informe en PDF"
	@echo "  clean   - Limpia los archivos temporales"
	@echo "  clean-fase1 - Limpia los archivos generados en la fase 1"-
	@echo "  clean-fase2 - Limpia los archivos generados en la fase 2"-
	@echo "  all     - Ejecuta todos los targets"

setup:
	@echo "Configurando entorno con venv..."
	@if [ -z "$(SYSTEM_PYTHON)" ]; then \
		echo "Error: no se encontro python3 ni python en el sistema."; \
		exit 1; \
	fi
	@$(SYSTEM_PYTHON) -m venv venv
	@echo "Instalando dependencias..."
	@$(PIP) install -r requirements.txt

run:
	@$(MAKE) fase1
	@$(MAKE) fase2
	@$(MAKE) fase3
	@$(MAKE) fase4

fase1:
	@echo "=========== FASE 1 ==========="
	@$(PYTHON) CODIGO/fase1.py

fase2:
	@echo "=========== FASE 2 ==========="
	@$(PYTHON) CODIGO/fase2.py

fase3:
	@echo "=========== FASE 3 ==========="
	@$(PYTHON) CODIGO/fase3.py

fase4:
	@echo "=========== FASE 4 ==========="
	@$(PYTHON) CODIGO/fase4.py

build:
	@echo "Generando informe.."
	@cd TEX && pdflatex -interaction=nonstopmode main.tex 1> /dev/null && cp main.pdf ../PDF/$(FORMAT).pdf
	@echo "Comprimiendo archivos..."
	@tar -cvzf $(FORMAT).tar.gz PDF/* CODIGO/* README.md requirements.txt

clean:
	@echo "Limpiando archivos temporales..."
	@rm -rf venv/ PDF/$(FORMAT).pdf TEX/*.aux TEX/*.log TEX/*.pdf $(FORMAT).tar.gz

clean-fase1:
	rm -rf CODIGO/keys/*

clean-fase2:
	rm -rf CODIGO/outputs/fase2

all: setup run build
	@echo "Proceso completo. Archivo generado: $(FORMAT).tar.gz"
