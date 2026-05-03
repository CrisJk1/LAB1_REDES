.PHONY: help setup run build clean all

GRUPO := 1
LAB := 1
FORMAT := grupo_$(GRUPO)_lab_$(LAB)

PIP = venv/bin/pip
PYTHON = venv/bin/python

help:
	@echo "Usage: make [target]"
	@echo "Targets:"
	@echo "  help    - Muestra esta ayuda"
	@echo "  setup   - Configura el entorno virtual e instala dependencias"
	@echo "  run     - Ejecuta las fases del laboratorio"
	@echo "  build   - Genera el informe en PDF"
	@echo "  clean   - Limpia los archivos temporales"
	@echo "  all     - Ejecuta todos los targets"

setup:
	@echo "Configurando entorno con venv..."
	@python -m venv venv
	@echo "Instalando dependencias..."
	@$(PIP) install -r requirements.txt

run:
	@echo "Ejecutando fase 1.."
	@$(PYTHON) CODIGO/fase1.py
	@echo "Ejecutando fase 2.."
	@$(PYTHON) CODIGO/fase2.py
	@echo "Ejecutando fase 3.."
	@$(PYTHON) CODIGO/fase3.py
	@echo "Ejecutando fase 4.."
	@$(PYTHON) CODIGO/fase4.py

build:
	@echo "Generando informe.."
	@cd TEX && pdflatex -interaction=nonstopmode main.tex 1> /dev/null && cp main.pdf ../PDF/$(FORMAT).pdf
	@echo "Comprimiendo archivos..."
	@tar -cvzf $(FORMAT).tar.gz PDF/* CODIGO/* README.md requirements.txt

clean:
	@echo "Limpiando archivos temporales..."
	@rm -rf venv/ PDF/$(FORMAT).pdf TEX/*.aux TEX/*.log TEX/*.pdf $(FORMAT).tar.gz

all: setup run build
	@echo "Proceso completo. Archivo generado: $(FORMAT).tar.gz"
