#!/usr/bin/env bash
set -euo pipefail
cd paper
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
cp main.pdf compiled_paper.pdf
