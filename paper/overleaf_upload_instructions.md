# SIFR LNCS / Overleaf Upload Instructions

The target venue is ICWS 2026. The ICWS submission page requires Springer LNCS Proceedings style for Research, Application, and Short Paper tracks.

1. Go to https://www.overleaf.com.
2. Create a new project using Overleaf's **Springer Lecture Notes in Computer Science** / **LNCS** template.
3. Replace the template `main.tex` with this project's `paper/main.tex`.
4. Upload `paper/references.bib`.
5. Upload the complete `paper/figures/` folder.
6. Set the main file to `main.tex`.
7. Compile with pdfLaTeX.
8. If `llncs.cls` or `splncs04.bst` is missing, start from Overleaf's built-in LNCS template and copy this project's `main.tex`, `references.bib`, and `figures/` into it.

Expected paper class:

```tex
\documentclass[runningheads]{llncs}
```

ICWS page checked on 2026-05-09: https://www.servicessociety.org/icws

- Research/Application manuscripts: 15 pages, LNCS style.
- Short Paper manuscripts: 8 pages, LNCS style.
- Conference theme: Agentic AI as a Service.

Authors:

- Raneem Althaqafi, althaqafi.raneem@gmail.com
- Majid Althaqafi, imajedmuhammad@gmail.com

Local compilation note:

- This workspace may not have a local TeX installation.
- Overleaf's LNCS template is the recommended compilation environment.
