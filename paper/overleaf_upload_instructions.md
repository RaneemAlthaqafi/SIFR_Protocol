# SIFR v0.2 Overleaf Upload Instructions

1. Go to Overleaf.
2. Create a new project.
3. Upload the contents of this paper package directly.
4. Set the main file to `main.tex`.
5. Ensure the complete `figures/` folder is included. It contains the architecture diagrams, v0.1 benchmark figures, v0.2 benchmark figures, and the IEEE-style adversary rejection PDF.
6. Ensure `references.bib` is included.
7. Compile with pdfLaTeX.
8. If `IEEEtran.cls` is missing, use Overleaf's built-in IEEE template and replace its `main.tex` with this project's `main.tex`.

The paper names the researchers as:

- Raneem Althaqafi, althaqafi.raneem@gmail.com
- Majid Althaqafi, imajedmuhammad@gmail.com

Reviewer scope note:

- QUIC is evaluated on localhost loopback only.
- Credentials are VC-inspired, not W3C VC compliant.
- The TLA+ artifact is bounded model checking, not a cryptographic proof.
- WASM evidence covers the included calculator and adversarial fixtures, not arbitrary untrusted code.

Local compilation was not performed in this workspace because `pdflatex` is not installed.
