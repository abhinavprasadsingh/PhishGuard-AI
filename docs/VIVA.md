# Viva / presentation notes

## 60-second project introduction

PhishGuard AI is an educational phishing-URL analysis project built with Python, Streamlit, and scikit-learn. It extracts interpretable features from URL text, such as length, subdomain count, HTTPS usage, suspicious words, IP-based hosts, and URL-shortener domains. The application explains warning signals and never visits the submitted URL. It starts in clearly labelled heuristic demo mode; supervised ML predictions are enabled only after a model is trained from a documented, labeled dataset. The goal is awareness and learning, not a guarantee that any website is safe.

## Common viva questions

1. **What is phishing?** A social-engineering attack that tricks people into revealing data or taking unsafe actions.
2. **What is the project objective?** Demonstrate URL-feature analysis for phishing awareness.
3. **Which language is used?** Python.
4. **Why Streamlit?** It creates an interactive web UI directly from Python.
5. **What is supervised learning?** Learning a mapping from examples that have labels.
6. **What do labels 0 and 1 mean?** 0 means legitimate and 1 means phishing, according to the dataset convention.
7. **What is a feature?** A measurable input used by a model.
8. **Why URL length?** Very long URLs can be a warning signal, but length alone is not decisive.
9. **Why check HTTPS?** HTTPS protects transport but does not prove a site is trustworthy.
10. **Why check IP hosts?** Some suspicious links use raw IP addresses, though legitimate cases exist.
11. **What is a subdomain?** A label before the registrable domain, such as login in login.example.com.
12. **What is a train/test split?** A way to evaluate on held-out examples.
13. **What is accuracy?** The fraction of predictions that are correct.
14. **What is precision?** The fraction of predicted phishing URLs that are actually phishing in test labels.
15. **What is recall?** The fraction of labeled phishing URLs the model detects.
16. **What is F1?** The harmonic mean of precision and recall.
17. **What is a confusion matrix?** Counts of true/false positives and negatives.
18. **Why is dataset quality important?** Incorrect labels, duplicates, and leakage can make metrics misleading.
19. **Does the app open a submitted URL?** No; it parses URL text only.
20. **Can it guarantee safety?** No. Treat it as an educational signal and verify domains independently.

## Limitations

- URL-only signals miss page content, redirects, newly registered domains, and context clues.
- Demo mode is a heuristic, not a trained ML classifier.
- Metrics are meaningful only for the selected dataset and split.
- Do not present demo-mode scores as measured model accuracy.
