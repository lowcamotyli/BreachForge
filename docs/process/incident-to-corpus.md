# Incident to Corpus Workflow

1. Identify attack class.
Determine the incident's primary class (for example: `bola`, `auth_bypass`, or `injection`) and map it to an existing planner rule.

2. Write a minimal reproducer.
Create the smallest deterministic pytest reproducer that models the vulnerable endpoint shape and asserts task generation behavior for that class.

3. Add test under `tests/corpus/<class>/`.
Place the reproducer in a class-specific corpus file (for example `tests/corpus/bola/test_bola_corpus.py`) so the corpus grows by attack class.

4. Ensure it gates CI.
Run test and type checks, then keep the test in the default CI path so a regression in rule coverage fails the pipeline.
