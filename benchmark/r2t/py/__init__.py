"""The python/behave stack's two programs, and the seam between them.

`r2t/php/` holds four PHP programs that run INSIDE the CoreShop container.
This is its twin: the two programs the behave stack needs, and they split
along exactly the same line.

* `analyze_py.py` is STATIC and runs on the host.  Python ships its own
  parser, so unlike PHP — where `analyze_php.php` needs nikic/php-parser out
  of the project's own `vendor/` and therefore has to run in the container —
  the index is `ast` and nothing else.  It is imported as
  `r2t.py.analyze_py`.

* `match_steps.py` is DYNAMIC and runs inside `r2t_docx_img:base`.  It is a
  standalone script, copied into the workspace and executed there exactly as
  `match_steps.php` is, and it imports `behave` — which is why it may not be
  imported from the host, where behave is a different version or absent.
  Nothing in `r2t` imports it; `pystep_index` reads its bytes and runs it.

The reason the second one is a separate program rather than a function is the
reason `match_steps.php` is: a step matcher re-implemented in the harness is a
SECOND source of truth about which definition answers a step, and the first
time the two disagree the benchmark scores a scenario against glue that behave
would never have called.  So the matching is done by behave's own registry, in
the image the run will use, and this package is where that boundary is drawn.
"""
