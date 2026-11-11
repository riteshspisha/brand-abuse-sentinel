"""BrandSentinel: local-first brand-abuse detection and triage."""

import os
import sys

# First statements of the package: a root process must not write bytecode into the
# code tree from here on. Console scripts already start with -B; this covers `python -m`
# and direct imports. It cannot cover imports that happened before this line.
if os.geteuid() == 0:
    sys.dont_write_bytecode = True

__version__ = "0.2.1"
