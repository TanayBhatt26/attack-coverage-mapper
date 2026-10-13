"""Streamlit view modules (Phase 6+).

Each module in this package renders one dashboard surface.  Views consume the
analysis/detections layers through their public entry points -- never by
re-running the pipeline inline -- so the rendering layer stays thin and the
work-list invariant (one query per missed technique) is preserved verbatim.

Current views:
- :mod:`src.visualization.views.coverage` -- Coverage Overview (Plotly tactic heatmap).
- :mod:`src.visualization.views.simulation` -- APT Simulation (detected/missed + recs).
- :mod:`src.visualization.views.hunt` -- Hunt Queries (gap list + per-technique queries with DRL attribution).
- :mod:`src.visualization.views.gap` -- Gap Analysis (KMeans clusters + summaries).
"""

from . import coverage  # noqa: F401
from . import gap  # noqa: F401
from . import hunt  # noqa: F401
from . import simulation  # noqa: F401