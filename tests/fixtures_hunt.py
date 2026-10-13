"""Shared fixtures for Phase 5 hunt-query tests.

Builds a temporary SigmaHQ-clone directory tree (no network) so
:class:`~detections.sigma_index.SigmaIndex` can be exercised against a
controlled corpus, plus small helpers for the curated/generic query tests.

Kept separate from ``conftest.py`` so the main fixture module stays focused
on the Phase 1-4 pipeline; hunt tests import these explicitly.
"""

from __future__ import annotations

import textwrap
from typing import Iterable

import pytest


def write_rule(
    path,
    *,
    title: str = "Synthetic Rule",
    technique_tags: Iterable[str] = ("attack.t1059.001",),
    product: str | None = "windows",
    category: str | None = "process_creation",
    service: str | None = None,
    status: str = "stable",
    author: str = "Synthetic Author",
) -> None:
    """Write a minimal, valid-enough Sigma rule YAML at ``path``.

    The rule is intentionally skeletal -- :class:`SigmaIndex` only reads tags
    via regex (no YAML parse at build), so we emit just enough structure to be
    a plausible rule file and carry the requested tags/logsource.

    Args:
        path: Destination ``Path`` (parent dir must exist).
        title: Rule title.
        technique_tags: ``attack.tXXXX`` tags to embed.
        product/category/service: ``logsource`` fields (all optional).
        status: Rule status string.
        author: Author string.
    """
    tags_block = "\n".join(f"    - {tag}" for tag in technique_tags)
    logsource_parts = []
    if product is not None:
        logsource_parts.append(f"product: {product}")
    if category is not None:
        logsource_parts.append(f"category: {category}")
    if service is not None:
        logsource_parts.append(f"service: {service}")
    logsource_block = "\n".join(f"  {line}" for line in logsource_parts)
    yaml = textwrap.dedent(
        f"""\
        title: {title}
        id: 00000000-0000-4000-8000-000000000001
        status: {status}
        author: {author}
        date: 2026-01-01
        tags:
        {tags_block}
        logsource:
        {logsource_block}
        detection:
          selection:
            CommandLine|contains: test
          condition: selection
        level: medium
        """
    )
    path.write_text(yaml, encoding="utf-8")


@pytest.fixture
def sigma_clone(tmp_path):
    """Build a tiny SigmaHQ-clone tree and return its root ``Path``.

    Layout (mirrors the real clone taxonomy enough for index tests)::

        rules/
          windows/process_creation/
            win_powershell.yml            (attack.t1059.001, product windows)
          cloud/aws/cloudtrail/
            aws_disable_logging.yml       (attack.t1562.001, product aws svc cloudtrail)
          network/zeek/
            zeek_dns.yml                  (attack.t1071.004, product zeek service dns)
          linux/
            lnx_aptm.yml                  (attack.t1071.001, product linux)
        not_a_rule.txt                    (ignored: wrong extension)

    The returned dict carries the root plus the resolved rule paths.
    """
    root = tmp_path / "sigma"
    rules = root / "rules"

    win = rules / "windows" / "process_creation"
    aws = rules / "cloud" / "aws" / "cloudtrail"
    zeek = rules / "network" / "zeek"
    lnx = rules / "linux"
    for d in (win, aws, zeek, lnx):
        d.mkdir(parents=True)

    write_rule(
        win / "win_powershell.yml",
        title="PowerShell Base64",
        technique_tags=("attack.t1059.001", "attack.t1059"),
        product="windows",
        category="process_creation",
    )
    write_rule(
        aws / "aws_disable_logging.yml",
        title="AWS Logging Disabled",
        technique_tags=("attack.t1562.001",),
        product="aws",
        category=None,
        service="cloudtrail",
    )
    write_rule(
        zeek / "zeek_dns.yml",
        title="Zeek DNS TXT",
        technique_tags=("attack.t1071.004",),
        product="zeek",
        category=None,
        service="dns",
    )
    write_rule(
        lnx / "lnx_aptm.yml",
        title="Linux Network",
        technique_tags=("attack.t1071.001",),
        product="linux",
        category="network_connection",
    )
    # A non-rule file that must be ignored by the scanner.
    (root / "not_a_rule.txt").write_text("attack.t9999.999", encoding="utf-8")

    return {
        "root": root,
        "rules": rules,
        "win_powershell": win / "win_powershell.yml",
        "aws_disable_logging": aws / "aws_disable_logging.yml",
        "zeek_dns": zeek / "zeek_dns.yml",
        "lnx_aptm": lnx / "lnx_aptm.yml",
    }
