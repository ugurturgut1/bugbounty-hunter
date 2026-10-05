"""Phase 3: CVSS v3.1 base-score calculator -- checked against official
reference vectors/scores from the CVSS 3.1 spec examples."""
import pytest

from bbhunter.reporting.cvss import base_score, parse_vector, score_and_rating


@pytest.mark.parametrize("vector,score,rating", [
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "medium"),
    ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),   # scope changed
    ("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "high"),
    ("AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, "none"),        # no impact
])
def test_known_cvss_vectors(vector, score, rating):
    assert score_and_rating(vector) == (score, rating)


def test_parse_vector_rejects_missing_metrics():
    with pytest.raises(ValueError):
        parse_vector("AV:N/AC:L")  # missing PR/UI/S/C/I/A


def test_base_score_rejects_unknown_value():
    with pytest.raises(ValueError):
        base_score("AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
