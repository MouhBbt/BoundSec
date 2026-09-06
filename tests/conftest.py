import matplotlib

matplotlib.use("Agg")
import pytest


@pytest.fixture
def seeds():
    from boundsec.payloads.seeds import load_seeds
    return load_seeds()
