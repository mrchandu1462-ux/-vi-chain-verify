import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from adapters.interface import VerificationInput
from adapters.reference import ReferenceVerifierAdapter
from vi_verify.replay_store import ReplayStore
from vi_verify.verify import VerifyContext


CORPUS_PATH = Path(__file__).with_name("corpus.py")

spec = importlib.util.spec_from_file_location(
    "phase_b_corpus",
    CORPUS_PATH,
)

if spec is None or spec.loader is None:
    raise ImportError(f"Unable to load corpus: {CORPUS_PATH}")

corpus = importlib.util.module_from_spec(spec)
sys.modules["phase_b_corpus"] = corpus
spec.loader.exec_module(corpus)

get_vectors = corpus.get_vectors


def test_phase_b_reference_corpus_matches_expected_decisions():
    for vector in get_vectors():
        chain, payment, trustline_public_key = vector.build()

        context = VerifyContext(
            trustline_public_key=trustline_public_key,
            replay_store=ReplayStore(),
        )

        adapter = ReferenceVerifierAdapter(context)

        result = adapter.verify(
            VerificationInput(
                chain=chain,
                payment=payment,
            )
        )

        assert result.source == "phase_a_independent_reference"
        assert result.is_mock is False

        assert result.decision == vector.expected_reference_decision, (
            vector.name,
            result.reasons,
        )
