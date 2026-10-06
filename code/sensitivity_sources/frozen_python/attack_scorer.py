from collections.abc import Mapping, Sequence, Set
from math import exp, isfinite, log
from numbers import Real
from types import MappingProxyType

from common import (
    AssertionViolation,
    QIS,
    TOLERANCE,
    require,
)


IMPLEMENTATION_STATUS = "CANDIDATE_SCORER_NOT_OPERATIONAL_PRODUCER"
PROTOCOL_TARGET_VERSION = "v1.2.4"

_BASE_K = ("age", "sex", "education", "marital-status")
_ATTRIBUTES = MappingProxyType({
    "BASE": _BASE_K,
    "S1": ("age", "sex"),
    "S2": QIS,
    "S3": _BASE_K,
    "S4": _BASE_K,
})
_BASE_Q = MappingProxyType({-2: 0.1, -1: 0.2, 0: 0.4, 1: 0.2, 2: 0.1})
_PMFS = MappingProxyType({
    "BASE": _BASE_Q,
    "S1": _BASE_Q,
    "S2": _BASE_Q,
    "S3": MappingProxyType({0: 1.0}),
    "S4": MappingProxyType({d: 1.0 / 11.0 for d in range(-5, 6)}),
})


def _integer(value, name, *, nonnegative=False):
    require(type(value) is int, "ATTACK_INVALID_INTEGER",
            name + " must be a Python int, not bool")
    require(not nonnegative or value >= 0, "ATTACK_NEGATIVE_INTEGER",
            name + " must be nonnegative")
    return value


def _string(value, name):
    require(type(value) is str and bool(value) and value == value.strip(),
            "ATTACK_INVALID_STRING",
            name + " must be an exact nonempty, unpadded string")
    return value


def _scenario(scenario):
    require(type(scenario) is str and scenario in _PMFS,
            "ATTACK_INVALID_SCENARIO",
            "scenario must be BASE, S1, S2, S3 or S4")
    return scenario


def scenario_attributes(scenario):

    return _ATTRIBUTES[_scenario(scenario)]


def scenario_pmf(scenario):

    selected = _PMFS[_scenario(scenario)]
    return tuple(sorted(selected.items()))


def q(scenario, error):
    """Age-error probability mass q_s; zero outside its support."""
    return _PMFS[_scenario(scenario)].get(_integer(error, "error"), 0.0)


def observe_age(raw_age, error, scenario):

    raw_age = _integer(raw_age, "raw_age", nonnegative=True)
    error = _integer(error, "error")
    require(q(scenario, error) > 0.0, "ATTACK_ERROR_OUTSIDE_SUPPORT",
            "error lies outside the scenario support")
    return raw_age + error


def _leafset(values, attribute):
    require(isinstance(values, Set) and not isinstance(values, (str, bytes)),
            "ATTACK_INVALID_LEAF_SET",
            attribute + " leaf set must be a set or frozenset, not a label")
    require(bool(values), "ATTACK_EMPTY_LEAF_SET",
            attribute + " leaf set must not be empty")
    if attribute == "age":
        return frozenset(
            _integer(value, "age leaf", nonnegative=True) for value in values
        )
    return frozenset(_string(value, attribute + " leaf") for value in values)


def age_compatibility(observed_age, age_leaves, scenario):
    """Return max_v q_s(z-v), not the sum or average of leaf masses."""
    observed_age = _integer(observed_age, "observed_age")
    selected_scenario = _scenario(scenario)
    leaves = _leafset(age_leaves, "age")
    return max(q(selected_scenario, observed_age - value) for value in leaves)


def score_candidates(observed_age, known_categories, candidate_leafsets, scenario):
    """Score candidate rows in their supplied order; duplicates remain distinct rows."""
    observed_age = _integer(observed_age, "observed_age")
    selected_scenario = _scenario(scenario)
    attributes = scenario_attributes(selected_scenario)
    categorical = tuple(attribute for attribute in attributes if attribute != "age")
    require(isinstance(known_categories, Mapping)
            and set(known_categories) == set(categorical),
            "ATTACK_KNOWN_KEYS",
            "known_categories must contain exactly the scenario's known categories")
    known = {
        attribute: _string(known_categories[attribute], attribute + " known value")
        for attribute in categorical
    }
    require(isinstance(candidate_leafsets, Sequence)
            and not isinstance(candidate_leafsets, (str, bytes, bytearray))
            and len(candidate_leafsets) > 0,
            "ATTACK_CANDIDATE_SEQUENCE",
            "candidate_leafsets must be a nonempty ordered row sequence")

    scores = []
    for row in candidate_leafsets:
        require(isinstance(row, Mapping) and set(row) == set(attributes),
                "ATTACK_CANDIDATE_KEYS",
                "each candidate must contain exactly the scenario's K_s leaf sets")

        leaves = {attribute: _leafset(row[attribute], attribute)
                  for attribute in attributes}
        factors = [
            age_compatibility(observed_age, leaves["age"], selected_scenario)
        ]
        factors.extend(
            float(known[attribute] in leaves[attribute])
            for attribute in categorical
        )
        log_score = (float("-inf") if any(factor == 0.0 for factor in factors)
                     else sum(log(factor) for factor in factors))
        scores.append(0.0 if log_score == float("-inf") else exp(log_score))
    return tuple(scores)


def _scores(values):
    require(isinstance(values, Sequence)
            and not isinstance(values, (str, bytes, bytearray))
            and len(values) > 0,
            "ATTACK_SCORE_SEQUENCE",
            "scores must be a nonempty ordered sequence")
    checked = []
    for value in values:
        require(isinstance(value, Real) and not isinstance(value, bool),
                "ATTACK_INVALID_SCORE",
                "each score must be a finite real, not bool")
        try:
            item = float(value)
        except (OverflowError, TypeError, ValueError) as error:
            raise AssertionViolation(
                "ATTACK_INVALID_SCORE: score is not representable as float"
            ) from error
        require(isfinite(item) and 0.0 <= item <= 1.0,
                "ATTACK_SCORE_RANGE",
                "each score must be finite and in [0,1]")
        checked.append(item)
    return tuple(checked)


def select_best(scores):
    """Select all positive maxima within absolute TOLERANCE on the S scale."""
    checked = _scores(scores)
    maximum = max(checked)
    if maximum == 0.0:
        return ()
    return tuple(index for index, value in enumerate(checked)
                 if abs(value - maximum) <= TOLERANCE)


def fractional_success(scores, true_row_index):
    """Return 1/|B| if B contains the retained true row, otherwise zero."""
    checked = _scores(scores)
    if true_row_index is not None:
        _integer(true_row_index, "true_row_index", nonnegative=True)
        require(true_row_index < len(checked), "ATTACK_TRUE_ROW_RANGE",
                "true_row_index is outside candidate rows")
    best = select_best(checked)
    return 1.0 / len(best) if true_row_index in best else 0.0
