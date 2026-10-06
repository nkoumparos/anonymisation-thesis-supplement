from collections.abc import Mapping
import copy
import hashlib
import json
import math
from numbers import Real

QIS = ('age', 'sex', 'race', 'marital-status', 'education',
       'native-country', 'workclass', 'occupation')
POPULATION_SIZE = 30162
HOLDOUT_SIZE = 15060
TARGET_COUNT = 5000
DRAW_COUNT = 30
BOOTSTRAP_COUNT = 2000
TOLERANCE = 1e-12
RID_ORDER_SHA256 = '11fd5eeaaa9fd5245361fce5b6d7aa7c8e4f0b7110ca026580586ccecb74ba68'
CONFIGURATION_SHA256 = 'ae28a3ac91dd733c5561a6f4d887c48d4b792915531d72a5e2158bc0bce72d2e'


class AssertionViolation(ValueError):

    def __init__(self, code, message):
        self.code = code
        super().__init__(code + ': ' + message)


def require(condition, code, message):
    if not condition:
        raise AssertionViolation(code, message)


def number(value, name):
    require(isinstance(value, Real) and not isinstance(value, bool),
            'INVALID_NUMBER', name + ' must be a finite real number, not bool')
    try:
        result = float(value)
    except (ValueError, OverflowError, TypeError) as error:
        raise AssertionViolation('INVALID_NUMBER', name + ' cannot be represented as float64') from error
    require(math.isfinite(result), 'NONFINITE_NUMBER', name + ' must be finite')
    return result


def integer(value, name, minimum=0):
    require(type(value) is int and value >= minimum, 'INVALID_INTEGER',
            name + ' must be a Python integer >= ' + str(minimum) + ', not bool')
    return value


def exact_keys(mapping, keys, name):
    require(isinstance(mapping, Mapping), 'INVALID_MAPPING', name + ' must be a mapping')
    require(set(mapping) == set(keys), 'MAPPING_KEYS_MISMATCH', name + ' has missing or extra keys')
    return mapping


def json_digest(value):

    try:
        data = json.dumps(value, ensure_ascii=True, allow_nan=False,
                          sort_keys=True, separators=(',', ':')).encode('ascii')
    except (ValueError, TypeError, OverflowError) as error:
        raise AssertionViolation('NONCANONICAL_JSON', 'Unsupported hash input') from error
    return hashlib.sha256(data).hexdigest()


_CONFIGS = {'CFG00': {'config_id': 'CFG00', 'family': 'raw_control', 'k': None, 'l': None, 't': None, 't_distance': None, 'suppression_limit': None, 'arx_salary_attribute_type': 'NOT_APPLICABLE'}, 'CFG01': {'config_id': 'CFG01', 'family': 'k_only', 'k': 2, 'l': None, 't': None, 't_distance': None, 'suppression_limit': 0.0, 'arx_salary_attribute_type': 'INSENSITIVE_ATTRIBUTE'}, 'CFG02': {'config_id': 'CFG02', 'family': 'k_only', 'k': 5, 'l': None, 't': None, 't_distance': None, 'suppression_limit': 0.0, 'arx_salary_attribute_type': 'INSENSITIVE_ATTRIBUTE'}, 'CFG03': {'config_id': 'CFG03', 'family': 'k_only', 'k': 10, 'l': None, 't': None, 't_distance': None, 'suppression_limit': 0.0, 'arx_salary_attribute_type': 'INSENSITIVE_ATTRIBUTE'}, 'CFG04': {'config_id': 'CFG04', 'family': 'k_only', 'k': 20, 'l': None, 't': None, 't_distance': None, 'suppression_limit': 0.0, 'arx_salary_attribute_type': 'INSENSITIVE_ATTRIBUTE'}, 'CFG05': {'config_id': 'CFG05', 'family': 'k_distinct_l', 'k': 5, 'l': 2, 't': None, 't_distance': None, 'suppression_limit': 0.0, 'arx_salary_attribute_type': 'SENSITIVE_ATTRIBUTE'}, 'CFG06': {'config_id': 'CFG06', 'family': 'k_distinct_l', 'k': 10, 'l': 2, 't': None, 't_distance': None, 'suppression_limit': 0.0, 'arx_salary_attribute_type': 'SENSITIVE_ATTRIBUTE'}, 'CFG07': {'config_id': 'CFG07', 'family': 'k_equal_distance_t', 'k': 5, 'l': None, 't': 0.2, 't_distance': 'equal_distance', 'suppression_limit': 0.0, 'arx_salary_attribute_type': 'SENSITIVE_ATTRIBUTE'}, 'CFG08': {'config_id': 'CFG08', 'family': 'k_equal_distance_t', 'k': 5, 'l': None, 't': 0.1, 't_distance': 'equal_distance', 'suppression_limit': 0.0, 'arx_salary_attribute_type': 'SENSITIVE_ATTRIBUTE'}, 'CFG09': {'config_id': 'CFG09', 'family': 'k_equal_distance_t', 'k': 10, 'l': None, 't': 0.2, 't_distance': 'equal_distance', 'suppression_limit': 0.0, 'arx_salary_attribute_type': 'SENSITIVE_ATTRIBUTE'}, 'CFG10': {'config_id': 'CFG10', 'family': 'k_equal_distance_t', 'k': 10, 'l': None, 't': 0.1, 't_distance': 'equal_distance', 'suppression_limit': 0.0, 'arx_salary_attribute_type': 'SENSITIVE_ATTRIBUTE'}, 'CFG11': {'config_id': 'CFG11', 'family': 'k_only', 'k': 5, 'l': None, 't': None, 't_distance': None, 'suppression_limit': 0.05, 'arx_salary_attribute_type': 'INSENSITIVE_ATTRIBUTE'}, 'CFG12': {'config_id': 'CFG12', 'family': 'k_only', 'k': 10, 'l': None, 't': None, 't_distance': None, 'suppression_limit': 0.05, 'arx_salary_attribute_type': 'INSENSITIVE_ATTRIBUTE'}, 'CFG13': {'config_id': 'CFG13', 'family': 'k_distinct_l', 'k': 5, 'l': 2, 't': None, 't_distance': None, 'suppression_limit': 0.05, 'arx_salary_attribute_type': 'SENSITIVE_ATTRIBUTE'}, 'CFG14': {'config_id': 'CFG14', 'family': 'k_distinct_l', 'k': 10, 'l': 2, 't': None, 't_distance': None, 'suppression_limit': 0.05, 'arx_salary_attribute_type': 'SENSITIVE_ATTRIBUTE'}, 'CFG15': {'config_id': 'CFG15', 'family': 'k_equal_distance_t', 'k': 5, 'l': None, 't': 0.1, 't_distance': 'equal_distance', 'suppression_limit': 0.05, 'arx_salary_attribute_type': 'SENSITIVE_ATTRIBUTE'}, 'CFG16': {'config_id': 'CFG16', 'family': 'k_equal_distance_t', 'k': 10, 'l': None, 't': 0.1, 't_distance': 'equal_distance', 'suppression_limit': 0.05, 'arx_salary_attribute_type': 'SENSITIVE_ATTRIBUTE'}}


def cfg_contract(cfg_id):
    require(type(cfg_id) is str and cfg_id in _CONFIGS,
            'INVALID_CFG', 'Expected an exact CFG00 through CFG16 identifier')
    return copy.deepcopy(_CONFIGS[cfg_id])
