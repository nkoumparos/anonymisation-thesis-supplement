package org.nkoum.anonymisation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.deidentifier.arx.ARXConfiguration;
import org.deidentifier.arx.ARXConfiguration.AnonymizationAlgorithm;
import org.deidentifier.arx.AttributeType;
import org.deidentifier.arx.AttributeType.Hierarchy;
import org.deidentifier.arx.Data;
import org.deidentifier.arx.DataDefinition;
import org.deidentifier.arx.criteria.DistinctLDiversity;
import org.deidentifier.arx.criteria.EqualDistanceTCloseness;
import org.deidentifier.arx.criteria.ExplicitPrivacyCriterion;
import org.deidentifier.arx.criteria.KAnonymity;
import org.deidentifier.arx.criteria.PrivacyCriterion;
import org.deidentifier.arx.metric.Metric;
import org.deidentifier.arx.metric.MetricConfiguration;
import org.deidentifier.arx.metric.v2.MetricMDNMLoss;


public final class ArxConfigurationMatrixTest {

    private static final String REPORT_SCHEMA =
        "arx-cfg-matrix-tests-v1.2.3/1.0";

    private static final List<ExpectedRow> EXPECTED = expectedRows();


    private static final List<String> EXPECTED_PHYSICAL_SCHEMA =
        Collections.unmodifiableList(Arrays.asList(
            "sex", "age", "race", "marital-status", "education",
            "native-country", "workclass", "occupation", "salary-class"));

    private static final List<String> EXPECTED_QI_ORDER =
        Collections.unmodifiableList(Arrays.asList(
            "sex", "age", "race", "marital-status", "education",
            "native-country", "workclass", "occupation"));

    private static final Map<String, Integer> EXPECTED_MAX_GENERALIZATION =
        expectedMaximumGeneralizations();

    private static final List<String> EXPECTED_HANDLE_RECEIPT_CODES =
        Collections.unmodifiableList(Arrays.asList(
            "CFG_ASSERT_MANIFEST_IDENTITY",
            "CFG_ASSERT_SPEC_EXACT",
            "CFG_ASSERT_STATE_FRESH_DATA_DEFINITION",
            "CFG_ASSERT_STATE_FRESH_CONFIGURATION_CRITERIA",
            "CFG_ASSERT_RELEASE_SCHEMA",
            "CFG_ASSERT_OPERATIVE_HANDLE_DEFINITION",
            "CFG_ASSERT_QI_SET",
            "CFG_ASSERT_QI_GENERALIZATION_SET",
            "CFG_ASSERT_MICROAGGREGATION",
            "CFG_ASSERT_IDENTIFYING_SET",
            "CFG_ASSERT_RESPONSE_VARIABLES",
            "CFG_ASSERT_HIERARCHY_SET_CONTENT_BOUNDS",
            "CFG_ASSERT_TRANSFORMATION_SPACE",
            "CFG_ASSERT_SALARY_NOT_QI",
            "CFG_ASSERT_SALARY_NO_HIERARCHY_OR_MICROAGGREGATION",
            "CFG_ASSERT_SALARY_TYPE_AND_ATTRIBUTE_SETS",
            "CFG_ASSERT_ALGORITHM_THRESHOLD_MONOTONICITY",
            "CFG_ASSERT_SUPPRESSION_POLICY",
            "CFG_ASSERT_PRIVACY_MODEL_SET_CLASS_TARGET_VALUE",
            "CFG_ASSERT_METRIC_EXACT",
            "CFG_ASSERT_WEIGHT_SET_AND_VALUES"));

    private ArxConfigurationMatrixTest() {

    }

    public static void main(String[] args) {
        try {
            Arguments arguments = Arguments.parse(args);
            TestReport report = execute(arguments);
            byte[] bytes = report.json().getBytes(StandardCharsets.UTF_8);
            writeNew(arguments.report, bytes);
            System.out.println("CFG_MATRIX_REPORT=" + arguments.report);
            System.out.println("CFG_MATRIX_REPORT_BYTES=" + bytes.length);
            System.out.println("POSITIVE_TEST_COUNT=" + report.positive.size());
            System.out.println("NEGATIVE_TEST_COUNT=" + report.negative.size());
            System.out.println("ANONYMIZATION_INVOCATION_COUNT=0");
            System.out.println("RESULT=PASS");
        } catch (Throwable error) {
            String message = error.getMessage();
            if (message == null || message.isEmpty()) {
                message = "no detail";
            }
            System.err.println("RESULT=FAIL");
            System.err.println("ERROR_CLASS=" + error.getClass().getName());
            System.err.println("ERROR_MESSAGE=" + sanitize(message));
            System.exit(1);
        }
    }

    private static TestReport execute(Arguments arguments) {
        ArxConfigurationMatrix matrix = ArxConfigurationMatrix.load(
            arguments.repoRoot.resolve(ArxConfigurationMatrix.MANIFEST_RELATIVE_PATH));
        assertCatalog(matrix);

        List<PositiveResult> positive = new ArrayList<PositiveResult>();
        for (ExpectedRow expected : EXPECTED.subList(1, EXPECTED.size())) {
            Fixture first = fixture("raw");
            ArxConfigurationMatrix.PreparedConfiguration firstPrepared =
                matrix.prepare(expected.id, first.data, first.hierarchies);
            ArxConfigurationMatrix.AssertionReceipt firstReceipt =
                ArxConfigurationMatrix.assertPreparedForTests(firstPrepared);
            require(firstReceipt.allPassed(), "positive receipt did not pass");
            require(expected.fingerprint().equals(firstReceipt.fingerprint()),
                    "positive fingerprint mismatch for " + expected.id);
            require(firstReceipt.passedAssertions().equals(
                        EXPECTED_HANDLE_RECEIPT_CODES),
                    "positive assertion-code contract mismatch for " + expected.id);
            assertIndependentActual(expected, firstPrepared, first);

            Fixture second = fixture("raw");
            ArxConfigurationMatrix.PreparedConfiguration secondPrepared =
                matrix.prepare(expected.id, second.data, second.hierarchies);
            ArxConfigurationMatrix.AssertionReceipt secondReceipt =
                ArxConfigurationMatrix.assertPreparedForTests(secondPrepared);
            require(expected.fingerprint().equals(secondReceipt.fingerprint()),
                    "repeat fingerprint mismatch for " + expected.id);
            require(secondReceipt.passedAssertions().equals(
                        EXPECTED_HANDLE_RECEIPT_CODES),
                    "repeat assertion-code contract mismatch for " + expected.id);
            assertIndependentActual(expected, secondPrepared, second);
            assertFresh(firstPrepared, secondPrepared, expected.id);

            positive.add(new PositiveResult(
                expected.id, firstReceipt.fingerprint(),
                firstReceipt.passedAssertions().size()));
        }

        Fixture raw = fixture("raw");
        Fixture semantic = fixture("semantic");
        ArxConfigurationMatrix.PreparedConfiguration rawCfg =
            matrix.prepare("CFG02", raw.data, raw.hierarchies);
        ArxConfigurationMatrix.PreparedConfiguration semanticCfg =
            matrix.prepare("CFG02", semantic.data, semantic.hierarchies);
        require(rawCfg.preparationReceipt().fingerprint().equals(
                    semanticCfg.preparationReceipt().fingerprint()),
                "raw/semantic CFG02 fingerprints differ");

        List<NegativeResult> negative = new ArrayList<NegativeResult>();
        expectFailure(negative, "invalid_id_null", "CFG_ASSERT_ID_NULL",
            new FailureAction() {
                public void run() {
                    matrix.requireAnonymized(null);
                }
            });
        expectFailure(negative, "invalid_id_empty", "CFG_ASSERT_ID_DOMAIN",
            new FailureAction() {
                public void run() {
                    matrix.requireAnonymized("");
                }
            });
        expectFailure(negative, "invalid_id_cfg00", "CFG_ASSERT_ID_DOMAIN",
            new FailureAction() {
                public void run() {
                    matrix.requireAnonymized("CFG00");
                }
            });
        expectFailure(negative, "invalid_id_lowercase", "CFG_ASSERT_ID_DOMAIN",
            new FailureAction() {
                public void run() {
                    matrix.requireAnonymized("cfg01");
                }
            });
        expectFailure(negative, "invalid_id_whitespace", "CFG_ASSERT_ID_DOMAIN",
            new FailureAction() {
                public void run() {
                    matrix.requireAnonymized(" CFG01");
                }
            });
        expectFailure(negative, "invalid_id_cfg17", "CFG_ASSERT_ID_DOMAIN",
            new FailureAction() {
                public void run() {
                    matrix.requireAnonymized("CFG17");
                }
            });

        expectMutation(negative, matrix, "wrong_k_cfg01", "CFG01",
            "CFG_ASSERT_K_VALUE", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    ARXConfiguration config = prepared.configurationForTests();
                    removeExact(config, KAnonymity.class);
                    config.addPrivacyModel(new KAnonymity(3));
                }
            });
        expectMutation(negative, matrix, "wrong_k_cfg16", "CFG16",
            "CFG_ASSERT_K_VALUE", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    ARXConfiguration config = prepared.configurationForTests();
                    removeExact(config, KAnonymity.class);
                    config.addPrivacyModel(new KAnonymity(11));
                }
            });
        expectMutation(negative, matrix, "missing_k", "CFG02",
            "CFG_ASSERT_PRIVACY_MODEL_COUNT", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    removeExact(prepared.configurationForTests(), KAnonymity.class);
                }
            });
        expectMutation(negative, matrix, "extra_model_k_only", "CFG02",
            "CFG_ASSERT_PRIVACY_MODEL_COUNT", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().addPrivacyModel(
                        new DistinctLDiversity("salary-class", 2));
                }
            });
        expectMutation(negative, matrix, "missing_l", "CFG05",
            "CFG_ASSERT_PRIVACY_MODEL_COUNT", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    removeExact(prepared.configurationForTests(),
                                DistinctLDiversity.class);
                }
            });
        expectMutation(negative, matrix, "wrong_l_value", "CFG05",
            "CFG_ASSERT_L_VALUE", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    ARXConfiguration config = prepared.configurationForTests();
                    removeExact(config, DistinctLDiversity.class);
                    config.addPrivacyModel(new DistinctLDiversity("salary-class", 3));
                }
            });
        expectMutation(negative, matrix, "wrong_l_attribute", "CFG05",
            "CFG_ASSERT_L_ATTRIBUTE", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    ARXConfiguration config = prepared.configurationForTests();
                    removeExact(config, DistinctLDiversity.class);
                    config.addPrivacyModel(new DistinctLDiversity("age", 2));
                }
            });
        expectMutation(negative, matrix, "l_replaced_by_t", "CFG05",
            "CFG_ASSERT_L_MODEL", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    ARXConfiguration config = prepared.configurationForTests();
                    removeExact(config, DistinctLDiversity.class);
                    config.addPrivacyModel(
                        new EqualDistanceTCloseness("salary-class", 0.10d));
                }
            });
        expectMutation(negative, matrix, "missing_t", "CFG08",
            "CFG_ASSERT_PRIVACY_MODEL_COUNT", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    removeExact(prepared.configurationForTests(),
                                EqualDistanceTCloseness.class);
                }
            });
        expectMutation(negative, matrix, "wrong_t_value", "CFG08",
            "CFG_ASSERT_T_VALUE", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    ARXConfiguration config = prepared.configurationForTests();
                    removeExact(config, EqualDistanceTCloseness.class);
                    config.addPrivacyModel(new EqualDistanceTCloseness(
                        "salary-class", Math.nextUp(0.10d)));
                }
            });
        expectMutation(negative, matrix, "wrong_t_attribute", "CFG08",
            "CFG_ASSERT_T_ATTRIBUTE", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    ARXConfiguration config = prepared.configurationForTests();
                    removeExact(config, EqualDistanceTCloseness.class);
                    config.addPrivacyModel(new EqualDistanceTCloseness("age", 0.10d));
                }
            });
        expectMutation(negative, matrix, "t_replaced_by_l", "CFG08",
            "CFG_ASSERT_T_MODEL", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    ARXConfiguration config = prepared.configurationForTests();
                    removeExact(config, EqualDistanceTCloseness.class);
                    config.addPrivacyModel(new DistinctLDiversity("salary-class", 2));
                }
            });
        expectMutation(negative, matrix, "salary_type_k_only", "CFG02",
            "CFG_ASSERT_SALARY_TYPE", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    fixture.definition.setAttributeType(
                        "salary-class", AttributeType.SENSITIVE_ATTRIBUTE);
                }
            });
        expectMutation(negative, matrix, "salary_type_sensitive", "CFG05",
            "CFG_ASSERT_SALARY_TYPE", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    fixture.definition.setAttributeType(
                        "salary-class", AttributeType.INSENSITIVE_ATTRIBUTE);
                }
            });
        expectMutation(negative, matrix, "salary_hierarchy", "CFG02",
            "CFG_ASSERT_SALARY_HIERARCHY", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    fixture.definition.setHierarchy(
                        "salary-class", Hierarchy.create(new String[][] {
                            {"<=50K", "*"}, {">50K", "*"}
                        }));
                }
            });
        expectMutation(negative, matrix, "qi_missing", "CFG02",
            "CFG_ASSERT_QI_SET", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    fixture.definition.resetAttributeType("sex");
                }
            });
        expectMutation(negative, matrix, "hierarchy_missing", "CFG02",
            "CFG_ASSERT_HIERARCHY_PRESENT", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    fixture.definition.resetHierarchy("age");
                }
            });
        expectMutation(negative, matrix, "hierarchy_min", "CFG02",
            "CFG_ASSERT_HIERARCHY_MIN", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    fixture.definition.setMinimumGeneralization("age", 1);
                }
            });
        expectMutation(negative, matrix, "hierarchy_max", "CFG02",
            "CFG_ASSERT_HIERARCHY_MAX", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    fixture.definition.setMaximumGeneralization("age", 3);
                }
            });
        expectMutation(negative, matrix, "hierarchy_content", "CFG02",
            "CFG_ASSERT_HIERARCHY_CONTENT", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    String[][] changed = deepCopy(fixture.hierarchies.get("age"));
                    changed[0][1] = changed[0][1] + "_MUTATED";
                    fixture.definition.setHierarchy("age", Hierarchy.create(changed));
                }
            });
        expectMutation(negative, matrix, "microaggregation", "CFG02",
            "CFG_ASSERT_QI_GENERALIZATION_SET", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    fixture.definition.setMicroAggregationFunction(
                        "age", AttributeType.MicroAggregationFunction.createArithmeticMean());
                }
            });
        expectMutation(negative, matrix, "identifying_attribute", "CFG02",
            "CFG_ASSERT_IDENTIFYING_SET", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    fixture.definition.setAttributeType(
                        "salary-class", AttributeType.IDENTIFYING_ATTRIBUTE);
                }
            });
        expectMutation(negative, matrix, "response_variable", "CFG02",
            "CFG_ASSERT_RESPONSE_VARIABLES", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    fixture.definition.setResponseVariable("salary-class", true);
                }
            });
        expectMutation(negative, matrix, "suppression_negative_zero", "CFG02",
            "CFG_ASSERT_SUPPRESSION_LIMIT", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().setSuppressionLimit(-0.0d);
                }
            });
        expectMutation(negative, matrix, "suppression_wrong", "CFG11",
            "CFG_ASSERT_SUPPRESSION_LIMIT", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().setSuppressionLimit(0.0d);
                }
            });
        expectMutation(negative, matrix, "suppression_always", "CFG02",
            "CFG_ASSERT_SUPPRESSION_ALWAYS", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().setSuppressionAlwaysEnabled(false);
                }
            });
        expectMutation(negative, matrix, "suppression_flag_qi", "CFG02",
            "CFG_ASSERT_SUPPRESSION_FLAG_QI", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().setAttributeTypeSuppressed(
                        AttributeType.QUASI_IDENTIFYING_ATTRIBUTE, false);
                }
            });
        expectMutation(negative, matrix, "suppression_flag_sensitive", "CFG05",
            "CFG_ASSERT_SUPPRESSION_FLAG_SENSITIVE", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().setAttributeTypeSuppressed(
                        AttributeType.SENSITIVE_ATTRIBUTE, true);
                }
            });
        expectMutation(negative, matrix, "suppression_flag_insensitive", "CFG02",
            "CFG_ASSERT_SUPPRESSION_FLAG_INSENSITIVE", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().setAttributeTypeSuppressed(
                        AttributeType.INSENSITIVE_ATTRIBUTE, true);
                }
            });
        expectMutation(negative, matrix, "suppression_flag_identifying", "CFG02",
            "CFG_ASSERT_SUPPRESSION_FLAG_IDENTIFYING", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().setAttributeTypeSuppressed(
                        AttributeType.IDENTIFYING_ATTRIBUTE, true);
                }
            });
        expectMutation(negative, matrix, "algorithm", "CFG02",
            "CFG_ASSERT_ALGORITHM", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().setAlgorithm(
                        AnonymizationAlgorithm.BEST_EFFORT_BOTTOM_UP);
                }
            });
        expectMutation(negative, matrix, "heuristic_threshold", "CFG02",
            "CFG_ASSERT_HEURISTIC_THRESHOLD", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().setHeuristicSearchThreshold(6480);
                }
            });
        expectMutation(negative, matrix, "practical_monotonicity", "CFG02",
            "CFG_ASSERT_PRACTICAL_MONOTONICITY", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().setPracticalMonotonicity(true);
                }
            });
        expectMutation(negative, matrix, "metric_class", "CFG02",
            "CFG_ASSERT_METRIC_CLASS", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().setQualityModel(
                        Metric.createHeightMetric(Metric.AggregateFunction.ARITHMETIC_MEAN));
                }
            });
        expectMutation(negative, matrix, "metric_aggregate", "CFG02",
            "CFG_ASSERT_METRIC_AGGREGATE", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().setQualityModel(
                        Metric.createLossMetric(0.5d, Metric.AggregateFunction.SUM));
                }
            });
        expectMutation(negative, matrix, "metric_gs_factor", "CFG02",
            "CFG_ASSERT_METRIC_GS_FACTOR", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().setQualityModel(
                        Metric.createLossMetric(
                            Math.nextUp(0.5d),
                            Metric.AggregateFunction.ARITHMETIC_MEAN));
                }
            });
        expectMutation(negative, matrix, "weight_value", "CFG02",
            "CFG_ASSERT_WEIGHT_VALUE", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().setAttributeWeight(
                        "age", Math.nextUp(1.0d));
                }
            });
        expectMutation(negative, matrix, "weight_extra", "CFG02",
            "CFG_ASSERT_WEIGHT_KEY_SET", new Mutation() {
                public void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                                  Fixture fixture) {
                    prepared.configurationForTests().setAttributeWeight(
                        "salary-class", 1.0d);
                }
            });

        expectFailure(negative, "expected_hierarchy_missing",
            "CFG_ASSERT_EXPECTED_HIERARCHY_SET", new FailureAction() {
                public void run() {
                    Fixture fixture = fixture("raw");
                    fixture.hierarchies.remove("age");
                    matrix.prepare("CFG02", fixture.data, fixture.hierarchies);
                }
            });
        expectFailure(negative, "data_reuse", "CFG_ASSERT_STATE_REUSE_DATA",
            new FailureAction() {
                public void run() {
                    Fixture fixture = fixture("raw");
                    matrix.prepare("CFG02", fixture.data, fixture.hierarchies);
                    matrix.prepare("CFG03", fixture.data, fixture.hierarchies);
                }
            });
        expectFailure(negative, "effective_before_anonymize",
            "CFG_ASSERT_EFFECTIVE_NOT_COMPLETED", new FailureAction() {
                public void run() {
                    Fixture fixture = fixture("raw");
                    ArxConfigurationMatrix.PreparedConfiguration prepared =
                        matrix.prepare("CFG02", fixture.data, fixture.hierarchies);
                    matrix.assertEffective(
                        prepared, prepared.configurationForTests(),
                        prepared.definitionForTests());
                }
            });
        expectFailure(negative, "production_boundary_mutation_before_arx",
            "CFG_ASSERT_SUPPRESSION_LIMIT", new FailureAction() {
                public void run() throws Exception {
                    Fixture fixture = fixture("raw");
                    ArxConfigurationMatrix.PreparedConfiguration prepared =
                        matrix.prepare("CFG02", fixture.data, fixture.hierarchies);
                    prepared.configurationForTests().setSuppressionLimit(-0.0d);
                    prepared.anonymizeOnce();
                }
            });

        require(ArxConfigurationMatrix.anonymizationInvocationCountForTests() == 0,
                "mapper tests invoked anonymization");
        return new TestReport(positive, negative);
    }

    private static void assertCatalog(ArxConfigurationMatrix matrix) {
        require(ArxConfigurationMatrix.physicalSchema().equals(EXPECTED_PHYSICAL_SCHEMA),
                "public physical-schema contract mismatch");
        require(ArxConfigurationMatrix.qiOrder().equals(EXPECTED_QI_ORDER),
                "public QI-order contract mismatch");
        require(ArxConfigurationMatrix.maximumGeneralizations().equals(
                    EXPECTED_MAX_GENERALIZATION),
                "public maximum-generalization contract mismatch");
        List<ArxConfigurationMatrix.CfgSpec> actual = matrix.allSpecifications();
        require(actual.size() == EXPECTED.size(), "catalog size mismatch");
        for (int index = 0; index < EXPECTED.size(); index++) {
            ExpectedRow expected = EXPECTED.get(index);
            ArxConfigurationMatrix.CfgSpec observed = actual.get(index);
            require(expected.id.equals(observed.id()), "catalog ID mismatch");
            require(expected.family.equals(observed.family().token()),
                    "catalog family mismatch for " + expected.id);
            require(equals(expected.k, observed.k()), "catalog k mismatch");
            require(equals(expected.l, observed.l()), "catalog l mismatch");
            require(doubleEquals(expected.t, observed.t()), "catalog t mismatch");
            require(doubleEquals(expected.suppression, observed.suppressionLimit()),
                    "catalog suppression mismatch");
            require(expected.salaryType.equals(observed.salaryTypeToken()),
                    "catalog salary type mismatch");
            require(expected.fingerprint().equals(observed.fingerprint()),
                    "catalog fingerprint mismatch for " + expected.id);
        }
    }

    private static void assertFresh(
            ArxConfigurationMatrix.PreparedConfiguration first,
            ArxConfigurationMatrix.PreparedConfiguration second,
            String id) {
        require(first != second, "prepared identity reused for " + id);
        require(first.dataForTests() != second.dataForTests(),
                "Data identity reused for " + id);
        require(first.definitionForTests() != second.definitionForTests(),
                "DataDefinition identity reused for " + id);
        require(first.configurationForTests() != second.configurationForTests(),
                "ARXConfiguration identity reused for " + id);
        Set<PrivacyCriterion> identities = Collections.newSetFromMap(
            new IdentityHashMap<PrivacyCriterion, Boolean>());
        identities.addAll(first.configurationForTests().getPrivacyModels());
        for (PrivacyCriterion criterion :
                second.configurationForTests().getPrivacyModels()) {
            require(!identities.contains(criterion),
                    "privacy criterion identity reused for " + id);
        }
    }

    private static void assertIndependentActual(
            ExpectedRow expected,
            ArxConfigurationMatrix.PreparedConfiguration prepared,
            Fixture fixture) {
        ARXConfiguration configuration = prepared.configurationForTests();
        DataDefinition definition = prepared.definitionForTests();
        require(definition == fixture.definition,
                "independent definition identity mismatch for " + expected.id);
        require(configuration.getAlgorithm() == AnonymizationAlgorithm.OPTIMAL,
                "independent algorithm mismatch for " + expected.id);
        require(configuration.getHeuristicSearchThreshold() == Integer.MAX_VALUE,
                "independent threshold mismatch for " + expected.id);
        require(!configuration.isPracticalMonotonicity(),
                "independent practical-monotonicity mismatch for " + expected.id);
        require(configuration.isSuppressionAlwaysEnabled(),
                "independent suppression-always mismatch for " + expected.id);
        require(doubleEquals(expected.suppression,
                             Double.valueOf(configuration.getSuppressionLimit())),
                "independent suppression mismatch for " + expected.id);
        require(configuration.isAttributeTypeSuppressed(
                    AttributeType.QUASI_IDENTIFYING_ATTRIBUTE),
                "independent QI suppression flag mismatch for " + expected.id);
        require(!configuration.isAttributeTypeSuppressed(
                    AttributeType.SENSITIVE_ATTRIBUTE) &&
                !configuration.isAttributeTypeSuppressed(
                    AttributeType.INSENSITIVE_ATTRIBUTE) &&
                !configuration.isAttributeTypeSuppressed(
                    AttributeType.IDENTIFYING_ATTRIBUTE),
                "independent non-QI suppression flags mismatch for " + expected.id);

        KAnonymity observedK = null;
        DistinctLDiversity observedL = null;
        EqualDistanceTCloseness observedT = null;
        for (PrivacyCriterion criterion : configuration.getPrivacyModels()) {
            if (criterion.getClass().equals(KAnonymity.class)) {
                require(observedK == null, "independent duplicate K for " + expected.id);
                observedK = (KAnonymity) criterion;
            } else if (criterion.getClass().equals(DistinctLDiversity.class)) {
                require(observedL == null, "independent duplicate l for " + expected.id);
                observedL = (DistinctLDiversity) criterion;
            } else if (criterion.getClass().equals(EqualDistanceTCloseness.class)) {
                require(observedT == null, "independent duplicate t for " + expected.id);
                observedT = (EqualDistanceTCloseness) criterion;
            } else {
                throw new IllegalStateException(
                    "independent unexpected criterion for " + expected.id);
            }
        }
        require(observedK != null && observedK.getK() == expected.k.intValue(),
                "independent K mismatch for " + expected.id);
        int expectedCriteria = "k_only".equals(expected.family) ? 1 : 2;
        require(configuration.getPrivacyModels().size() == expectedCriteria,
                "independent criterion count mismatch for " + expected.id);
        if ("k_only".equals(expected.family)) {
            require(observedL == null && observedT == null,
                    "independent k-only signature mismatch for " + expected.id);
        } else if ("k_distinct_l".equals(expected.family)) {
            require(observedL != null && observedT == null &&
                    "salary-class".equals(
                        ((ExplicitPrivacyCriterion) observedL).getAttribute()) &&
                    doubleEquals(Double.valueOf(expected.l.doubleValue()),
                                 Double.valueOf(observedL.getL())),
                    "independent distinct-l mismatch for " + expected.id);
        } else {
            require(observedT != null && observedL == null &&
                    "salary-class".equals(
                        ((ExplicitPrivacyCriterion) observedT).getAttribute()) &&
                    doubleEquals(expected.t, Double.valueOf(observedT.getT())),
                    "independent equal-distance-t mismatch for " + expected.id);
        }

        require(fixture.data.getHandle().getNumColumns() ==
                    EXPECTED_PHYSICAL_SCHEMA.size(),
                "independent physical-schema width mismatch for " + expected.id);
        for (int index = 0; index < EXPECTED_PHYSICAL_SCHEMA.size(); index++) {
            require(EXPECTED_PHYSICAL_SCHEMA.get(index).equals(
                        fixture.data.getHandle().getAttributeName(index)),
                    "independent physical-schema mismatch for " + expected.id +
                    " at column " + index);
        }

        Set<String> qis = new HashSet<String>(EXPECTED_QI_ORDER);
        require(definition.getQuasiIdentifyingAttributes().equals(qis),
                "independent QI set mismatch for " + expected.id);
        require(definition.getQuasiIdentifiersWithGeneralization().equals(qis),
                "independent generalized QI set mismatch for " + expected.id);
        require(definition.getQuasiIdentifiersWithMicroaggregation().isEmpty(),
                "independent microaggregation mismatch for " + expected.id);
        AttributeType expectedSalary = "INSENSITIVE_ATTRIBUTE".equals(
            expected.salaryType)
            ? AttributeType.INSENSITIVE_ATTRIBUTE
            : AttributeType.SENSITIVE_ATTRIBUTE;
        require(definition.getAttributeType("salary-class") == expectedSalary,
                "independent salary type mismatch for " + expected.id);
        require(definition.getHierarchy("salary-class") == null,
                "independent salary hierarchy mismatch for " + expected.id);
        for (String qi : EXPECTED_QI_ORDER) {
            require(Arrays.deepEquals(fixture.hierarchies.get(qi),
                                      definition.getHierarchy(qi)),
                    "independent hierarchy mismatch for " + expected.id + "/" + qi);
            require(definition.getMinimumGeneralization(qi) == 0 &&
                    definition.getMaximumGeneralization(qi) ==
                        EXPECTED_MAX_GENERALIZATION.get(qi).intValue(),
                    "independent bounds mismatch for " + expected.id + "/" + qi);
        }

        Metric<?> metric = configuration.getQualityModel();
        require(metric != null && metric.getClass().equals(MetricMDNMLoss.class),
                "independent metric class mismatch for " + expected.id);
        require(metric.getAggregateFunction() ==
                    Metric.AggregateFunction.ARITHMETIC_MEAN &&
                doubleEquals(Double.valueOf(0.5d), Double.valueOf(
                    metric.getGeneralizationSuppressionFactor())),
                "independent metric settings mismatch for " + expected.id);
        MetricConfiguration details = metric.getConfiguration();
        require(details.getAggregateFunction() ==
                    Metric.AggregateFunction.ARITHMETIC_MEAN &&
                doubleEquals(Double.valueOf(0.5d),
                             Double.valueOf(details.getGsFactor())) &&
                !details.isMonotonic() && !details.isPrecomputed(),
                "independent metric configuration mismatch for " + expected.id);
        require(configuration.getAttributeWeights().keySet().equals(qis),
                "independent weight set mismatch for " + expected.id);
        for (String qi : qis) {
            require(doubleEquals(Double.valueOf(1.0d),
                                 configuration.getAttributeWeights().get(qi)),
                    "independent weight mismatch for " + expected.id + "/" + qi);
        }
    }

    private static void expectMutation(
            List<NegativeResult> results,
            final ArxConfigurationMatrix matrix,
            String testId,
            final String configId,
            String expectedCode,
            final Mutation mutation) {
        expectFailure(results, testId, expectedCode, new FailureAction() {
            public void run() throws Exception {
                Fixture fixture = fixture("raw");
                ArxConfigurationMatrix.PreparedConfiguration prepared =
                    matrix.prepare(configId, fixture.data, fixture.hierarchies);
                mutation.apply(prepared, fixture);
                prepared.anonymizeOnce();
            }
        });
    }

    private static void expectFailure(List<NegativeResult> results,
                                      String testId,
                                      String expectedCode,
                                      FailureAction action) {
        try {
            action.run();
        } catch (ArxConfigurationMatrix.CfgAssertionException error) {
            require(expectedCode.equals(error.code()),
                    testId + ": expected " + expectedCode +
                    ", observed " + error.code());
            results.add(new NegativeResult(
                testId, expectedCode, error.code()));
            return;
        } catch (Exception error) {
            throw new IllegalStateException(
                testId + ": unexpected exception " + error.getClass().getName(), error);
        }
        throw new IllegalStateException(testId + ": expected failure was not raised");
    }

    private static void removeExact(ARXConfiguration configuration,
                                    Class<?> exactClass) {
        List<PrivacyCriterion> copy = new ArrayList<PrivacyCriterion>(
            configuration.getPrivacyModels());
        boolean removed = false;
        for (PrivacyCriterion criterion : copy) {
            if (criterion.getClass().equals(exactClass)) {
                require(configuration.removeCriterion(criterion),
                        "criterion removal failed");
                removed = true;
            }
        }
        require(removed, "criterion to remove was absent");
    }

    private static Fixture fixture(String ageVariant) {
        Data.DefaultData data = Data.create();
        data.add(EXPECTED_PHYSICAL_SCHEMA.toArray(new String[0]));
        data.add("Male", "20", "White", "Never-married", "Bachelors",
                 "United-States", "Private", "Tech-support", "<=50K");
        data.add("Female", "30", "Black", "Married-civ-spouse", "HS-grad",
                 "Canada", "Self-emp-not-inc", "Sales", ">50K");
        DataDefinition definition = data.getDefinition();
        LinkedHashMap<String, String[][]> hierarchies =
            new LinkedHashMap<String, String[][]>();
        for (String qi : EXPECTED_QI_ORDER) {
            int maximum = EXPECTED_MAX_GENERALIZATION.get(qi).intValue();
            String first = valueFor(qi, 0);
            String second = valueFor(qi, 1);
            String[][] hierarchy = syntheticHierarchy(
                qi, first, second, maximum, ageVariant);
            definition.setAttributeType(qi, Hierarchy.create(hierarchy));
            definition.setMinimumGeneralization(qi, 0);
            definition.setMaximumGeneralization(qi, maximum);
            hierarchies.put(qi, hierarchy);
        }
        return new Fixture(data, definition, hierarchies);
    }

    private static String[][] syntheticHierarchy(String qi,
                                                  String first,
                                                  String second,
                                                  int maximum,
                                                  String ageVariant) {
        String[][] result = new String[2][maximum + 1];
        result[0][0] = first;
        result[1][0] = second;
        for (int level = 1; level <= maximum; level++) {
            String suffix = "age".equals(qi)
                ? ageVariant + "_L" + level
                : qi + "_L" + level;
            result[0][level] = suffix;
            result[1][level] = suffix;
        }
        return result;
    }

    private static String[][] deepCopy(String[][] source) {
        String[][] result = new String[source.length][];
        for (int index = 0; index < source.length; index++) {
            result[index] = source[index].clone();
        }
        return result;
    }

    private static String valueFor(String qi, int row) {
        Map<String, String[]> values = new HashMap<String, String[]>();
        values.put("sex", new String[] {"Male", "Female"});
        values.put("age", new String[] {"20", "30"});
        values.put("race", new String[] {"White", "Black"});
        values.put("marital-status",
                   new String[] {"Never-married", "Married-civ-spouse"});
        values.put("education", new String[] {"Bachelors", "HS-grad"});
        values.put("native-country", new String[] {"United-States", "Canada"});
        values.put("workclass", new String[] {"Private", "Self-emp-not-inc"});
        values.put("occupation", new String[] {"Tech-support", "Sales"});
        return values.get(qi)[row];
    }

    private static List<ExpectedRow> expectedRows() {
        List<ExpectedRow> rows = new ArrayList<ExpectedRow>();
        rows.add(row("CFG00", "raw_control", null, null, null, null,
                     "NOT_APPLICABLE", null));
        rows.add(row("CFG01", "k_only", 2, null, null, 0.0d,
                     "INSENSITIVE_ATTRIBUTE", null));
        rows.add(row("CFG02", "k_only", 5, null, null, 0.0d,
                     "INSENSITIVE_ATTRIBUTE", null));
        rows.add(row("CFG03", "k_only", 10, null, null, 0.0d,
                     "INSENSITIVE_ATTRIBUTE", null));
        rows.add(row("CFG04", "k_only", 20, null, null, 0.0d,
                     "INSENSITIVE_ATTRIBUTE", null));
        rows.add(row("CFG05", "k_distinct_l", 5, 2, null, 0.0d,
                     "SENSITIVE_ATTRIBUTE", null));
        rows.add(row("CFG06", "k_distinct_l", 10, 2, null, 0.0d,
                     "SENSITIVE_ATTRIBUTE", null));
        rows.add(row("CFG07", "k_equal_distance_t", 5, null, 0.20d, 0.0d,
                     "SENSITIVE_ATTRIBUTE", "0.20"));
        rows.add(row("CFG08", "k_equal_distance_t", 5, null, 0.10d, 0.0d,
                     "SENSITIVE_ATTRIBUTE", "0.10"));
        rows.add(row("CFG09", "k_equal_distance_t", 10, null, 0.20d, 0.0d,
                     "SENSITIVE_ATTRIBUTE", "0.20"));
        rows.add(row("CFG10", "k_equal_distance_t", 10, null, 0.10d, 0.0d,
                     "SENSITIVE_ATTRIBUTE", "0.10"));
        rows.add(row("CFG11", "k_only", 5, null, null, 0.05d,
                     "INSENSITIVE_ATTRIBUTE", null));
        rows.add(row("CFG12", "k_only", 10, null, null, 0.05d,
                     "INSENSITIVE_ATTRIBUTE", null));
        rows.add(row("CFG13", "k_distinct_l", 5, 2, null, 0.05d,
                     "SENSITIVE_ATTRIBUTE", null));
        rows.add(row("CFG14", "k_distinct_l", 10, 2, null, 0.05d,
                     "SENSITIVE_ATTRIBUTE", null));
        rows.add(row("CFG15", "k_equal_distance_t", 5, null, 0.10d, 0.05d,
                     "SENSITIVE_ATTRIBUTE", "0.10"));
        rows.add(row("CFG16", "k_equal_distance_t", 10, null, 0.10d, 0.05d,
                     "SENSITIVE_ATTRIBUTE", "0.10"));
        return Collections.unmodifiableList(rows);
    }

    private static Map<String, Integer> expectedMaximumGeneralizations() {
        LinkedHashMap<String, Integer> result =
            new LinkedHashMap<String, Integer>();
        result.put("sex", Integer.valueOf(1));
        result.put("age", Integer.valueOf(4));
        result.put("race", Integer.valueOf(1));
        result.put("marital-status", Integer.valueOf(2));
        result.put("education", Integer.valueOf(3));
        result.put("native-country", Integer.valueOf(2));
        result.put("workclass", Integer.valueOf(2));
        result.put("occupation", Integer.valueOf(2));
        return Collections.unmodifiableMap(result);
    }

    private static ExpectedRow row(String id, String family, Integer k, Integer l,
                                   Double t, Double suppression, String salary,
                                   String tLexical) {
        return new ExpectedRow(id, family, k, l, t, suppression, salary, tLexical);
    }

    private static boolean equals(Object first, Object second) {
        return first == null ? second == null : first.equals(second);
    }

    private static boolean doubleEquals(Double first, Double second) {
        if (first == null || second == null) {
            return first == null && second == null;
        }
        return Double.doubleToLongBits(first.doubleValue()) ==
               Double.doubleToLongBits(second.doubleValue());
    }

    private static String bitsHex(double value) {
        return String.format("%016x", Long.valueOf(Double.doubleToLongBits(value)));
    }

    private static String sanitize(String value) {
        return value.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ');
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    private static void writeNew(Path target, byte[] bytes) throws IOException {
        require(!Files.exists(target), "report target already exists");
        Path parent = target.getParent();
        require(parent != null, "report target has no parent");
        Files.createDirectories(parent);
        Path temporary = parent.resolve(target.getFileName().toString() + ".tmp");
        Files.write(temporary, bytes, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE);
        try {
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException error) {
                Files.move(temporary, target);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private interface FailureAction {
        void run() throws Exception;
    }

    private interface Mutation {
        void apply(ArxConfigurationMatrix.PreparedConfiguration prepared,
                   Fixture fixture) throws Exception;
    }

    private static final class Fixture {
        final Data.DefaultData data;
        final DataDefinition definition;
        final LinkedHashMap<String, String[][]> hierarchies;

        Fixture(Data.DefaultData data, DataDefinition definition,
                LinkedHashMap<String, String[][]> hierarchies) {
            this.data = data;
            this.definition = definition;
            this.hierarchies = hierarchies;
        }
    }

    private static final class ExpectedRow {
        final String id;
        final String family;
        final Integer k;
        final Integer l;
        final Double t;
        final Double suppression;
        final String salaryType;
        final String tLexical;

        ExpectedRow(String id, String family, Integer k, Integer l,
                    Double t, Double suppression, String salaryType,
                    String tLexical) {
            this.id = id;
            this.family = family;
            this.k = k;
            this.l = l;
            this.t = t;
            this.suppression = suppression;
            this.salaryType = salaryType;
            this.tLexical = tLexical;
        }

        String fingerprint() {
            if ("raw_control".equals(family)) {
                return id + "|raw_control|arx=NOT_APPLICABLE";
            }
            String models = "KAnonymity(" + k + ")";
            if ("k_distinct_l".equals(family)) {
                models += "+DistinctLDiversity(salary-class," + l + ")";
            } else if ("k_equal_distance_t".equals(family)) {
                models += "+EqualDistanceTCloseness(salary-class," + tLexical + ")";
            }
            return id + "|" + family + "|k=" + k + "|l=" +
                (l == null ? "null" : l.toString()) + "|t=" +
                (t == null ? "null" : bitsHex(t.doubleValue())) + "|s=" +
                bitsHex(suppression.doubleValue()) + "|salary=" + salaryType +
                "|models=" + models +
                "|metric=MetricMDNMLoss:ARITHMETIC_MEAN:3fe0000000000000" +
                "|weights=8x3ff0000000000000|hierarchy_space=6480";
        }
    }

    private static final class PositiveResult {
        final String id;
        final String fingerprint;
        final int assertionCount;

        PositiveResult(String id, String fingerprint, int assertionCount) {
            this.id = id;
            this.fingerprint = fingerprint;
            this.assertionCount = assertionCount;
        }
    }

    private static final class NegativeResult {
        final String id;
        final String expectedCode;
        final String observedCode;

        NegativeResult(String id, String expectedCode, String observedCode) {
            this.id = id;
            this.expectedCode = expectedCode;
            this.observedCode = observedCode;
        }
    }

    private static final class TestReport {
        final List<PositiveResult> positive;
        final List<NegativeResult> negative;

        TestReport(List<PositiveResult> positive, List<NegativeResult> negative) {
            this.positive = positive;
            this.negative = negative;
        }

        String json() {
            StringBuilder out = new StringBuilder();
            out.append("{\n");
            member(out, 1, "report_schema", REPORT_SCHEMA, true);
            member(out, 1, "status", "PASS", true);
            out.append("  \"manifest\": {\n");
            member(out, 2, "relative_path", ArxConfigurationMatrix.MANIFEST_RELATIVE_PATH, true);
            numberMember(out, 2, "bytes", ArxConfigurationMatrix.MANIFEST_BYTES, true);
            member(out, 2, "sha256", ArxConfigurationMatrix.MANIFEST_SHA256, false);
            out.append("  },\n");
            out.append("  \"receipt_contract\": {\n");
            out.append("    \"handle_present_assertions\": ")
               .append(stringArray(EXPECTED_HANDLE_RECEIPT_CODES)).append(",\n");
            numberMember(out, 2, "assertion_count",
                         EXPECTED_HANDLE_RECEIPT_CODES.size(), true);
            boolMember(out, 2, "assertion_codes_unique",
                       new HashSet<String>(EXPECTED_HANDLE_RECEIPT_CODES).size() ==
                           EXPECTED_HANDLE_RECEIPT_CODES.size(), false);
            out.append("  },\n");
            out.append("  \"catalog\": [\n");
            for (int index = 0; index < EXPECTED.size(); index++) {
                ExpectedRow row = EXPECTED.get(index);
                out.append("    {\"config_id\":").append(quote(row.id))
                   .append(",\"family\":").append(quote(row.family))
                   .append(",\"k\":").append(nullable(row.k))
                   .append(",\"l\":").append(nullable(row.l))
                   .append(",\"t_bits_hex\":")
                   .append(row.t == null ? "null" : quote(bitsHex(row.t.doubleValue())))
                   .append(",\"suppression_bits_hex\":")
                   .append(row.suppression == null ? "null" :
                           quote(bitsHex(row.suppression.doubleValue())))
                   .append(",\"salary_type\":").append(quote(row.salaryType))
                   .append(",\"fingerprint\":").append(quote(row.fingerprint()))
                   .append("}");
                out.append(index + 1 == EXPECTED.size() ? "\n" : ",\n");
            }
            out.append("  ],\n");
            out.append("  \"positive_tests\": [\n");
            for (int index = 0; index < positive.size(); index++) {
                PositiveResult result = positive.get(index);
                out.append("    {\"test_id\":")
                   .append(quote("positive_" + result.id))
                   .append(",\"config_id\":").append(quote(result.id))
                   .append(",\"fingerprint\":").append(quote(result.fingerprint))
                   .append(",\"assertion_count\":").append(result.assertionCount)
                   .append(",\"repeat_build_fresh\":true,\"status\":\"PASS\"}");
                out.append(index + 1 == positive.size() ? "\n" : ",\n");
            }
            out.append("  ],\n");
            out.append("  \"negative_tests\": [\n");
            for (int index = 0; index < negative.size(); index++) {
                NegativeResult result = negative.get(index);
                out.append("    {\"test_id\":").append(quote(result.id))
                   .append(",\"expected_code\":").append(quote(result.expectedCode))
                   .append(",\"observed_code\":").append(quote(result.observedCode))
                   .append(",\"anonymization_invocation_count\":0,")
                   .append("\"fallback_used\":false,\"status\":\"PASS\"}");
                out.append(index + 1 == negative.size() ? "\n" : ",\n");
            }
            out.append("  ],\n");
            out.append("  \"summary\": {\n");
            numberMember(out, 2, "catalog_rows", EXPECTED.size(), true);
            numberMember(out, 2, "anonymized_cfg_rows", 16, true);
            numberMember(out, 2, "positive_tests", positive.size(), true);
            numberMember(out, 2, "negative_tests", negative.size(), true);
            numberMember(out, 2, "anonymization_invocation_count", 0, true);
            boolMember(out, 2, "raw_semantic_cfg02_fingerprint_equal", true, true);
            boolMember(out, 2, "fallback_used", false, true);
            boolMember(out, 2, "main_runs_authorized", false, false);
            out.append("  }\n");
            out.append("}\n");
            return out.toString();
        }
    }

    private static void member(StringBuilder out, int indent, String name,
                               String value, boolean comma) {
        spaces(out, indent);
        out.append(quote(name)).append(": ").append(quote(value));
        out.append(comma ? ",\n" : "\n");
    }

    private static void numberMember(StringBuilder out, int indent, String name,
                                     long value, boolean comma) {
        spaces(out, indent);
        out.append(quote(name)).append(": ").append(value);
        out.append(comma ? ",\n" : "\n");
    }

    private static void boolMember(StringBuilder out, int indent, String name,
                                   boolean value, boolean comma) {
        spaces(out, indent);
        out.append(quote(name)).append(": ").append(value);
        out.append(comma ? ",\n" : "\n");
    }

    private static void spaces(StringBuilder out, int indent) {
        for (int i = 0; i < indent * 2; i++) {
            out.append(' ');
        }
    }

    private static String nullable(Integer value) {
        return value == null ? "null" : value.toString();
    }

    private static String stringArray(List<String> values) {
        StringBuilder out = new StringBuilder();
        out.append('[');
        for (int index = 0; index < values.size(); index++) {
            if (index != 0) {
                out.append(',');
            }
            out.append(quote(values.get(index)));
        }
        out.append(']');
        return out.toString();
    }

    private static String quote(String value) {
        StringBuilder out = new StringBuilder();
        out.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == '"' || character == '\\') {
                out.append('\\').append(character);
            } else if (character < 0x20) {
                out.append(String.format("\\u%04x", Integer.valueOf(character)));
            } else {
                out.append(character);
            }
        }
        out.append('"');
        return out.toString();
    }

    private static final class Arguments {
        final Path repoRoot;
        final Path report;

        Arguments(Path repoRoot, Path report) {
            this.repoRoot = repoRoot;
            this.report = report;
        }

        static Arguments parse(String[] args) throws IOException {
            require(args.length == 4,
                    "usage: --repo-root <absolute> --report <absolute>");
            Map<String, String> values = new HashMap<String, String>();
            for (int index = 0; index < args.length; index += 2) {
                require("--repo-root".equals(args[index]) ||
                        "--report".equals(args[index]),
                        "unknown argument: " + args[index]);
                require(values.put(args[index], args[index + 1]) == null,
                        "duplicate argument: " + args[index]);
            }
            Path root = Paths.get(values.get("--repo-root"));
            Path report = Paths.get(values.get("--report"));
            require(root.isAbsolute() && report.isAbsolute(),
                    "paths must be absolute");
            root = root.toRealPath();
            report = report.toAbsolutePath().normalize();
            require(Files.isDirectory(root), "repo-root is not a directory");
            return new Arguments(root, report);
        }
    }
}
