package org.nkoum.anonymisation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.deidentifier.arx.ARXAnonymizer;
import org.deidentifier.arx.ARXConfiguration;
import org.deidentifier.arx.ARXConfiguration.AnonymizationAlgorithm;
import org.deidentifier.arx.ARXResult;
import org.deidentifier.arx.AttributeType;
import org.deidentifier.arx.Data;
import org.deidentifier.arx.DataDefinition;
import org.deidentifier.arx.DataHandle;
import org.deidentifier.arx.criteria.DistinctLDiversity;
import org.deidentifier.arx.criteria.EqualDistanceTCloseness;
import org.deidentifier.arx.criteria.ExplicitPrivacyCriterion;
import org.deidentifier.arx.criteria.KAnonymity;
import org.deidentifier.arx.criteria.PrivacyCriterion;
import org.deidentifier.arx.metric.Metric;
import org.deidentifier.arx.metric.MetricConfiguration;
import org.deidentifier.arx.metric.v2.MetricMDNMLoss;


public final class ArxConfigurationMatrix {

    public static final String MANIFEST_RELATIVE_PATH = "configurations.csv";
    public static final long MANIFEST_BYTES = 1150L;
    public static final String MANIFEST_SHA256 =
        "ae28a3ac91dd733c5561a6f4d887c48d4b792915531d72a5e2158bc0bce72d2e";

    private static final String SALARY = "salary-class";

    private static final List<String> PHYSICAL_SCHEMA = immutable(
        "sex", "age", "race", "marital-status", "education",
        "native-country", "workclass", "occupation", SALARY);

    private static final List<String> QI_ORDER = immutable(
        "sex", "age", "race", "marital-status", "education",
        "native-country", "workclass", "occupation");

    private static final Map<String, Integer> MAX_GENERALIZATION =
        buildMaximumGeneralizations();

    private static final List<CfgSpec> CATALOG = catalog();
    private static final Map<String, CfgSpec> BY_ID = byId(CATALOG);

    private static final Set<Data> PREPARED_DATA = Collections.synchronizedSet(
        Collections.newSetFromMap(new IdentityHashMap<Data, Boolean>()));

    private static final Set<DataDefinition> PREPARED_DEFINITIONS =
        Collections.synchronizedSet(
            Collections.newSetFromMap(
                new IdentityHashMap<DataDefinition, Boolean>()));

    private static final Set<ARXConfiguration> PREPARED_CONFIGURATIONS =
        Collections.synchronizedSet(
            Collections.newSetFromMap(
                new IdentityHashMap<ARXConfiguration, Boolean>()));

    private static final Set<PrivacyCriterion> PREPARED_CRITERIA =
        Collections.synchronizedSet(
            Collections.newSetFromMap(
                new IdentityHashMap<PrivacyCriterion, Boolean>()));

    private static final AtomicInteger ANONYMIZATION_INVOCATIONS =
        new AtomicInteger(0);

    static {
        validateStaticCatalog();
    }

    private final Path manifestPath;

    private ArxConfigurationMatrix(Path manifestPath) {
        this.manifestPath = manifestPath;
    }


    public static ArxConfigurationMatrix load(Path path) {
        require(path != null, "CFG_ASSERT_MANIFEST_PATH", "manifest path is null");
        Path normalized = path.toAbsolutePath().normalize();
        validateManifest(normalized);
        return new ArxConfigurationMatrix(normalized);
    }

    private static void validateManifest(Path path) {
        final byte[] bytes;
        try {
            require(Files.isRegularFile(path), "CFG_ASSERT_MANIFEST_FILE",
                    "configuration manifest is missing or not a regular file");
            long before = Files.size(path);
            bytes = Files.readAllBytes(path);
            long after = Files.size(path);
            require(before == after && before == bytes.length,
                    "CFG_ASSERT_MANIFEST_STABILITY",
                    "configuration manifest changed while it was read");
        } catch (IOException error) {
            throw new CfgAssertionException(
                "CFG_ASSERT_MANIFEST_READ", "cannot read configuration manifest", error);
        }
        require(bytes.length == MANIFEST_BYTES, "CFG_ASSERT_MANIFEST_BYTES",
                "configuration manifest byte length mismatch");
        require(!startsWithUtf8Bom(bytes), "CFG_ASSERT_MANIFEST_BOM",
                "configuration manifest has a UTF-8 BOM");
        for (byte value : bytes) {
            require(value != '\r', "CFG_ASSERT_MANIFEST_EOL",
                    "configuration manifest contains CR");
            require(value != 0, "CFG_ASSERT_MANIFEST_NUL",
                    "configuration manifest contains NUL");
        }
        require(bytes.length > 0 && bytes[bytes.length - 1] == '\n',
                "CFG_ASSERT_MANIFEST_FINAL_LF",
                "configuration manifest does not end with LF");
        require(MANIFEST_SHA256.equals(sha256(bytes)), "CFG_ASSERT_MANIFEST_SHA256",
                "configuration manifest SHA-256 mismatch");
        String text = new String(bytes, StandardCharsets.UTF_8);
        require(Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8)),
                "CFG_ASSERT_MANIFEST_UTF8", "configuration manifest is not strict UTF-8");
        require(canonicalManifest().equals(text), "CFG_ASSERT_MANIFEST_CONTENT",
                "configuration manifest content differs from the closed catalog");
    }


    public List<CfgSpec> anonymizedSpecifications() {
        return CATALOG.subList(1, CATALOG.size());
    }


    public List<CfgSpec> allSpecifications() {
        return CATALOG;
    }


    public CfgSpec requireAnonymized(String configId) {
        require(configId != null, "CFG_ASSERT_ID_NULL", "configuration ID is null");
        require(configId.matches("CFG(?:0[1-9]|1[0-6])"),
                "CFG_ASSERT_ID_DOMAIN", "configuration ID is not CFG01-CFG16");
        CfgSpec spec = BY_ID.get(configId);
        require(spec != null && spec.family != Family.RAW_CONTROL,
                "CFG_ASSERT_ID_CATALOG", "configuration ID is absent from the catalog");
        return spec;
    }


    public PreparedConfiguration prepare(String configId,
                                          Data data,
                                          Map<String, String[][]> expectedHierarchies) {
        CfgSpec spec = requireAnonymized(configId);
        require(data != null, "CFG_ASSERT_DATA_NULL", "data is null");
        DataDefinition definition = data.getDefinition();
        require(definition != null, "CFG_ASSERT_DEFINITION_NULL", "definition is null");

        synchronized (PREPARED_DATA) {
            require(PREPARED_DATA.add(data), "CFG_ASSERT_STATE_REUSE_DATA",
                    "Data object has already been prepared in this process");
        }
        synchronized (PREPARED_DEFINITIONS) {
            require(PREPARED_DEFINITIONS.add(definition),
                    "CFG_ASSERT_STATE_REUSE_DEFINITION",
                    "DataDefinition object has already been prepared in this process");
        }

        definition.setAttributeType(SALARY, spec.salaryAttributeType());
        ARXConfiguration configuration = buildConfiguration(spec);
        synchronized (PREPARED_CONFIGURATIONS) {
            require(PREPARED_CONFIGURATIONS.add(configuration),
                    "CFG_ASSERT_STATE_REUSE_CONFIGURATION",
                    "ARXConfiguration object has already been prepared");
        }
        synchronized (PREPARED_CRITERIA) {
            for (PrivacyCriterion criterion : configuration.getPrivacyModels()) {
                require(PREPARED_CRITERIA.add(criterion),
                        "CFG_ASSERT_STATE_REUSE_CRITERION",
                        "privacy-criterion object has already been prepared");
            }
        }
        Map<String, String[][]> frozenHierarchies =
            deepImmutableHierarchyCopy(expectedHierarchies);
        AssertionReceipt receipt = assertConfiguration(
            spec, data.getHandle(), definition, configuration,
            frozenHierarchies, "preparation");
        return new PreparedConfiguration(
            this, spec, data, definition, configuration,
            frozenHierarchies, receipt);
    }


    public AssertionReceipt assertEffective(PreparedConfiguration prepared,
                                              ARXConfiguration configuration,
                                              DataDefinition definition) {
        require(prepared != null && prepared.matrix == this,
                "CFG_ASSERT_PREPARED_OWNER", "prepared configuration owner mismatch");
        prepared.assertEffectiveInputs(configuration, definition);
        return assertConfiguration(
            prepared.spec, null, definition, configuration,
            prepared.expectedHierarchies, "effective");
    }

    public Path manifestPath() {
        return manifestPath;
    }

    public String manifestSha256() {
        return MANIFEST_SHA256;
    }

    public long manifestBytes() {
        return MANIFEST_BYTES;
    }

    public static List<String> physicalSchema() {
        return PHYSICAL_SCHEMA;
    }

    public static List<String> qiOrder() {
        return QI_ORDER;
    }

    public static Map<String, Integer> maximumGeneralizations() {
        return MAX_GENERALIZATION;
    }

    static int anonymizationInvocationCountForTests() {
        return ANONYMIZATION_INVOCATIONS.get();
    }

    static AssertionReceipt assertPreparedForTests(PreparedConfiguration prepared) {
        require(prepared != null, "CFG_ASSERT_PREPARED_NULL",
                "prepared configuration is null");
        return prepared.matrix.assertConfiguration(
            prepared.spec, prepared.data.getHandle(), prepared.definition,
            prepared.configuration, prepared.expectedHierarchies, "test_recheck");
    }

    private static ARXConfiguration buildConfiguration(CfgSpec spec) {
        ARXConfiguration configuration = ARXConfiguration.create();
        configuration.addPrivacyModel(new KAnonymity(spec.k.intValue()));
        if (spec.family == Family.K_DISTINCT_L) {
            configuration.addPrivacyModel(
                new DistinctLDiversity(SALARY, spec.l.intValue()));
        } else if (spec.family == Family.K_EQUAL_DISTANCE_T) {
            configuration.addPrivacyModel(
                new EqualDistanceTCloseness(SALARY, spec.t.doubleValue()));
        }
        configuration.setSuppressionLimit(spec.suppressionLimit.doubleValue());
        configuration.setSuppressionAlwaysEnabled(true);
        configuration.setAttributeTypeSuppressed(
            AttributeType.QUASI_IDENTIFYING_ATTRIBUTE, true);
        configuration.setAttributeTypeSuppressed(
            AttributeType.SENSITIVE_ATTRIBUTE, false);
        configuration.setAttributeTypeSuppressed(
            AttributeType.INSENSITIVE_ATTRIBUTE, false);
        configuration.setAttributeTypeSuppressed(
            AttributeType.IDENTIFYING_ATTRIBUTE, false);
        configuration.setAlgorithm(AnonymizationAlgorithm.OPTIMAL);
        configuration.setHeuristicSearchThreshold(Integer.MAX_VALUE);
        configuration.setPracticalMonotonicity(false);
        configuration.setQualityModel(
            Metric.createLossMetric(
                0.5d, Metric.AggregateFunction.ARITHMETIC_MEAN));
        for (String qi : QI_ORDER) {
            configuration.setAttributeWeight(qi, 1.0d);
        }
        return configuration;
    }

    private AssertionReceipt assertConfiguration(
            CfgSpec spec,
            DataHandle handle,
            DataDefinition definition,
            ARXConfiguration configuration,
            Map<String, String[][]> expectedHierarchies,
            String phase) {

        List<String> passed = new ArrayList<String>();
        require(spec != null, "CFG_ASSERT_SPEC_NULL", "specification is null");
        require(definition != null, "CFG_ASSERT_DEFINITION_NULL", "definition is null");
        require(configuration != null, "CFG_ASSERT_CONFIGURATION_NULL",
                "configuration is null");
        validateManifest(manifestPath);
        record(passed, "CFG_ASSERT_MANIFEST_IDENTITY");
        record(passed, "CFG_ASSERT_SPEC_EXACT");
        record(passed, "CFG_ASSERT_STATE_FRESH_DATA_DEFINITION");
        record(passed, "CFG_ASSERT_STATE_FRESH_CONFIGURATION_CRITERIA");

        if (handle != null) {
            require(handle.getNumColumns() == PHYSICAL_SCHEMA.size(),
                    "CFG_ASSERT_RELEASE_SCHEMA", "release schema column count mismatch");
            for (int index = 0; index < PHYSICAL_SCHEMA.size(); index++) {
                require(PHYSICAL_SCHEMA.get(index).equals(handle.getAttributeName(index)),
                        "CFG_ASSERT_RELEASE_SCHEMA",
                        "release schema mismatch at column " + index);
            }
            record(passed, "CFG_ASSERT_RELEASE_SCHEMA");
            DataDefinition operative = handle.getDefinition();
            require(operative != null, "CFG_ASSERT_OPERATIVE_DEFINITION_NULL",
                    "operative handle definition is null");
            assertConfiguration(
                spec, null, operative, configuration, expectedHierarchies,
                phase + "_operative_handle_definition");
            record(passed, "CFG_ASSERT_OPERATIVE_HANDLE_DEFINITION");
        }

        Set<String> expectedQiSet = new HashSet<String>(QI_ORDER);
        require(definition.getQuasiIdentifyingAttributes().equals(expectedQiSet),
                "CFG_ASSERT_QI_SET", "QI set mismatch");
        require(definition.getQuasiIdentifiersWithGeneralization().equals(expectedQiSet),
                "CFG_ASSERT_QI_GENERALIZATION_SET",
                "generalized QI set mismatch");
        require(definition.getQuasiIdentifiersWithMicroaggregation().isEmpty(),
                "CFG_ASSERT_MICROAGGREGATION", "microaggregation is configured");
        require(definition.getQuasiIdentifiersWithClusteringAndMicroaggregation().isEmpty(),
                "CFG_ASSERT_MICROAGGREGATION_CLUSTERING",
                "clustering with microaggregation is configured");
        require(definition.getIdentifyingAttributes().isEmpty(),
                "CFG_ASSERT_IDENTIFYING_SET", "identifying attribute set is not empty");
        require(definition.getResponseVariables().isEmpty(),
                "CFG_ASSERT_RESPONSE_VARIABLES", "response-variable set is not empty");
        record(passed, "CFG_ASSERT_QI_SET");
        record(passed, "CFG_ASSERT_QI_GENERALIZATION_SET");
        record(passed, "CFG_ASSERT_MICROAGGREGATION");
        record(passed, "CFG_ASSERT_IDENTIFYING_SET");
        record(passed, "CFG_ASSERT_RESPONSE_VARIABLES");

        require(expectedHierarchies != null &&
                expectedHierarchies.keySet().equals(expectedQiSet),
                "CFG_ASSERT_EXPECTED_HIERARCHY_SET",
                "expected hierarchy set mismatch");
        int transformations = 1;
        for (String qi : QI_ORDER) {
            String[][] expected = expectedHierarchies.get(qi);
            String[][] actual = definition.getHierarchy(qi);
            require(expected != null && actual != null,
                    "CFG_ASSERT_HIERARCHY_PRESENT", "hierarchy missing for " + qi);
            require(Arrays.deepEquals(expected, actual),
                    "CFG_ASSERT_HIERARCHY_CONTENT", "hierarchy content mismatch for " + qi);
            require(definition.getHierarchyBuilder(qi) == null,
                    "CFG_ASSERT_HIERARCHY_BUILDER", "hierarchy builder present for " + qi);
            require(definition.getMinimumGeneralization(qi) == 0,
                    "CFG_ASSERT_HIERARCHY_MIN", "minimum generalization mismatch for " + qi);
            int maximum = MAX_GENERALIZATION.get(qi).intValue();
            require(definition.getMaximumGeneralization(qi) == maximum,
                    "CFG_ASSERT_HIERARCHY_MAX", "maximum generalization mismatch for " + qi);
            require(actual.length > 0, "CFG_ASSERT_HIERARCHY_SHAPE",
                    "empty hierarchy for " + qi);
            for (String[] row : actual) {
                require(row != null && row.length == maximum + 1,
                        "CFG_ASSERT_HIERARCHY_SHAPE",
                        "hierarchy height mismatch for " + qi);
            }
            transformations = Math.multiplyExact(transformations, maximum + 1);
        }
        require(transformations == 6480, "CFG_ASSERT_TRANSFORMATION_SPACE",
                "transformation space is not 6480");
        record(passed, "CFG_ASSERT_HIERARCHY_SET_CONTENT_BOUNDS");
        record(passed, "CFG_ASSERT_TRANSFORMATION_SPACE");

        require(!definition.getQuasiIdentifyingAttributes().contains(SALARY),
                "CFG_ASSERT_SALARY_NOT_QI", "salary-class is a QI");
        require(definition.getHierarchy(SALARY) == null &&
                definition.getHierarchyObject(SALARY) == null &&
                definition.getHierarchyBuilder(SALARY) == null,
                "CFG_ASSERT_SALARY_HIERARCHY", "salary-class has a hierarchy");
        require(definition.getMicroAggregationFunction(SALARY) == null,
                "CFG_ASSERT_SALARY_MICROAGGREGATION",
                "salary-class has a microaggregation function");
        require(definition.getAttributeType(SALARY) == spec.salaryAttributeType(),
                "CFG_ASSERT_SALARY_TYPE", "salary-class type mismatch");
        if (spec.family == Family.K_ONLY) {
            require(definition.getSensitiveAttributes().isEmpty(),
                    "CFG_ASSERT_SENSITIVE_SET", "k-only sensitive set is not empty");
            require(definition.getInsensitiveAttributes().equals(
                        Collections.singleton(SALARY)),
                    "CFG_ASSERT_INSENSITIVE_SET", "k-only insensitive set mismatch");
        } else {
            require(definition.getSensitiveAttributes().equals(
                        Collections.singleton(SALARY)),
                    "CFG_ASSERT_SENSITIVE_SET", "l/t sensitive set mismatch");
            require(definition.getInsensitiveAttributes().isEmpty(),
                    "CFG_ASSERT_INSENSITIVE_SET", "l/t insensitive set is not empty");
        }
        record(passed, "CFG_ASSERT_SALARY_NOT_QI");
        record(passed, "CFG_ASSERT_SALARY_NO_HIERARCHY_OR_MICROAGGREGATION");
        record(passed, "CFG_ASSERT_SALARY_TYPE_AND_ATTRIBUTE_SETS");

        require(configuration.getAlgorithm() == AnonymizationAlgorithm.OPTIMAL,
                "CFG_ASSERT_ALGORITHM", "algorithm is not OPTIMAL");
        require(configuration.getHeuristicSearchThreshold() == Integer.MAX_VALUE,
                "CFG_ASSERT_HEURISTIC_THRESHOLD", "heuristic threshold mismatch");
        require(!configuration.isPracticalMonotonicity(),
                "CFG_ASSERT_PRACTICAL_MONOTONICITY",
                "practical monotonicity is enabled");
        require(configuration.isSuppressionAlwaysEnabled(),
                "CFG_ASSERT_SUPPRESSION_ALWAYS", "suppression-always is disabled");
        require(bitsEqual(configuration.getSuppressionLimit(),
                          spec.suppressionLimit.doubleValue()),
                "CFG_ASSERT_SUPPRESSION_LIMIT", "suppression limit mismatch");
        require(configuration.isAttributeTypeSuppressed(
                    AttributeType.QUASI_IDENTIFYING_ATTRIBUTE),
                "CFG_ASSERT_SUPPRESSION_FLAG_QI", "QI suppression flag is false");
        require(!configuration.isAttributeTypeSuppressed(
                    AttributeType.SENSITIVE_ATTRIBUTE),
                "CFG_ASSERT_SUPPRESSION_FLAG_SENSITIVE",
                "sensitive suppression flag is true");
        require(!configuration.isAttributeTypeSuppressed(
                    AttributeType.INSENSITIVE_ATTRIBUTE),
                "CFG_ASSERT_SUPPRESSION_FLAG_INSENSITIVE",
                "insensitive suppression flag is true");
        require(!configuration.isAttributeTypeSuppressed(
                    AttributeType.IDENTIFYING_ATTRIBUTE),
                "CFG_ASSERT_SUPPRESSION_FLAG_IDENTIFYING",
                "identifying suppression flag is true");
        record(passed, "CFG_ASSERT_ALGORITHM_THRESHOLD_MONOTONICITY");
        record(passed, "CFG_ASSERT_SUPPRESSION_POLICY");

        assertPrivacyModels(spec, configuration, passed);
        assertMetricAndWeights(configuration, passed);

        return new AssertionReceipt(
            phase, spec, MANIFEST_BYTES, MANIFEST_SHA256,
            configurationFingerprint(spec), passed);
    }

    private static void assertPrivacyModels(CfgSpec spec,
                                             ARXConfiguration configuration,
                                             List<String> passed) {
        Set<PrivacyCriterion> criteria = configuration.getPrivacyModels();
        int expectedCount = spec.family == Family.K_ONLY ? 1 : 2;
        require(criteria.size() == expectedCount,
                "CFG_ASSERT_PRIVACY_MODEL_COUNT", "privacy-model count mismatch");

        KAnonymity observedK = null;
        DistinctLDiversity observedL = null;
        EqualDistanceTCloseness observedT = null;
        for (PrivacyCriterion criterion : criteria) {
            if (criterion.getClass().equals(KAnonymity.class)) {
                require(observedK == null, "CFG_ASSERT_K_COUNT",
                        "more than one exact KAnonymity");
                observedK = (KAnonymity) criterion;
            } else if (criterion.getClass().equals(DistinctLDiversity.class)) {
                require(observedL == null, "CFG_ASSERT_L_COUNT",
                        "more than one exact DistinctLDiversity");
                observedL = (DistinctLDiversity) criterion;
            } else if (criterion.getClass().equals(EqualDistanceTCloseness.class)) {
                require(observedT == null, "CFG_ASSERT_T_COUNT",
                        "more than one exact EqualDistanceTCloseness");
                observedT = (EqualDistanceTCloseness) criterion;
            } else {
                throw new CfgAssertionException(
                    "CFG_ASSERT_PRIVACY_MODEL_CLASS",
                    "unexpected privacy-model class: " + criterion.getClass().getName());
            }
        }

        require(observedK != null, "CFG_ASSERT_K_PRESENT", "KAnonymity missing");
        require(observedK.getK() == spec.k.intValue(),
                "CFG_ASSERT_K_VALUE", "KAnonymity k mismatch");
        if (spec.family == Family.K_ONLY) {
            require(observedL == null && observedT == null,
                    "CFG_ASSERT_K_ONLY_MODELS", "k-only configuration has l/t model");
        } else if (spec.family == Family.K_DISTINCT_L) {
            require(observedL != null && observedT == null,
                    "CFG_ASSERT_L_MODEL", "distinct-l model signature mismatch");
            assertExplicitAttribute(observedL, "CFG_ASSERT_L_ATTRIBUTE");
            require(bitsEqual(observedL.getL(), spec.l.doubleValue()),
                    "CFG_ASSERT_L_VALUE", "distinct-l value mismatch");
        } else if (spec.family == Family.K_EQUAL_DISTANCE_T) {
            require(observedT != null && observedL == null,
                    "CFG_ASSERT_T_MODEL", "equal-distance-t model signature mismatch");
            assertExplicitAttribute(observedT, "CFG_ASSERT_T_ATTRIBUTE");
            require(bitsEqual(observedT.getT(), spec.t.doubleValue()),
                    "CFG_ASSERT_T_VALUE", "equal-distance-t value mismatch");
        } else {
            throw new CfgAssertionException(
                "CFG_ASSERT_FAMILY", "raw-control family cannot be anonymized");
        }
        record(passed, "CFG_ASSERT_PRIVACY_MODEL_SET_CLASS_TARGET_VALUE");
    }

    private static void assertExplicitAttribute(ExplicitPrivacyCriterion criterion,
                                                String code) {
        require(SALARY.equals(criterion.getAttribute()), code,
                "explicit privacy criterion targets the wrong attribute");
    }

    private static void assertMetricAndWeights(ARXConfiguration configuration,
                                               List<String> passed) {
        Metric<?> metric = configuration.getQualityModel();
        require(metric != null, "CFG_ASSERT_METRIC_NULL", "quality metric is null");
        require(metric.getClass().equals(MetricMDNMLoss.class),
                "CFG_ASSERT_METRIC_CLASS", "quality metric class mismatch");
        require(metric.getAggregateFunction() == Metric.AggregateFunction.ARITHMETIC_MEAN,
                "CFG_ASSERT_METRIC_AGGREGATE", "metric aggregate mismatch");
        require(bitsEqual(metric.getGeneralizationSuppressionFactor(), 0.5d),
                "CFG_ASSERT_METRIC_GS_FACTOR", "metric gsFactor mismatch");
        MetricConfiguration details = metric.getConfiguration();
        require(details.getAggregateFunction() == Metric.AggregateFunction.ARITHMETIC_MEAN,
                "CFG_ASSERT_METRIC_CONFIGURATION_AGGREGATE",
                "metric configuration aggregate mismatch");
        require(bitsEqual(details.getGsFactor(), 0.5d),
                "CFG_ASSERT_METRIC_CONFIGURATION_GS_FACTOR",
                "metric configuration gsFactor mismatch");
        require(!details.isMonotonic(), "CFG_ASSERT_METRIC_MONOTONIC",
                "metric configuration is monotonic");
        require(!details.isPrecomputed(), "CFG_ASSERT_METRIC_PRECOMPUTED",
                "metric configuration is precomputed");
        require(bitsEqual(details.getPrecomputationThreshold(), +0.0d),
                "CFG_ASSERT_METRIC_PRECOMPUTATION_THRESHOLD",
                "metric precomputation threshold mismatch");

        Map<String, Double> weights = configuration.getAttributeWeights();
        require(weights.keySet().equals(new HashSet<String>(QI_ORDER)),
                "CFG_ASSERT_WEIGHT_KEY_SET", "attribute-weight key set mismatch");
        for (String qi : QI_ORDER) {
            Double value = weights.get(qi);
            require(value != null && bitsEqual(value.doubleValue(), 1.0d) &&
                    bitsEqual(configuration.getAttributeWeight(qi), 1.0d),
                    "CFG_ASSERT_WEIGHT_VALUE", "attribute weight mismatch for " + qi);
        }
        record(passed, "CFG_ASSERT_METRIC_EXACT");
        record(passed, "CFG_ASSERT_WEIGHT_SET_AND_VALUES");
    }

    private static String configurationFingerprint(CfgSpec spec) {
        if (spec.family == Family.RAW_CONTROL) {
            return spec.id + "|raw_control|arx=NOT_APPLICABLE";
        }
        return spec.id + "|" + spec.family.token + "|k=" + spec.value(spec.k) +
            "|l=" + spec.value(spec.l) + "|t=" + spec.doubleBits(spec.t) +
            "|s=" + bitsHex(spec.suppressionLimit.doubleValue()) +
            "|salary=" + spec.salaryTypeToken +
            "|models=" + spec.privacyModelSignature() +
            "|metric=MetricMDNMLoss:ARITHMETIC_MEAN:3fe0000000000000" +
            "|weights=8x3ff0000000000000|hierarchy_space=6480";
    }

    private static Map<String, String[][]> deepImmutableHierarchyCopy(
            Map<String, String[][]> source) {
        require(source != null, "CFG_ASSERT_EXPECTED_HIERARCHIES_NULL",
                "expected hierarchy map is null");
        LinkedHashMap<String, String[][]> copy =
            new LinkedHashMap<String, String[][]>();
        for (String qi : QI_ORDER) {
            String[][] hierarchy = source.get(qi);
            require(hierarchy != null, "CFG_ASSERT_EXPECTED_HIERARCHY_SET",
                    "expected hierarchy missing for " + qi);
            String[][] cloned = new String[hierarchy.length][];
            for (int row = 0; row < hierarchy.length; row++) {
                require(hierarchy[row] != null, "CFG_ASSERT_EXPECTED_HIERARCHY_SHAPE",
                        "null expected hierarchy row for " + qi);
                cloned[row] = hierarchy[row].clone();
            }
            copy.put(qi, cloned);
        }
        require(source.keySet().equals(new HashSet<String>(QI_ORDER)),
                "CFG_ASSERT_EXPECTED_HIERARCHY_SET",
                "expected hierarchy map has missing or extra keys");
        return Collections.unmodifiableMap(copy);
    }

    private static List<CfgSpec> catalog() {
        List<CfgSpec> result = new ArrayList<CfgSpec>();
        result.add(new CfgSpec("CFG00", Family.RAW_CONTROL, null, null, null,
                               null, null, "NOT_APPLICABLE"));
        result.add(spec("CFG01", Family.K_ONLY, 2, null, null, "0"));
        result.add(spec("CFG02", Family.K_ONLY, 5, null, null, "0"));
        result.add(spec("CFG03", Family.K_ONLY, 10, null, null, "0"));
        result.add(spec("CFG04", Family.K_ONLY, 20, null, null, "0"));
        result.add(spec("CFG05", Family.K_DISTINCT_L, 5, 2, null, "0"));
        result.add(spec("CFG06", Family.K_DISTINCT_L, 10, 2, null, "0"));
        result.add(spec("CFG07", Family.K_EQUAL_DISTANCE_T, 5, null, "0.20", "0"));
        result.add(spec("CFG08", Family.K_EQUAL_DISTANCE_T, 5, null, "0.10", "0"));
        result.add(spec("CFG09", Family.K_EQUAL_DISTANCE_T, 10, null, "0.20", "0"));
        result.add(spec("CFG10", Family.K_EQUAL_DISTANCE_T, 10, null, "0.10", "0"));
        result.add(spec("CFG11", Family.K_ONLY, 5, null, null, "0.05"));
        result.add(spec("CFG12", Family.K_ONLY, 10, null, null, "0.05"));
        result.add(spec("CFG13", Family.K_DISTINCT_L, 5, 2, null, "0.05"));
        result.add(spec("CFG14", Family.K_DISTINCT_L, 10, 2, null, "0.05"));
        result.add(spec("CFG15", Family.K_EQUAL_DISTANCE_T, 5, null, "0.10", "0.05"));
        result.add(spec("CFG16", Family.K_EQUAL_DISTANCE_T, 10, null, "0.10", "0.05"));
        return Collections.unmodifiableList(result);
    }

    private static CfgSpec spec(String id, Family family, int k, Integer l,
                                String tLexical, String suppressionLexical) {
        String salaryType = family == Family.K_ONLY
            ? "INSENSITIVE_ATTRIBUTE" : "SENSITIVE_ATTRIBUTE";
        Double t = tLexical == null ? null : Double.valueOf(tLexical);
        return new CfgSpec(id, family, Integer.valueOf(k), l, t,
                           tLexical, suppressionLexical, salaryType);
    }

    private static Map<String, CfgSpec> byId(List<CfgSpec> specs) {
        LinkedHashMap<String, CfgSpec> result = new LinkedHashMap<String, CfgSpec>();
        for (CfgSpec spec : specs) {
            require(result.put(spec.id, spec) == null,
                    "CFG_ASSERT_CATALOG_DUPLICATE", "duplicate catalog ID");
        }
        return Collections.unmodifiableMap(result);
    }

    private static void validateStaticCatalog() {
        require(CATALOG.size() == 17, "CFG_ASSERT_CATALOG_SIZE",
                "catalog must contain CFG00-CFG16");
        int kOnly = 0;
        int lFamily = 0;
        int tFamily = 0;
        int suppressed = 0;
        for (int index = 0; index < CATALOG.size(); index++) {
            CfgSpec spec = CATALOG.get(index);
            require(String.format(Locale.ROOT, "CFG%02d", Integer.valueOf(index)).equals(spec.id),
                    "CFG_ASSERT_CATALOG_ORDER", "catalog order mismatch");
            spec.validate();
            if (spec.family == Family.K_ONLY) {
                kOnly++;
            } else if (spec.family == Family.K_DISTINCT_L) {
                lFamily++;
            } else if (spec.family == Family.K_EQUAL_DISTANCE_T) {
                tFamily++;
            }
            if (spec.suppressionLimit != null &&
                bitsEqual(spec.suppressionLimit.doubleValue(), 0.05d)) {
                suppressed++;
            }
        }
        require(kOnly == 6 && lFamily == 4 && tFamily == 6 && suppressed == 6,
                "CFG_ASSERT_CATALOG_FAMILY_COUNTS", "catalog family counts mismatch");
    }

    private static String canonicalManifest() {
        StringBuilder result = new StringBuilder();
        result.append("config_id,family,k,l,t,t_distance,suppression_limit,")
              .append("arx_salary_attribute_type\n");
        for (CfgSpec spec : CATALOG) {
            result.append(spec.manifestLine()).append('\n');
        }
        return result.toString();
    }

    private static Map<String, Integer> buildMaximumGeneralizations() {
        LinkedHashMap<String, Integer> result = new LinkedHashMap<String, Integer>();
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

    private static boolean startsWithUtf8Bom(byte[] bytes) {
        return bytes.length >= 3 &&
            (bytes[0] & 0xff) == 0xef &&
            (bytes[1] & 0xff) == 0xbb &&
            (bytes[2] & 0xff) == 0xbf;
    }

    private static boolean bitsEqual(double first, double second) {
        return Double.doubleToLongBits(first) == Double.doubleToLongBits(second);
    }

    private static String bitsHex(double value) {
        return String.format(Locale.ROOT, "%016x",
                             Long.valueOf(Double.doubleToLongBits(value)));
    }

    private static String sha256(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(bytes);
            StringBuilder result = new StringBuilder(64);
            for (byte value : hash) {
                result.append(String.format(Locale.ROOT, "%02x",
                                            Integer.valueOf(value & 0xff)));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
    }

    private static void record(List<String> passed, String code) {
        passed.add(code);
    }

    private static void require(boolean condition, String code, String message) {
        if (!condition) {
            throw new CfgAssertionException(code, message);
        }
    }

    private static List<String> immutable(String... values) {
        return Collections.unmodifiableList(Arrays.asList(values.clone()));
    }

    public enum Family {
        RAW_CONTROL("raw_control"),
        K_ONLY("k_only"),
        K_DISTINCT_L("k_distinct_l"),
        K_EQUAL_DISTANCE_T("k_equal_distance_t");

        private final String token;

        Family(String token) {
            this.token = token;
        }

        public String token() {
            return token;
        }
    }


    public static final class CfgSpec {
        private final String id;
        private final Family family;
        private final Integer k;
        private final Integer l;
        private final Double t;
        private final String tLexical;
        private final Double suppressionLimit;
        private final String suppressionLexical;
        private final String salaryTypeToken;

        private CfgSpec(String id, Family family, Integer k, Integer l,
                        Double t, String tLexical, String suppressionLexical,
                        String salaryTypeToken) {
            this.id = id;
            this.family = family;
            this.k = k;
            this.l = l;
            this.t = t;
            this.tLexical = tLexical;
            this.suppressionLexical = suppressionLexical;
            this.suppressionLimit = suppressionLexical == null
                ? null : Double.valueOf(suppressionLexical);
            this.salaryTypeToken = salaryTypeToken;
        }

        private void validate() {
            if (family == Family.RAW_CONTROL) {
                require(k == null && l == null && t == null && suppressionLimit == null &&
                        "NOT_APPLICABLE".equals(salaryTypeToken),
                        "CFG_ASSERT_RAW_SPEC", "invalid CFG00 specification");
                return;
            }
            require(k != null && suppressionLimit != null,
                    "CFG_ASSERT_SPEC_REQUIRED", "missing k or suppression");
            require(bitsEqual(suppressionLimit.doubleValue(), +0.0d) ||
                    bitsEqual(suppressionLimit.doubleValue(), 0.05d),
                    "CFG_ASSERT_SPEC_SUPPRESSION", "invalid suppression value");
            if (family == Family.K_ONLY) {
                require(l == null && t == null &&
                        "INSENSITIVE_ATTRIBUTE".equals(salaryTypeToken),
                        "CFG_ASSERT_SPEC_K_ONLY", "invalid k-only specification");
            } else if (family == Family.K_DISTINCT_L) {
                require(Integer.valueOf(2).equals(l) && t == null &&
                        "SENSITIVE_ATTRIBUTE".equals(salaryTypeToken),
                        "CFG_ASSERT_SPEC_L", "invalid distinct-l specification");
            } else if (family == Family.K_EQUAL_DISTANCE_T) {
                require(l == null && t != null &&
                        (bitsEqual(t.doubleValue(), 0.10d) ||
                         bitsEqual(t.doubleValue(), 0.20d)) &&
                        "SENSITIVE_ATTRIBUTE".equals(salaryTypeToken),
                        "CFG_ASSERT_SPEC_T", "invalid equal-distance-t specification");
            }
        }

        public String id() {
            return id;
        }

        public Family family() {
            return family;
        }

        public Integer k() {
            return k;
        }

        public Integer l() {
            return l;
        }

        public Double t() {
            return t;
        }

        public Double suppressionLimit() {
            return suppressionLimit;
        }

        public String salaryTypeToken() {
            return salaryTypeToken;
        }

        public String privacyModelSignature() {
            if (family == Family.RAW_CONTROL) {
                return "none";
            }
            String result = "KAnonymity(" + k + ")";
            if (family == Family.K_DISTINCT_L) {
                result += "+DistinctLDiversity(salary-class," + l + ")";
            } else if (family == Family.K_EQUAL_DISTANCE_T) {
                result += "+EqualDistanceTCloseness(salary-class," + tLexical + ")";
            }
            return result;
        }

        public String fingerprint() {
            return configurationFingerprint(this);
        }

        private AttributeType salaryAttributeType() {
            if (family == Family.K_ONLY) {
                return AttributeType.INSENSITIVE_ATTRIBUTE;
            }
            if (family == Family.K_DISTINCT_L ||
                family == Family.K_EQUAL_DISTANCE_T) {
                return AttributeType.SENSITIVE_ATTRIBUTE;
            }
            throw new CfgAssertionException(
                "CFG_ASSERT_RAW_BUILD", "CFG00 cannot be built for anonymization");
        }

        private String manifestLine() {
            String distance = family == Family.K_EQUAL_DISTANCE_T
                ? "equal_distance" : "null";
            return id + "," + family.token + "," + value(k) + "," + value(l) +
                "," + (tLexical == null ? "null" : tLexical) + "," + distance +
                "," + (suppressionLexical == null ? "null" : suppressionLexical) +
                "," + salaryTypeToken;
        }

        private String value(Integer value) {
            return value == null ? "null" : value.toString();
        }

        private String doubleBits(Double value) {
            return value == null ? "null" : bitsHex(value.doubleValue());
        }
    }


    public static final class AssertionReceipt {
        private final String phase;
        private final CfgSpec spec;
        private final long manifestBytes;
        private final String manifestSha256;
        private final String fingerprint;
        private final List<String> passedAssertions;

        private AssertionReceipt(String phase, CfgSpec spec, long manifestBytes,
                                 String manifestSha256, String fingerprint,
                                 List<String> passedAssertions) {
            this.phase = phase;
            this.spec = spec;
            this.manifestBytes = manifestBytes;
            this.manifestSha256 = manifestSha256;
            this.fingerprint = fingerprint;
            this.passedAssertions = Collections.unmodifiableList(
                new ArrayList<String>(passedAssertions));
        }

        public String phase() {
            return phase;
        }

        public CfgSpec specification() {
            return spec;
        }

        public long manifestBytes() {
            return manifestBytes;
        }

        public String manifestSha256() {
            return manifestSha256;
        }

        public String fingerprint() {
            return fingerprint;
        }

        public List<String> passedAssertions() {
            return passedAssertions;
        }

        public boolean allPassed() {
            return true;
        }

        public boolean contains(String code) {
            return passedAssertions.contains(code);
        }
    }


    public static final class PreparedConfiguration {
        private final ArxConfigurationMatrix matrix;
        private final CfgSpec spec;
        private final Data data;
        private final DataDefinition definition;
        private final ARXConfiguration configuration;
        private final Map<String, String[][]> expectedHierarchies;
        private final AssertionReceipt preparationReceipt;
        private AssertionReceipt immediateReceipt;
        private ARXResult successfulResult;
        private boolean attempted;

        private PreparedConfiguration(ArxConfigurationMatrix matrix,
                                      CfgSpec spec,
                                      Data data,
                                      DataDefinition definition,
                                      ARXConfiguration configuration,
                                      Map<String, String[][]> expectedHierarchies,
                                      AssertionReceipt preparationReceipt) {
            this.matrix = matrix;
            this.spec = spec;
            this.data = data;
            this.definition = definition;
            this.configuration = configuration;
            this.expectedHierarchies = expectedHierarchies;
            this.preparationReceipt = preparationReceipt;
        }

        public synchronized ARXResult anonymizeOnce() throws IOException {
            require(!attempted, "CFG_ASSERT_ANONYMIZE_REUSE",
                    "prepared configuration has already been consumed");
            attempted = true;
            immediateReceipt = matrix.assertConfiguration(
                spec, data.getHandle(), definition, configuration,
                expectedHierarchies, "immediate_pre_anonymization");
            ANONYMIZATION_INVOCATIONS.incrementAndGet();
            ARXAnonymizer anonymizer = new ARXAnonymizer();
            ARXResult result = anonymizer.anonymize(data, configuration);
            successfulResult = result;
            return result;
        }

        private synchronized void assertEffectiveInputs(
                ARXConfiguration observedConfiguration,
                DataDefinition observedDefinition) {
            require(successfulResult != null,
                    "CFG_ASSERT_EFFECTIVE_NOT_COMPLETED",
                    "effective state requested before successful anonymization");
            require(observedConfiguration == successfulResult.getConfiguration(),
                    "CFG_ASSERT_EFFECTIVE_CONFIGURATION_IDENTITY",
                    "effective configuration is not the result-owned object");
            require(observedDefinition == successfulResult.getDataDefinition(),
                    "CFG_ASSERT_EFFECTIVE_DEFINITION_IDENTITY",
                    "effective definition is not the result-owned object");
        }

        public CfgSpec specification() {
            return spec;
        }

        public AssertionReceipt preparationReceipt() {
            return preparationReceipt;
        }

        public synchronized AssertionReceipt immediateReceipt() {
            require(immediateReceipt != null, "CFG_ASSERT_IMMEDIATE_RECEIPT",
                    "immediate pre-anonymization receipt is unavailable");
            return immediateReceipt;
        }

        Data dataForTests() {
            return data;
        }

        DataDefinition definitionForTests() {
            return definition;
        }

        ARXConfiguration configurationForTests() {
            return configuration;
        }
    }


    public static final class CfgAssertionException extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        private final String code;

        CfgAssertionException(String code, String message) {
            super(code + ": " + message);
            this.code = code;
        }

        CfgAssertionException(String code, String message, Throwable cause) {
            super(code + ": " + message, cause);
            this.code = code;
        }

        public String code() {
            return code;
        }
    }
}
