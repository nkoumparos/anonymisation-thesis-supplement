package org.nkoum.anonymisation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.deidentifier.arx.ARXAnonymizer;
import org.deidentifier.arx.ARXConfiguration;
import org.deidentifier.arx.ARXLattice;
import org.deidentifier.arx.ARXLattice.ARXNode;
import org.deidentifier.arx.ARXResult;
import org.deidentifier.arx.AttributeType.Hierarchy;
import org.deidentifier.arx.Data;
import org.deidentifier.arx.DataDefinition;
import org.deidentifier.arx.DataHandle;
import org.deidentifier.arx.metric.InformationLoss;
import org.deidentifier.arx.metric.Metric;
import org.deidentifier.arx.metric.v2.AbstractILMultiDimensional;
import org.deidentifier.arx.metric.v2.ILMultiDimensionalArithmeticMean;
import org.deidentifier.arx.metric.v2.MetricMDNMLoss;


public final class ArxExperimentRunner {

    private static final String REPORT_SCHEMA = "arx-main-cfg-v1.2.4/1.0";
    private static final int EXPECTED_ROWS = 30162;
    private static final int EXPECTED_LOW = 22654;
    private static final int EXPECTED_HIGH = 7508;
    private static final String LOW_LABEL = "<=50K";
    private static final String HIGH_LABEL = ">50K";
    private static final char DELIMITER = ';';
    private static final char QUOTE = '"';
    private static final char ESCAPE = '"';
    private static final char[] LINEBREAK = new char[] {'\n'};

    private static final String RAW_ROOT =
        "data/raw/arx-adult/4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f";
    private static final String JAR_RELATIVE = "vendor/arx-3.9.2/libarx-3.9.2.jar";

    private static final List<String> PHYSICAL = immutable(
        "sex", "age", "race", "marital-status", "education",
        "native-country", "workclass", "occupation", "salary-class");
    private static final List<String> QIS = immutable(
        "age", "sex", "race", "marital-status", "education",
        "native-country", "workclass", "occupation");
    private static final List<String> EXPECTED_DIMENSION_ORDER = immutable(
        "sex", "age", "race", "marital-status", "education",
        "native-country", "workclass", "occupation");

    private static final FileSpec ARX_JAR = new FileSpec(
        JAR_RELATIVE, 36161310L,
        "18040108e95ca7955d806bf32354b20601d664495653b8ee169d249f43f58d44");
    private static final FileSpec INPUT = new FileSpec(
        RAW_ROOT + "/adult.csv", 2516935L,
        "c700df9304fbf3c4d4db5938bffc510561bd4a2dfad285a3feef9a20619391c5");
    private static final FileSpec CONFIGURATIONS = new FileSpec(
        "configurations.csv", 1150L,
        "ae28a3ac91dd733c5561a6f4d887c48d4b792915531d72a5e2158bc0bce72d2e");
    private static final FileSpec EFFECTIVE_PROTOCOL = new FileSpec(
        "manifest/protocol_effective_v1_2_4.txt", 7203L,
        "77ef91e9691eef8f271598b357f27f14650b52ea0f9bb6ebe5c1f4a0e4fd78e5");

    private static final List<HierarchySpec> HIERARCHIES = Collections.unmodifiableList(
        Arrays.asList(
            new HierarchySpec("sex", RAW_ROOT + "/adult_hierarchy_sex.csv", 16L,
                "537d23f7b6969b916b5a5490eb1b32c273fefdc62ca050a7a813e23bbf3b78b2", 1),
            new HierarchySpec("age", "data/derived/hierarchies/adult_hierarchy_age_semantic.csv", 2282L,
                "de2a5bdc9b0ad72a31ca8199e7be5d39346646da604bf1fb8954afc7626e0ba5", 4),
            new HierarchySpec("race", RAW_ROOT + "/adult_hierarchy_race.csv", 66L,
                "df11abf41fa0669455adc9c9f9fa88663afa0cee8327684ecca861cd32dc4209", 1),
            new HierarchySpec("marital-status", RAW_ROOT + "/adult_hierarchy_marital-status.csv", 239L,
                "3e7ba2c4a5cd4fec059b4e3a2c57fce6e7c34a20daee1e624990ddd7beba85e5", 2),
            new HierarchySpec("education", RAW_ROOT + "/adult_hierarchy_education.csv", 692L,
                "f22e5ee519c28b05538d4e5ddea0fbee5f0017fefb3abab3fa02272325bf9ce5", 3),
            new HierarchySpec("native-country", RAW_ROOT + "/adult_hierarchy_native-country.csv", 840L,
                "696d3b53973311c096b33f98bb56e526016910b1a1cd5a1e904cb799d1077023", 2),
            new HierarchySpec("workclass", RAW_ROOT + "/adult_hierarchy_workclass.csv", 211L,
                "106f420349bf0071dbb25371795a78799edf24a64c3424619d563c3990ee8d02", 2),
            new HierarchySpec("occupation", RAW_ROOT + "/adult_hierarchy_occupation.csv", 353L,
                "16dc420d5d7f8ab4d1e6144eb1d19ab8314ef42523fe8c4ee202372db1c98126", 2)
        ));

    private ArxExperimentRunner() { }

    public static void main(String[] args) {
        try {
            Arguments arguments = Arguments.parse(args);
            Outcome outcome = execute(arguments);
            System.out.println("RESULT=" + (arguments.mode.equals("preflight")
                    ? "ARX_MAIN_CFG_PREFLIGHT_PASS" : "ARX_MAIN_CFG_RUN_PASS"));
            System.out.println("CONFIG_ID=" + arguments.configId);
            System.out.println("REPORT=" + outcome.report);
            System.out.println("REPORT_BYTES=" + outcome.reportBytes);
            System.out.println("REPORT_SHA256=" + outcome.reportSha256);
            if (outcome.output != null) {
                System.out.println("FULL_OUTPUT=" + outcome.output);
                System.out.println("FULL_OUTPUT_BYTES=" + outcome.outputBytes);
                System.out.println("FULL_OUTPUT_SHA256=" + outcome.outputSha256);
            }
        } catch (Throwable error) {
            String message = error.getMessage() == null ? "no detail" : error.getMessage();
            System.err.println("RESULT=ARX_MAIN_CFG_FAIL");
            System.err.println("ERROR_CLASS=" + error.getClass().getName());
            System.err.println("ERROR=" + sanitize(message));
            System.exit(1);
        }
    }

    private static Outcome execute(Arguments arguments) throws Exception {
        final Instant startedAt = Instant.now();
        final long startedNanos = System.nanoTime();
        verifyFile(arguments.repoRoot, ARX_JAR);
        verifyFile(arguments.repoRoot, INPUT);
        verifyFile(arguments.repoRoot, CONFIGURATIONS);
        verifyFile(arguments.repoRoot, EFFECTIVE_PROTOCOL);
        verifyLoadedArxJar(arguments.repoRoot.resolve(JAR_RELATIVE));

        List<ResolvedHierarchy> resolved = new ArrayList<ResolvedHierarchy>();
        for (HierarchySpec spec : HIERARCHIES) {
            verifyFile(arguments.repoRoot, spec);
            String[][] table = readStrictHierarchy(
                arguments.repoRoot.resolve(spec.relativePath), spec.maximum + 1);
            resolved.add(new ResolvedHierarchy(spec, table));
        }
        validateHierarchySet(resolved);

        Data data = Data.create(arguments.repoRoot.resolve(INPUT.relativePath).toFile(),
                                StandardCharsets.UTF_8, DELIMITER, QUOTE, ESCAPE,
                                LINEBREAK.clone());
        DataHandle input = data.getHandle();
        assertSchema(input, PHYSICAL, "input");
        check(input.getNumRows() == EXPECTED_ROWS, "MAIN_INPUT_ROW_COUNT");
        List<String[]> sourceRows = snapshot(input);
        assertSalary(sourceRows, "MAIN_INPUT_TARGET_COUNTS");

        DataDefinition definition = data.getDefinition();
        Map<String, String[][]> expectedHierarchies = new LinkedHashMap<String, String[][]>();
        Map<String, Map<String, String[]>> hierarchyIndex =
            new LinkedHashMap<String, Map<String, String[]>>();
        for (ResolvedHierarchy item : resolved) {
            Hierarchy hierarchy = Hierarchy.create(
                arguments.repoRoot.resolve(item.spec.relativePath).toFile(),
                StandardCharsets.UTF_8, DELIMITER, QUOTE, ESCAPE, LINEBREAK.clone());
            definition.setAttributeType(item.spec.qi, hierarchy);
            definition.setMinimumGeneralization(item.spec.qi, 0);
            definition.setMaximumGeneralization(item.spec.qi, item.spec.maximum);
            check(expectedHierarchies.put(item.spec.qi, copy(item.table)) == null,
                  "MAIN_DUPLICATE_HIERARCHY");
            hierarchyIndex.put(item.spec.qi, index(item.table));
        }

        ArxConfigurationMatrix matrix = ArxConfigurationMatrix.load(
            arguments.repoRoot.resolve(CONFIGURATIONS.relativePath));
        ArxConfigurationMatrix.PreparedConfiguration prepared =
            matrix.prepare(arguments.configId, data, expectedHierarchies);
        ArxConfigurationMatrix.CfgSpec specification = prepared.specification();
        ArxConfigurationMatrix.AssertionReceipt preparation = prepared.preparationReceipt();

        Files.createDirectories(arguments.runDir);
        check(Files.isDirectory(arguments.runDir), "MAIN_RUN_DIR_CREATE");
        if (arguments.mode.equals("preflight")) {
            LinkedHashMap<String, Object> report = baseReport(arguments, specification);
            report.put("result", "PASS");
            report.put("phase", "preflight_before_anonymization");
            report.put("preparation_receipt", receipt(preparation));
            report.put("anonymization_invoked", Boolean.FALSE);
            report.put("main_runs_authorized", Boolean.FALSE);
            report.put("main_runs_executed", Boolean.FALSE);
            report.put("output_written", Boolean.FALSE);
            addTelemetry(report, "arx_preflight_before_anonymization",
                         startedAt, startedNanos, EXPECTED_ROWS, 0, 0);
            Path path = arguments.runDir.resolve(arguments.configId + ".preflight.json");
            byte[] bytes = jsonBytes(report);
            writeNew(path, bytes);
            return new Outcome(path, bytes, null, null);
        }

        Authorization authorization = Authorization.load(arguments.authorizationRecord,
                                                          arguments.configId);
        ARXResult result = prepared.anonymizeOnce();
        ArxConfigurationMatrix.AssertionReceipt immediate = prepared.immediateReceipt();
        check(result != null && result.isResultAvailable(), "MAIN_RESULT_AVAILABLE");
        check(result.getOptimumFound(), "MAIN_OPTIMUM_FOUND");
        ARXNode node = result.getGlobalOptimum();
        check(node != null && node.isChecked(), "MAIN_NODE_CHECKED");
        check(node.getAnonymity() == ARXLattice.Anonymity.ANONYMOUS,
              "MAIN_NODE_ANONYMOUS");
        ArxConfigurationMatrix.AssertionReceipt effective = matrix.assertEffective(
            prepared, result.getConfiguration(), result.getDataDefinition());

        String[] dimensionArray = node.getQuasiIdentifyingAttributes().clone();
        check(Arrays.equals(dimensionArray,
              EXPECTED_DIMENSION_ORDER.toArray(new String[0])), "MAIN_DIMENSION_ORDER");
        int[] rawTransformation = node.getTransformation().clone();
        Map<String, Integer> transformation = namedTransformation(node, dimensionArray,
                                                                  rawTransformation);
        LossEvidence loss = loss(node, result.getConfiguration(), dimensionArray);

        DataHandle output = result.getOutput(node, false);
        check(output != null && !output.isOptimized(), "MAIN_NO_LOCAL_RECODING");
        assertSchema(output, PHYSICAL, "output");
        check(output.getNumRows() == EXPECTED_ROWS, "MAIN_OUTPUT_ROW_COUNT");

        List<String[]> outputRows = new ArrayList<String[]>(EXPECTED_ROWS);
        List<Boolean> mask = new ArrayList<Boolean>(EXPECTED_ROWS);
        int outliers = 0;
        for (int rowIndex = 0; rowIndex < EXPECTED_ROWS; rowIndex++) {
            boolean outlier = output.isOutlier(rowIndex);
            String[] observed = handleRow(output, rowIndex);
            String[] source = sourceRows.get(rowIndex);
            check(observed[8].equals(source[8]), "MAIN_TARGET_INDEX_BINDING");
            if (!outlier) {
                String[] expected = transform(source, transformation, hierarchyIndex);
                check(Arrays.equals(observed, expected), "MAIN_RETAINED_TRANSFORMATION_BINDING");
            } else {
                outliers++;
            }
            outputRows.add(observed);
            mask.add(Boolean.valueOf(outlier));
        }
        int budget = specification.suppressionLimit().doubleValue() == 0.0d
            ? 0 : EXPECTED_ROWS / 20;
        check(outliers <= budget, "MAIN_SUPPRESSION_BUDGET");
        check(rowsEqual(snapshot(input), sourceRows), "MAIN_INPUT_BEFORE_AFTER_BINDING");
        check(node == result.getGlobalOptimum(), "MAIN_NODE_IDENTITY_STABILITY");
        check(Arrays.equals(rawTransformation, node.getTransformation()),
              "MAIN_TRANSFORMATION_STABILITY");

        byte[] outputBytes = serialize(outputRows);
        String outputName = arguments.configId + ".full.tsv";
        Path outputPath = arguments.runDir.resolve(outputName);
        LinkedHashMap<String, Object> report = baseReport(arguments, specification);
        report.put("result", "PASS");
        report.put("phase", "one_cfg_anonymization_complete_before_gate_b");
        report.put("authorization", authorization.report());
        report.put("preparation_receipt", receipt(preparation));
        report.put("immediate_receipt", receipt(immediate));
        report.put("effective_receipt", receipt(effective));
        report.put("actual_arx_dimension_order", new ArrayList<String>(Arrays.asList(dimensionArray)));
        report.put("raw_transformation", integers(rawTransformation));
        report.put("transformation_by_name", transformation);
        report.put("loss", loss.report());
        report.put("full_output", artifact(outputName, outputBytes));
        report.put("outlier_mask", ArxTransformationCapture.map(
            "source", "DataHandle.isOutlier", "values", mask,
            "count", Integer.valueOf(outliers)));
        report.put("input_before_after_equal", Boolean.TRUE);
        report.put("retained_transformation_equality", Boolean.TRUE);
        report.put("target_index_binding", Boolean.TRUE);
        report.put("no_sort_or_permutation", Boolean.TRUE);
        report.put("no_local_recoding", Boolean.TRUE);
        report.put("anonymization_invoked", Boolean.TRUE);
        report.put("main_runs_authorized", Boolean.TRUE);
        report.put("main_runs_executed", Boolean.TRUE);
        report.put("gate_b_status", "pending_independent_validator");
        addTelemetry(report, "arx_anonymization_and_result_capture",
                     startedAt, startedNanos, EXPECTED_ROWS,
                     EXPECTED_ROWS, EXPECTED_ROWS - outliers);
        Path reportPath = arguments.runDir.resolve(arguments.configId + ".java-report.json");
        byte[] reportBytes = jsonBytes(report);

        preflightNew(outputPath);
        preflightNew(reportPath);
        writeNew(outputPath, outputBytes);
        writeNew(reportPath, reportBytes);
        return new Outcome(reportPath, reportBytes, outputPath, outputBytes);
    }

    private static LinkedHashMap<String, Object> baseReport(
            Arguments args, ArxConfigurationMatrix.CfgSpec spec) throws Exception {
        LinkedHashMap<String, Object> report = object();
        report.put("record_schema", REPORT_SCHEMA);
        report.put("config_id", args.configId);
        report.put("mode", args.mode);
        report.put("effective_protocol", "v1.2.4");
        report.put("configuration", ArxTransformationCapture.map(
            "family", spec.family().toString(), "k", spec.k(), "l", spec.l(),
            "t", spec.t() == null ? null : spec.t().toString(),
            "suppression_limit", spec.suppressionLimit().toString(),
            "salary_attribute_type", spec.salaryTypeToken()));
        report.put("pinned_inputs", pinnedInputs());
        report.put("input_rows", Integer.valueOf(EXPECTED_ROWS));
        report.put("input_target_counts", ArxTransformationCapture.map(
            LOW_LABEL, Integer.valueOf(EXPECTED_LOW), HIGH_LABEL, Integer.valueOf(EXPECTED_HIGH)));
        report.put("runtime", ArxTransformationCapture.map(
            "java_version", safeProperty("java.version"),
            "java_vm_name", safeProperty("java.vm.name"),
            "os_name", safeProperty("os.name"), "os_arch", safeProperty("os.arch"),
            "arx_code_source", ARXAnonymizer.class.getProtectionDomain()
                .getCodeSource().getLocation().toExternalForm()));
        report.put("rng_instantiated", Boolean.FALSE);
        report.put("model_fits_executed", Boolean.FALSE);
        return report;
    }

    private static void addTelemetry(LinkedHashMap<String, Object> report,
            String stage, Instant startedAt, long startedNanos,
            int inputRecords, int resultOwnedRows, int retainedRows) {
        Instant completedAt = Instant.now();
        double seconds = (System.nanoTime() - startedNanos) / 1_000_000_000d;
        check(Double.isFinite(seconds) && seconds >= 0d, "MAIN_TELEMETRY_DURATION");
        report.put("telemetry", ArxTransformationCapture.map(
            "stage", stage,
            "status", "PASS",
            "started_at_utc", startedAt.toString(),
            "completed_at_utc", completedAt.toString(),
            "wall_clock_seconds", Double.toString(seconds),
            "input_records", Integer.valueOf(inputRecords),
            "result_owned_rows", Integer.valueOf(resultOwnedRows),
            "retained_rows", Integer.valueOf(retainedRows),
            "peak_resident_memory_bytes", null,
            "peak_resident_memory_available", Boolean.FALSE,
            "peak_resident_memory_note", "not exposed by the pinned Java standard-library path"));
    }

    private static List<Object> pinnedInputs() {
        List<Object> result = new ArrayList<Object>();
        result.add(INPUT.report("training_input"));
        result.add(CONFIGURATIONS.report("configuration_manifest"));
        result.add(EFFECTIVE_PROTOCOL.report("effective_protocol_manifest"));
        result.add(ARX_JAR.report("arx_jar"));
        for (HierarchySpec item : HIERARCHIES) result.add(item.report("hierarchy:" + item.qi));
        return result;
    }

    private static Map<String, Object> receipt(ArxConfigurationMatrix.AssertionReceipt value) {
        check(value != null && value.allPassed(), "MAIN_MATRIX_RECEIPT");
        return ArxTransformationCapture.map(
            "phase", value.phase(), "config_id", value.specification().id(),
            "manifest_bytes", Long.valueOf(value.manifestBytes()),
            "manifest_sha256", value.manifestSha256(),
            "fingerprint", value.fingerprint(),
            "passed_assertions", new ArrayList<String>(value.passedAssertions()),
            "all_passed", Boolean.TRUE);
    }

    private static Map<String, Integer> namedTransformation(
            ARXNode node, String[] dimensions, int[] vector) {
        check(dimensions.length == 8 && vector.length == 8, "MAIN_TRANSFORMATION_LENGTH");
        LinkedHashMap<String, Integer> result = new LinkedHashMap<String, Integer>();
        Set<Integer> used = new HashSet<Integer>();
        for (String qi : QIS) {
            int index = node.getDimension(qi);
            check(index >= 0 && index < 8 && used.add(Integer.valueOf(index)),
                  "MAIN_DIMENSION_BIJECTION");
            check(dimensions[index].equals(qi), "MAIN_DIMENSION_REVERSE");
            int level = vector[index];
            check(level == node.getGeneralization(qi), "MAIN_NAMED_TRANSFORMATION");
            check(level >= 0 && level <= ArxConfigurationMatrix.maximumGeneralizations().get(qi),
                  "MAIN_TRANSFORMATION_BOUNDS");
            result.put(qi, Integer.valueOf(level));
        }
        return Collections.unmodifiableMap(result);
    }

    private static LossEvidence loss(ARXNode node, ARXConfiguration configuration,
                                     String[] dimensions) {
        InformationLoss<?> highest = node.getHighestScore();
        InformationLoss<?> lowest = node.getLowestScore();
        check(highest != null && lowest != null, "MAIN_LOSS_NULL");
        check(highest.getClass().equals(ILMultiDimensionalArithmeticMean.class)
              && lowest.getClass().equals(ILMultiDimensionalArithmeticMean.class),
              "MAIN_LOSS_CLASS");
        double[] high = values(highest);
        double[] low = values(lowest);
        assertBits(high, low, "MAIN_LOSS_HIGH_LOW_COMPONENTS");
        Metric<?> metric = configuration.getQualityModel();
        check(metric.getClass().equals(MetricMDNMLoss.class), "MAIN_LOSS_METRIC");
        InformationLoss<?> minimum = metric.createInstanceOfLowestScore();
        InformationLoss<?> maximum = metric.createInstanceOfHighestScore();
        double[] min = values(minimum);
        double[] max = values(maximum);
        double[] weights = new double[8];
        for (int index = 0; index < 8; index++) {
            check(bits(configuration.getAttributeWeight(dimensions[index]), 1.0d),
                  "MAIN_LOSS_WEIGHT");
            weights[index] = 1.0d;
            check(bits(min[index], +0.0d) && bits(max[index], 1.0d),
                  "MAIN_LOSS_BOUNDS");
        }
        double typedHigh = highest.relativeTo(minimum, maximum);
        double typedLow = lowest.relativeTo(minimum, maximum);
        double folded = aggregate(high, weights);
        check(finiteUnit(typedHigh) && finiteUnit(typedLow) && finiteUnit(folded),
              "MAIN_LOSS_DOMAIN");
        check(bits(typedHigh, typedLow) && bits(typedHigh, folded),
              "MAIN_LOSS_TOTAL_BINDING");
        LinkedHashMap<String, String> byName = new LinkedHashMap<String, String>();
        for (int index = 0; index < 8; index++)
            byName.put(dimensions[index], Double.toString(high[index]));
        return new LossEvidence(high, byName, typedHigh);
    }

    private static double[] values(InformationLoss<?> value) {
        check(value instanceof AbstractILMultiDimensional, "MAIN_LOSS_VALUE_TYPE");
        double[] result = ((AbstractILMultiDimensional)value).getValue().clone();
        check(result.length == 8, "MAIN_LOSS_COMPONENT_COUNT");
        for (double item : result) check(finiteUnit(item), "MAIN_LOSS_COMPONENT_DOMAIN");
        return result;
    }

    private static double aggregate(double[] values, double[] weights) {
        double result = 0d;
        for (int index = 0; index < values.length; index++)
            result += (values[index] / (double)values.length) * weights[index];
        return result;
    }

    private static String[] transform(String[] source, Map<String, Integer> levels,
            Map<String, Map<String, String[]>> tables) {
        String[] result = new String[PHYSICAL.size()];
        for (int column = 0; column < PHYSICAL.size(); column++) {
            String name = PHYSICAL.get(column);
            if (name.equals("salary-class")) {
                result[column] = source[column];
            } else {
                String[] path = tables.get(name).get(source[column]);
                check(path != null, "MAIN_HIERARCHY_SOURCE_COVERAGE");
                result[column] = path[levels.get(name).intValue()];
            }
        }
        return result;
    }

    private static Map<String, String[]> index(String[][] table) {
        LinkedHashMap<String, String[]> result = new LinkedHashMap<String, String[]>();
        for (String[] row : table)
            check(result.put(row[0], row.clone()) == null, "MAIN_HIERARCHY_DUPLICATE_LEAF");
        return Collections.unmodifiableMap(result);
    }

    private static void validateHierarchySet(List<ResolvedHierarchy> resolved) {
        Set<String> names = new HashSet<String>();
        int product = 1;
        for (ResolvedHierarchy item : resolved) {
            check(names.add(item.spec.qi), "MAIN_HIERARCHY_DUPLICATE_QI");
            check(item.table.length > 0, "MAIN_HIERARCHY_EMPTY");
            product *= item.spec.maximum + 1;
        }
        check(names.equals(new HashSet<String>(QIS)), "MAIN_HIERARCHY_QI_SET");
        check(product == 6480, "MAIN_TRANSFORMATION_SPACE");
    }

    private static String[][] readStrictHierarchy(Path path, int columns) throws IOException {
        byte[] bytes = Files.readAllBytes(path);
        String text = new String(bytes, StandardCharsets.UTF_8);
        check(Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8)), "MAIN_HIERARCHY_UTF8");
        check(!text.startsWith("\ufeff") && text.indexOf('\r') < 0,
              "MAIN_HIERARCHY_TEXT_FORM");
        String[] lines = text.split("\n", -1);
        int count = lines.length - (lines[lines.length - 1].isEmpty() ? 1 : 0);
        check(count > 0, "MAIN_HIERARCHY_EMPTY");
        String[][] result = new String[count][];
        for (int row = 0; row < count; row++) {
            String[] cells = lines[row].split(";", -1);
            check(cells.length == columns, "MAIN_HIERARCHY_WIDTH");
            for (String cell : cells) {
                check(cell.length() > 0 && cell.equals(cell.trim()) && cell.indexOf('"') < 0,
                      "MAIN_HIERARCHY_CELL");
                rejectControl(cell, "MAIN_HIERARCHY_CONTROL");
            }
            result[row] = cells;
        }
        return result;
    }

    private static List<String[]> snapshot(DataHandle handle) {
        List<String[]> result = new ArrayList<String[]>(handle.getNumRows());
        for (int row = 0; row < handle.getNumRows(); row++) result.add(handleRow(handle, row));
        return result;
    }

    private static boolean rowsEqual(List<String[]> first, List<String[]> second) {
        if (first.size() != second.size()) return false;
        for (int index = 0; index < first.size(); index++)
            if (!Arrays.equals(first.get(index), second.get(index))) return false;
        return true;
    }

    private static String[] handleRow(DataHandle handle, int row) {
        String[] result = new String[PHYSICAL.size()];
        for (int column = 0; column < result.length; column++) {
            String value = handle.getValue(row, column);
            check(value != null && value.length() > 0, "MAIN_OUTPUT_CELL");
            rejectControl(value, "MAIN_OUTPUT_CONTROL");
            result[column] = value;
        }
        return result;
    }

    private static void assertSchema(DataHandle handle, List<String> expected, String name) {
        check(handle.getNumColumns() == expected.size(), "MAIN_" + name.toUpperCase(Locale.ROOT) + "_COLUMN_COUNT");
        for (int column = 0; column < expected.size(); column++)
            check(expected.get(column).equals(handle.getAttributeName(column)),
                  "MAIN_" + name.toUpperCase(Locale.ROOT) + "_SCHEMA");
    }

    private static void assertSalary(List<String[]> rows, String code) {
        int low = 0, high = 0;
        for (String[] row : rows) {
            if (row[8].equals(LOW_LABEL)) low++;
            else if (row[8].equals(HIGH_LABEL)) high++;
            else check(false, code);
        }
        check(low == EXPECTED_LOW && high == EXPECTED_HIGH, code);
    }

    private static byte[] serialize(List<String[]> rows) {
        ByteArrayOutputStream output = new ByteArrayOutputStream(3000000);
        writeTsv(output, PHYSICAL.toArray(new String[0]));
        for (String[] row : rows) writeTsv(output, row);
        return output.toByteArray();
    }

    private static void writeTsv(ByteArrayOutputStream output, String[] row) {
        for (int column = 0; column < row.length; column++) {
            rejectControl(row[column], "MAIN_TSV_CONTROL");
            if (column > 0) output.write('\t');
            byte[] bytes = row[column].getBytes(StandardCharsets.UTF_8);
            output.write(bytes, 0, bytes.length);
        }
        output.write('\n');
    }

    private static Map<String, Object> artifact(String name, byte[] bytes) throws Exception {
        return ArxTransformationCapture.map(
            "filename", name, "bytes", Integer.valueOf(bytes.length), "sha256", sha256(bytes));
    }

    private static byte[] jsonBytes(Map<String, Object> value) {
        return (ArxTransformationCapture.json(value) + "\n")
            .getBytes(StandardCharsets.US_ASCII);
    }

    private static void verifyFile(Path root, FileSpec spec) throws Exception {
        Path path = root.resolve(spec.relativePath).normalize();
        check(path.startsWith(root) && Files.isRegularFile(path), "MAIN_REQUIRED_FILE");
        byte[] bytes = Files.readAllBytes(path);
        check(bytes.length == spec.bytes && sha256(bytes).equals(spec.sha256),
              "MAIN_FILE_IDENTITY:" + spec.relativePath);
    }

    private static void verifyLoadedArxJar(Path expectedJar) throws Exception {
        URI location = ARXAnonymizer.class.getProtectionDomain().getCodeSource().getLocation().toURI();
        Path loaded = Paths.get(location).toRealPath();
        check(Files.isSameFile(loaded, expectedJar.toRealPath()), "MAIN_ARX_CODE_SOURCE");
    }

    private static String sha256(byte[] bytes) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder result = new StringBuilder();
        for (byte value : digest)
            result.append(String.format(Locale.ROOT, "%02x", Integer.valueOf(value & 255)));
        return result.toString();
    }

    private static void preflightNew(Path path) throws IOException {
        check(!Files.exists(path), "MAIN_REFUSE_OVERWRITE:" + path.getFileName());
        Path temporary = path.resolveSibling(path.getFileName().toString() + ".tmp");
        check(!Files.exists(temporary), "MAIN_TEMP_EXISTS:" + temporary.getFileName());
    }

    private static void writeNew(Path path, byte[] bytes) throws IOException {
        preflightNew(path);
        Path temporary = path.resolveSibling(path.getFileName().toString() + ".tmp");
        Files.write(temporary, bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        try {
            Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException error) {
            Files.move(temporary, path);
        }
    }

    private static int[] physicalIndices(List<String> order) {
        int[] result = new int[order.size()];
        for (int index = 0; index < order.size(); index++) result[index] = PHYSICAL.indexOf(order.get(index));
        return result;
    }

    private static List<Integer> integers(int[] values) {
        List<Integer> result = new ArrayList<Integer>();
        for (int value : values) result.add(Integer.valueOf(value));
        return result;
    }

    private static String[][] copy(String[][] value) {
        String[][] result = new String[value.length][];
        for (int index = 0; index < value.length; index++) result[index] = value[index].clone();
        return result;
    }

    private static void assertBits(double[] first, double[] second, String code) {
        check(first.length == second.length, code);
        for (int index = 0; index < first.length; index++) check(bits(first[index], second[index]), code);
    }

    private static boolean bits(double first, double second) {
        return Double.doubleToLongBits(first) == Double.doubleToLongBits(second);
    }

    private static boolean finiteUnit(double value) {
        return Double.isFinite(value) && value >= 0.0d && value <= 1.0d;
    }

    private static void rejectControl(String value, String code) {
        check(value.indexOf('\0') < 0 && value.indexOf('\r') < 0
              && value.indexOf('\n') < 0 && value.indexOf('\t') < 0, code);
    }

    private static String sanitize(String value) {
        return value.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ');
    }

    private static String safeProperty(String name) {
        String value = System.getProperty(name);
        return value == null ? "UNAVAILABLE" : value;
    }

    private static LinkedHashMap<String, Object> object() {
        return new LinkedHashMap<String, Object>();
    }

    private static List<String> immutable(String... values) {
        return Collections.unmodifiableList(Arrays.asList(values));
    }

    private static void check(boolean condition, String code) {
        if (!condition) throw new IllegalStateException(code);
    }

    private static class FileSpec {
        final String relativePath;
        final long bytes;
        final String sha256;
        FileSpec(String relativePath, long bytes, String sha256) {
            this.relativePath = relativePath; this.bytes = bytes; this.sha256 = sha256;
        }
        Map<String, Object> report(String role) {
            return ArxTransformationCapture.map(
                "role", role, "relative_path", relativePath,
                "bytes", Long.valueOf(bytes), "sha256", sha256);
        }
    }

    private static final class HierarchySpec extends FileSpec {
        final String qi;
        final int maximum;
        HierarchySpec(String qi, String path, long bytes, String sha256, int maximum) {
            super(path, bytes, sha256); this.qi = qi; this.maximum = maximum;
        }
    }

    private static final class ResolvedHierarchy {
        final HierarchySpec spec;
        final String[][] table;
        ResolvedHierarchy(HierarchySpec spec, String[][] table) {
            this.spec = spec; this.table = table;
        }
    }

    private static final class LossEvidence {
        final double[] components;
        final Map<String, String> byName;
        final double total;
        LossEvidence(double[] components, Map<String, String> byName, double total) {
            this.components = components.clone(); this.byName = byName; this.total = total;
        }
        Map<String, Object> report() {
            List<Object> raw = new ArrayList<Object>();
            for (double value : components) raw.add(ArxTransformationCapture.map(
                "decimal", Double.toString(value), "float_hex", Double.toHexString(value)));
            LinkedHashMap<String, Object> named = object();
            for (Map.Entry<String, String> item : byName.entrySet()) named.put(item.getKey(), item.getValue());
            return ArxTransformationCapture.map(
                "components_in_actual_dimension_order", raw,
                "components_by_name_decimal", named,
                "loss_total_decimal", Double.toString(total),
                "loss_total_float_hex", Double.toHexString(total),
                "metric", "MetricMDNMLoss",
                "aggregation", "ILMultiDimensionalArithmeticMean");
        }
    }

    private static final class Authorization {
        private static final Set<String> KEYS = Collections.unmodifiableSet(new HashSet<String>(
            Arrays.asList("record_schema", "effective_protocol", "authorization_id",
                          "authorized_at_utc", "authorized_source_commit",
                          "authorized_configs", "authorized_by", "main_runs_authorized")));
        final Path path;
        final String sha256;
        final Map<String, String> values;
        Authorization(Path path, String sha256, Map<String, String> values) {
            this.path = path; this.sha256 = sha256; this.values = values;
        }
        static Authorization load(Path path, String cfg) throws Exception {
            check(path != null && Files.isRegularFile(path), "MAIN_AUTHORIZATION_REQUIRED");
            byte[] bytes = Files.readAllBytes(path);
            check(bytes.length > 0 && bytes[bytes.length - 1] == '\n', "MAIN_AUTHORIZATION_FINAL_LF");
            for (byte value : bytes) check(value != '\r' && value != 0, "MAIN_AUTHORIZATION_TEXT_FORM");
            String text = new String(bytes, StandardCharsets.UTF_8);
            check(Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8))
                  && !text.startsWith("\ufeff"), "MAIN_AUTHORIZATION_UTF8");
            LinkedHashMap<String, String> values = new LinkedHashMap<String, String>();
            for (String line : text.substring(0, text.length() - 1).split("\n", -1)) {
                int equals = line.indexOf('=');
                check(equals > 0 && equals == line.lastIndexOf('='), "MAIN_AUTHORIZATION_LINE");
                check(values.put(line.substring(0, equals), line.substring(equals + 1)) == null,
                      "MAIN_AUTHORIZATION_DUPLICATE_KEY");
            }
            check(values.keySet().equals(KEYS), "MAIN_AUTHORIZATION_KEYS");
            check(values.get("record_schema").equals("main-run-authorization/1.0")
                  && values.get("effective_protocol").equals("v1.2.4")
                  && values.get("main_runs_authorized").equals("true")
                  && values.get("authorized_by").equals("researcher"),
                  "MAIN_AUTHORIZATION_SEMANTICS");
            check(values.get("authorization_id").matches("AUTH-[0-9]{4}-[0-9]{2}-[0-9]{2}-[A-Z0-9_-]+"),
                  "MAIN_AUTHORIZATION_ID");
            check(values.get("authorized_at_utc").matches(
                  "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"),
                  "MAIN_AUTHORIZATION_TIME");
            check(values.get("authorized_source_commit").matches("[0-9a-f]{40}"),
                  "MAIN_AUTHORIZATION_COMMIT");
            List<String> configs = Arrays.asList(values.get("authorized_configs").split(",", -1));
            check(configs.size() == 16 && new LinkedHashSet<String>(configs).size() == 16,
                  "MAIN_AUTHORIZATION_CONFIG_COUNT");
            for (int index = 1; index <= 16; index++)
                check(configs.get(index - 1).equals(String.format(Locale.ROOT, "CFG%02d", index)),
                      "MAIN_AUTHORIZATION_CONFIG_ORDER");
            check(configs.contains(cfg), "MAIN_AUTHORIZATION_CFG_SCOPE");
            return new Authorization(path.toRealPath(), sha256(bytes), values);
        }
        Map<String, Object> report() {
            return ArxTransformationCapture.map(
                "record_sha256", sha256,
                "authorization_id", values.get("authorization_id"),
                "authorized_at_utc", values.get("authorized_at_utc"),
                "authorized_source_commit", values.get("authorized_source_commit"),
                "authorized_configs", values.get("authorized_configs"),
                "authorized_by", values.get("authorized_by"),
                "main_runs_authorized", Boolean.TRUE);
        }
    }

    private static final class Arguments {
        final Path repoRoot;
        final String configId;
        final Path runDir;
        final String mode;
        final Path authorizationRecord;
        Arguments(Path root, String cfg, Path runDir, String mode, Path authorization) {
            this.repoRoot = root; this.configId = cfg; this.runDir = runDir;
            this.mode = mode; this.authorizationRecord = authorization;
        }
        static Arguments parse(String[] args) throws Exception {
            check(args.length % 2 == 0, "MAIN_ARGUMENT_PAIRS");
            Map<String, String> parsed = new HashMap<String, String>();
            Set<String> allowed = new HashSet<String>(Arrays.asList(
                "--repo-root", "--config-id", "--run-dir", "--mode", "--authorization-record"));
            for (int index = 0; index < args.length; index += 2) {
                check(allowed.contains(args[index]) && !parsed.containsKey(args[index]),
                      "MAIN_ARGUMENT_FLAG");
                parsed.put(args[index], args[index + 1]);
            }
            check(parsed.containsKey("--repo-root") && parsed.containsKey("--config-id")
                  && parsed.containsKey("--run-dir") && parsed.containsKey("--mode"),
                  "MAIN_ARGUMENT_REQUIRED");
            String cfg = parsed.get("--config-id");
            check(cfg.matches("CFG(?:0[1-9]|1[0-6])"), "MAIN_CFG_ID");
            String mode = parsed.get("--mode");
            check(mode.equals("preflight") || mode.equals("run"), "MAIN_MODE");
            check(mode.equals("run") == parsed.containsKey("--authorization-record"),
                  "MAIN_AUTHORIZATION_ARGUMENT_MODE");
            Path rootInput = Paths.get(parsed.get("--repo-root"));
            Path runInput = Paths.get(parsed.get("--run-dir"));
            check(rootInput.isAbsolute() && runInput.isAbsolute(), "MAIN_ABSOLUTE_PATHS");
            Path root = rootInput.toRealPath();
            check(Files.isDirectory(root), "MAIN_REPOSITORY_DIRECTORY");
            Path runDir = runInput.toAbsolutePath().normalize();
            Path expected = root.resolve(mode.equals("preflight")
                ? "runs/readiness_20260915/" + cfg : "runs/main_v1_2_4/" + cfg).normalize();
            check(runDir.equals(expected), "MAIN_RUN_DIRECTORY_CONTRACT");
            Path authorization = mode.equals("run")
                ? Paths.get(parsed.get("--authorization-record")).toAbsolutePath().normalize() : null;
            return new Arguments(root, cfg, runDir, mode, authorization);
        }
    }

    private static final class Outcome {
        final Path report;
        final int reportBytes;
        final String reportSha256;
        final Path output;
        final int outputBytes;
        final String outputSha256;
        Outcome(Path report, byte[] reportBytes, Path output, byte[] outputBytes) throws Exception {
            this.report = report; this.reportBytes = reportBytes.length;
            this.reportSha256 = sha256(reportBytes); this.output = output;
            this.outputBytes = outputBytes == null ? 0 : outputBytes.length;
            this.outputSha256 = outputBytes == null ? null : sha256(outputBytes);
        }
    }
}
