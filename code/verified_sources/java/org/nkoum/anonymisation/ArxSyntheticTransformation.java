package org.nkoum.anonymisation;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.deidentifier.arx.ARXResult;


public final class ArxSyntheticTransformation {
    private static final String SCHEMA = "step7-java-transformation-native-worker/1";
    private static final List<String> QIS = Arrays.asList(
            "age", "sex", "race", "marital-status", "education", "native-country",
            "workclass", "occupation");
    private static final int[] MAXIMA = new int[] {4, 1, 1, 2, 3, 2, 2, 2};
    private static final String[] COMMON = new String[] {"20", "Male", "White", "Never-married",
            "Bachelors", "United-States", "Private", "Tech-support"};
    private static final String[] RARE = new String[] {"30", "Female", "Black", "Married-civ-spouse",
            "HS-grad", "Canada", "Self-emp-not-inc", "Sales"};

    private ArxSyntheticTransformation() { }

    public static void main(String[] args) {
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;
        LimitedBuffer capturedOut = new LimitedBuffer(1024 * 1024);
        LimitedBuffer capturedErr = new LimitedBuffer(1024 * 1024);
        PrintStream interceptedOut = null;
        PrintStream interceptedErr = null;
        int exit = 1;
        String stage = "validate_fixed_invocation";
        List<Map<String, Object>> runs = new ArrayList<Map<String, Object>>();
        Map<String, Object> report = map(
                "record_schema", SCHEMA, "result", "FAIL", "mode", "synthetic_fixture",
                "runs", runs, "effective_protocol_version", "v1.2.3",
                "source_base_commit", "b45540951e77d5d5a4db28ea6b6cc76df8d9e42a",
                "section_12_1_step_7_status", "pending", "gate_a_status", "pending",
                "main_runs_authorized", Boolean.FALSE, "main_runs_executed", Boolean.FALSE,
                "model_fits_executed", Boolean.FALSE, "model_fit_count", Integer.valueOf(0),
                "rng_invoked", Boolean.FALSE, "rng_instantiated", Boolean.FALSE,
                "production_rng_realizations_generated", Boolean.FALSE,
                "Adult_rows_accessed", Boolean.FALSE, "fixture_rids_are_synthetic_labels", Boolean.TRUE,
                "operational_producer_integration_verified", Boolean.FALSE,
                "new_protocol_activation", Boolean.FALSE, "step7_assertions_activated", Boolean.FALSE,
                "file_write_operations_performed", Boolean.FALSE, "private_file_write_operations", Boolean.FALSE,
                "data_creation", "Data.create()+DefaultData.add(String[])",
                "physical_serialized_header_verified", Boolean.FALSE,
                "observed_actual_handle_header_verified", Boolean.FALSE);
        try {
            require(args.length == 1, "SYNTHETIC_ARGUMENT_COUNT");
            require(!args[0].isEmpty(), "SYNTHETIC_CONFIG_PATH_EMPTY");
            interceptedOut = new PrintStream(capturedOut, true, StandardCharsets.UTF_8.name());
            interceptedErr = new PrintStream(capturedErr, true, StandardCharsets.UTF_8.name());
            System.setOut(interceptedOut);
            System.setErr(interceptedErr);
            stage = "construct_fixed_synthetic_fixture";
            List<Map<String, Object>> training = training();
            List<Map<String, Object>> holdout = holdout();
            Map<String, Map<String, Object>> tables = tables();
            Map<String, Object> fixture = map("raw_training_records", training,
                    "raw_holdout_records", holdout, "hierarchy_tables", tables);
            final String fixtureHash = digest(fixture);
            report.put("fixture", fixture);
            report.put("fixture_canonical_json_sha256", fixtureHash);
            report.put("training_canonical_json_sha256", digest(training));
            report.put("holdout_canonical_json_sha256", digest(holdout));
            report.put("hierarchies_canonical_json_sha256", digest(tables));
            report.put("runtime", map(
                    "java_version", System.getProperty("java.version"),
                    "java_vm_name", System.getProperty("java.vm.name"),
                    "java_home", System.getProperty("java.home"),
                    "os_name", System.getProperty("os.name"),
                    "os_arch", System.getProperty("os.arch"),
                    "arx_code_source", ARXResult.class.getProtectionDomain().getCodeSource().getLocation().toExternalForm(),
                    "matrix_code_source", ArxConfigurationMatrix.class.getProtectionDomain().getCodeSource().getLocation().toExternalForm()));
            stage = "load_frozen_cfg_matrix";
            ArxConfigurationMatrix matrix = ArxConfigurationMatrix.load(Paths.get(args[0]));
            report.put("configuration_manifest", map("bytes", Long.valueOf(matrix.manifestBytes()),
                    "sha256", matrix.manifestSha256()));
            require(ArxTransformationCapture.invocationAttempts() == 0
                    && ArxTransformationCapture.completedAnonymizations() == 0, "SYNTHETIC_FRESH_PROCESS_COUNTS");
            stage = "execute_synthetic_CFG02";
            runs.add(ArxTransformationCapture.run(matrix, "CFG02", training, tables));
            stage = "execute_synthetic_CFG11";
            runs.add(ArxTransformationCapture.run(matrix, "CFG11", training, tables));
            stage = "verify_completed_synthetic_scope";
            require(ArxTransformationCapture.invocationAttempts() == 2
                    && ArxTransformationCapture.completedAnonymizations() == 2
                    && runs.size() == 2, "SYNTHETIC_EXACT_ANONYMIZATION_COUNT");
            require(digest(fixture).equals(fixtureHash), "SYNTHETIC_FIXTURE_UNCHANGED");
            require(!capturedOut.limitExceeded && !capturedErr.limitExceeded, "SYNTHETIC_LIBRARY_OUTPUT_LIMIT");
            report.put("observed_actual_handle_header_verified", Boolean.TRUE);
            report.put("synthetic_capture_and_transformation_binding", "PASS");
            report.put("fixture_unchanged", Boolean.TRUE);
            report.put("result", "PASS");
            exit = 0;
        } catch (Throwable error) {
            report.put("result", "FAIL");
            report.put("failed_stage", stage);
            report.put("error_type", error.getClass().getName());
            report.put("error", error.getMessage() == null ? "No detail" : error.getMessage());
        } finally {
            if (interceptedOut != null) interceptedOut.flush();
            if (interceptedErr != null) interceptedErr.flush();
            System.setOut(originalOut);
            System.setErr(originalErr);
            report.put("anonymization_invocation_attempt_count", Integer.valueOf(ArxTransformationCapture.invocationAttempts()));
            report.put("anonymization_completed_count", Integer.valueOf(ArxTransformationCapture.completedAnonymizations()));
            report.put("captured_stdout", capturedOut.toString(StandardCharsets.UTF_8));
            report.put("captured_stderr", capturedErr.toString(StandardCharsets.UTF_8));
            report.put("captured_output_limit_exceeded", Boolean.valueOf(capturedOut.limitExceeded || capturedErr.limitExceeded));
            originalOut.print(ArxTransformationCapture.json(report) + "\n");
            originalOut.flush();
        }
        if (exit != 0) System.exit(exit);
    }

    private static List<Map<String, Object>> training() {
        List<Map<String, Object>> result = new ArrayList<Map<String, Object>>();
        for (int index = 0; index < 21; index++) {
            String label = index == 20 || index % 2 == 1 ? ">50K" : "<=50K";
            result.add(map("row_id", "adult.data:" + (index + 1), "row", row(index == 20, label)));
        }
        return result;
    }

    private static List<Map<String, Object>> holdout() {
        List<Map<String, Object>> result = new ArrayList<Map<String, Object>>();
        for (int index = 0; index < 6; index++) result.add(map(
                "row_id", "adult.test:" + (index + 2),
                "row", row(index % 2 == 1, index < 3 ? "<=50K" : ">50K")));
        return result;
    }

    private static Map<String, Object> row(boolean rare, String label) {
        Map<String, Object> result = new LinkedHashMap<String, Object>();
        String[] source = rare ? RARE : COMMON;
        for (int index = 0; index < QIS.size(); index++) result.put(QIS.get(index), source[index]);
        result.put("salary-class", label);
        return result;
    }

    private static Map<String, Map<String, Object>> tables() {
        Map<String, Map<String, Object>> result = new LinkedHashMap<String, Map<String, Object>>();
        for (int index = 0; index < QIS.size(); index++) {
            String qi = QIS.get(index);
            List<Integer> levels = new ArrayList<Integer>();
            List<String> common = new ArrayList<String>();
            List<String> rare = new ArrayList<String>();
            for (int level = 0; level <= MAXIMA[index]; level++) {
                levels.add(Integer.valueOf(level));
                common.add(level == 0 ? COMMON[index] : qi + "_ALL");
                rare.add(level == 0 ? RARE[index] : qi + "_ALL");
            }
            List<List<String>> rows = new ArrayList<List<String>>();
            rows.add(common); rows.add(rare);
            result.put(qi, map("levels", levels, "rows", rows));
        }
        return result;
    }

    private static Map<String, Object> map(Object... values) {
        return ArxTransformationCapture.map(values);
    }
    private static String digest(Object value) throws Exception {
        return ArxTransformationCapture.digest(value);
    }
    private static void require(boolean condition, String code) {
        ArxTransformationCapture.require(condition, code);
    }


    private static final class LimitedBuffer extends ByteArrayOutputStream {
        private final int limit;
        private boolean limitExceeded;
        LimitedBuffer(int limit) { this.limit = limit; }
        @Override public synchronized void write(int value) {
            if (count >= limit) { limitExceeded = true; return; }
            super.write(value);
        }
        @Override public synchronized void write(byte[] bytes, int offset, int length) {
            int remaining = limit - count;
            if (length > remaining) { limitExceeded = true; length = remaining; }
            if (length > 0) super.write(bytes, offset, length);
        }
    }
}
