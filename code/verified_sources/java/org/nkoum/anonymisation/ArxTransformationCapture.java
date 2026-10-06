package org.nkoum.anonymisation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.deidentifier.arx.ARXLattice;
import org.deidentifier.arx.ARXLattice.ARXNode;
import org.deidentifier.arx.ARXResult;
import org.deidentifier.arx.AttributeType.Hierarchy;
import org.deidentifier.arx.Data;
import org.deidentifier.arx.DataDefinition;
import org.deidentifier.arx.DataHandle;


public final class ArxTransformationCapture {
    public static final List<String> PHYSICAL = Collections.unmodifiableList(Arrays.asList(
        "sex", "age", "race", "marital-status", "education", "native-country",
        "workclass", "occupation", "salary-class"));
    public static final List<String> QIS = Collections.unmodifiableList(Arrays.asList(
        "age", "sex", "race", "marital-status", "education", "native-country",
        "workclass", "occupation"));
    private static int invocationAttempts;
    private static int completedAnonymizations;

    private ArxTransformationCapture() { }

    public static int invocationAttempts() { return invocationAttempts; }
    public static int completedAnonymizations() { return completedAnonymizations; }

    public static synchronized Map<String, Object> run(ArxConfigurationMatrix matrix, String cfg,
            List<Map<String, Object>> records,
            Map<String, Map<String, Object>> suppliedTables) throws Exception {
        require(matrix != null, "CAPTURE_MATRIX_NULL");
        require(invocationAttempts < 2, "CAPTURE_MAXIMUM_TWO_NATIVE_INVOCATIONS");
        require(cfg.equals("CFG02") || cfg.equals("CFG11"), "CAPTURE_SYNTHETIC_CFG_SCOPE");
        require(records != null && records.size() == 21, "CAPTURE_SYNTHETIC_ROWS");
        require(suppliedTables != null && suppliedTables.keySet().equals(new HashSet<String>(QIS)),
                "CAPTURE_HIERARCHY_KEYS");


        List<String> ids = new ArrayList<String>();
        List<Map<String, String>> frozenRows = new ArrayList<Map<String, String>>();
        for (int index = 0; index < records.size(); index++) {
            Map<String, Object> record = records.get(index);
            require(record.keySet().equals(set("row_id", "row")), "CAPTURE_SOURCE_RECORD_KEYS");
            require(("adult.data:" + (index + 1)).equals(record.get("row_id")),
                    "CAPTURE_SYNTHETIC_RID_ORDER");
            ids.add((String)record.get("row_id"));
            Map<String, String> row = sourceRow(record.get("row"));
            require(row.get("salary-class").equals("<=50K") || row.get("salary-class").equals(">50K"),
                    "CAPTURE_RAW_LABEL");
            frozenRows.add(Collections.unmodifiableMap(row));
        }
        final String frozenRowsHash = digest(frozenRows);
        final String suppliedSourceHash = digest(records);
        final String suppliedTablesHash = digest(suppliedTables);

        Data.DefaultData data = Data.create();
        data.add(PHYSICAL.toArray(new String[0]));
        for (Map<String, String> row : frozenRows) {
            String[] physical = new String[PHYSICAL.size()];
            for (int column = 0; column < physical.length; column++) physical[column] = row.get(PHYSICAL.get(column));
            data.add(physical);
        }
        DataDefinition definition = data.getDefinition();
        Map<String, String[][]> hierarchyCopies = new LinkedHashMap<String, String[][]>();
        for (String qi : QIS) {
            Map<String, Object> table = suppliedTables.get(qi);
            require(table.keySet().equals(set("levels", "rows")), "CAPTURE_HIERARCHY_TABLE_KEYS");
            int maximum = ArxConfigurationMatrix.maximumGeneralizations().get(qi).intValue();
            List<?> levels = checkedList(table.get("levels"));
            require(levels.size() == maximum + 1, "CAPTURE_HIERARCHY_LEVEL_COUNT");
            for (int i = 0; i < levels.size(); i++) require(Integer.valueOf(i).equals(levels.get(i)), "CAPTURE_HIERARCHY_LEVELS");
            List<?> rows = checkedList(table.get("rows"));
            require(rows.size() == 2, "CAPTURE_SYNTHETIC_HIERARCHY_LEAVES");
            String[][] copied = new String[rows.size()][maximum + 1];
            Set<String> leaves = new HashSet<String>();
            for (int r = 0; r < copied.length; r++) {
                List<?> cells = checkedList(rows.get(r));
                require(cells.size() == maximum + 1, "CAPTURE_HIERARCHY_RECTANGLE");
                for (int c = 0; c < copied[r].length; c++) copied[r][c] = cell(cells.get(c));
                require(leaves.add(copied[r][0]), "CAPTURE_DUPLICATE_LEAF");
            }
            for (Map<String, String> row : frozenRows) require(leaves.contains(row.get(qi)), "CAPTURE_RAW_LEAF_COVERAGE");
            definition.setAttributeType(qi, Hierarchy.create(copy(copied)));
            definition.setMinimumGeneralization(qi, 0);
            definition.setMaximumGeneralization(qi, maximum);
            hierarchyCopies.put(qi, copy(copied));
        }

        DataHandle input = data.getHandle();
        List<String> inputHeaders = headers(input);
        List<Map<String, String>> before = snapshot(input, inputHeaders);
        require(before.equals(frozenRows), "CAPTURE_ARX_INPUT_BEFORE_BINDING");
        require(digest(before).equals(frozenRowsHash), "CAPTURE_ARX_INPUT_BEFORE_HASH");

        ArxConfigurationMatrix.PreparedConfiguration prepared = matrix.prepare(cfg, data, hierarchyCopies);
        ArxConfigurationMatrix.AssertionReceipt preparation = prepared.preparationReceipt();
        require(invocationAttempts < 2, "CAPTURE_MAXIMUM_TWO_NATIVE_INVOCATIONS");
        invocationAttempts++;
        ARXResult result = prepared.anonymizeOnce();
        completedAnonymizations++;
        ArxConfigurationMatrix.AssertionReceipt immediate = prepared.immediateReceipt();
        require(result != null && result.isResultAvailable(), "CAPTURE_RESULT_AVAILABLE");
        require(result.getOptimumFound(), "CAPTURE_OPTIMUM_FOUND");
        ARXNode node = result.getGlobalOptimum();
        require(node != null && node.isChecked(), "CAPTURE_CHECKED_NODE");
        require(node.getAnonymity() == ARXLattice.Anonymity.ANONYMOUS, "CAPTURE_ANONYMOUS_NODE");
        ArxConfigurationMatrix.AssertionReceipt effective = matrix.assertEffective(
                prepared, result.getConfiguration(), result.getDataDefinition());

        String[] dimensionArray = node.getQuasiIdentifyingAttributes().clone();
        List<String> dimensionOrder = new ArrayList<String>(Arrays.asList(dimensionArray));
        int[] raw = node.getTransformation().clone();
        require(dimensionArray.length == QIS.size() && raw.length == QIS.size(), "CAPTURE_DIMENSION_COUNT");
        require(new HashSet<String>(dimensionOrder).equals(new HashSet<String>(QIS)), "CAPTURE_DIMENSION_SET");
        Map<String, Integer> dimensions = new LinkedHashMap<String, Integer>();
        Map<String, Integer> byName = new LinkedHashMap<String, Integer>();
        Map<String, Integer> observedGeneralization = new LinkedHashMap<String, Integer>();
        Set<Integer> used = new HashSet<Integer>();
        List<Integer> rawList = new ArrayList<Integer>();
        for (int value : raw) rawList.add(Integer.valueOf(value));
        for (String qi : QIS) {
            int dimension = node.getDimension(qi);
            require(dimension >= 0 && dimension < raw.length && used.add(Integer.valueOf(dimension)), "CAPTURE_DIMENSION_BIJECTION");
            require(qi.equals(dimensionArray[dimension]), "CAPTURE_DIMENSION_REVERSE");
            int observed = node.getGeneralization(qi);
            int level = raw[dimension];
            require(level == observed, "CAPTURE_NAMED_VECTOR_BINDING");
            require(level >= 0 && level <= ArxConfigurationMatrix.maximumGeneralizations().get(qi).intValue(), "CAPTURE_NAMED_VECTOR_BOUNDS");
            dimensions.put(qi, Integer.valueOf(dimension));
            byName.put(qi, Integer.valueOf(level));
            observedGeneralization.put(qi, Integer.valueOf(observed));
        }
        for (int i = 0; i < dimensionArray.length; i++) require(node.getDimension(dimensionArray[i]) == i, "CAPTURE_DIMENSION_FORWARD");


        DataHandle output = result.getOutput(node, false);
        require(output != null && !output.isOptimized(), "CAPTURE_NO_LOCAL_RECODING");
        List<String> outputHeaders = headers(output);
        require(output.getNumRows() == frozenRows.size(), "CAPTURE_OUTPUT_ROW_COUNT");
        require(input == data.getHandle(), "CAPTURE_INPUT_HANDLE_IDENTITY");
        List<Map<String, Object>> transcript = new ArrayList<Map<String, Object>>();
        List<Integer> outliers = new ArrayList<Integer>();
        for (int index = 0; index < output.getNumRows(); index++) {
            boolean outlier = output.isOutlier(index);
            Map<String, String> row = handleRow(output, outputHeaders, index);
            transcript.add(map("original_index", Integer.valueOf(index), "row", row,
                               "is_outlier", Boolean.valueOf(outlier)));
            if (outlier) outliers.add(Integer.valueOf(index));
        }


        List<Map<String, Object>> association = new ArrayList<Map<String, Object>>();
        List<Map<String, Object>> associationObserved = new ArrayList<Map<String, Object>>();
        for (int index = 0; index < output.getNumRows(); index++) {
            Map<String, String> rereadInput = handleRow(input, inputHeaders, index);
            Map<String, String> rereadOutput = handleRow(output, outputHeaders, index);
            boolean rereadOutlier = output.isOutlier(index);
            require(rereadInput.equals(frozenRows.get(index)), "CAPTURE_ASSOCIATION_RAW_INDEX_BINDING");
            String rowHash = digest(rereadOutput);
            association.add(map("original_index", Integer.valueOf(index), "row_id", ids.get(index),
                    "transformed_row_sha256", rowHash, "is_outlier", Boolean.valueOf(rereadOutlier)));
            associationObserved.add(map("original_index", Integer.valueOf(index), "row_id", ids.get(index),
                    "input_row", rereadInput, "output_row", rereadOutput,
                    "is_outlier", Boolean.valueOf(rereadOutlier)));
            Map<String, Object> first = transcript.get(index);
            require(rereadOutput.equals(first.get("row")) && Boolean.valueOf(rereadOutlier).equals(first.get("is_outlier")),
                    "CAPTURE_OUTPUT_TRAVERSAL_STABILITY");


            require(rereadOutput.get("salary-class").equals(frozenRows.get(index).get("salary-class")),
                    "CAPTURE_ALL_ROW_SALARY_BINDING");
            if (!rereadOutlier) {
                Map<String, String> independentlyTransformed = transform(frozenRows.get(index), byName, hierarchyCopies);
                require(rereadOutput.equals(independentlyTransformed), "CAPTURE_RETAINED_TRANSFORMATION_BINDING");
            }
        }
        require(headers(input).equals(inputHeaders) && headers(output).equals(outputHeaders), "CAPTURE_HEADER_STABILITY");
        require(input == data.getHandle() && input.getNumRows() == frozenRows.size()
                && output.getNumRows() == frozenRows.size(), "CAPTURE_HANDLE_SHAPE_STABILITY");
        List<Map<String, String>> after = snapshot(input, inputHeaders);
        require(after.equals(before) && digest(after).equals(frozenRowsHash), "CAPTURE_INPUT_AFTER_BINDING");
        require(digest(records).equals(suppliedSourceHash) && digest(suppliedTables).equals(suppliedTablesHash), "CAPTURE_CALLER_INPUT_STABILITY");
        require(node == result.getGlobalOptimum(), "CAPTURE_NODE_IDENTITY_STABILITY");
        require(Arrays.equals(raw, node.getTransformation()) && Arrays.equals(dimensionArray, node.getQuasiIdentifyingAttributes()), "CAPTURE_NODE_VECTOR_STABILITY");
        for (String qi : QIS) require(node.getDimension(qi) == dimensions.get(qi).intValue()
                && node.getGeneralization(qi) == byName.get(qi).intValue(), "CAPTURE_NODE_NAME_STABILITY");
        require(cfg.equals("CFG02") ? outliers.isEmpty() : outliers.equals(Arrays.asList(Integer.valueOf(20))),
                "CAPTURE_SYNTHETIC_SUPPRESSION_BRANCH");
        if (cfg.equals("CFG11")) for (Integer level : byName.values()) require(level.intValue() == 0, "CAPTURE_SYNTHETIC_RAW_OPTIMUM");

        return map("config_id", cfg, "input_physical_schema", inputHeaders,
                "output_physical_schema", outputHeaders, "actual_arx_dimension_order", dimensionOrder,
                "dimensions_by_name", dimensions, "raw_transformation", rawList,
                "transformation_by_name", byName, "node_generalization_by_name", observedGeneralization,
                "selected_node", map("is_checked", Boolean.TRUE, "anonymity", node.getAnonymity().toString(),
                        "optimum_found", Boolean.valueOf(result.getOptimumFound()),
                        "result_available", Boolean.valueOf(result.isResultAvailable()),
                        "output_optimized", Boolean.valueOf(output.isOptimized())),
                "input_before_rows", before, "input_after_rows", after,
                "input_rows_canonical_json_sha256", frozenRowsHash,
                "java_transcript", transcript, "captured_association", association,
                "association_observed_rows", associationObserved, "outlier_indices", outliers,
                "preparation_receipt", receipt(preparation), "immediate_receipt", receipt(immediate),
                "effective_receipt", receipt(effective),
                "checks", map("input_before_after_binding", Boolean.TRUE,
                        "result_owned_node_output_binding", Boolean.TRUE,
                        "named_vector_bijection", Boolean.TRUE, "two_output_traversals_equal", Boolean.TRUE,
                        "original_index_rid_binding", Boolean.TRUE, "retained_transform_equality", Boolean.TRUE,
                        "no_sort_or_permutation", Boolean.TRUE, "no_local_recoding", Boolean.TRUE));
    }

    private static Map<String, Object> receipt(ArxConfigurationMatrix.AssertionReceipt value) {
        require(value != null && value.allPassed(), "CAPTURE_MATRIX_RECEIPT");
        return map("phase", value.phase(), "config_id", value.specification().id(),
                "manifest_bytes", Long.valueOf(value.manifestBytes()), "manifest_sha256", value.manifestSha256(),
                "fingerprint", value.fingerprint(), "passed_assertions", new ArrayList<String>(value.passedAssertions()),
                "all_passed", Boolean.valueOf(value.allPassed()));
    }

    private static Map<String, String> transform(Map<String, String> row,
            Map<String, Integer> vector, Map<String, String[][]> tables) {
        Map<String, String> result = new LinkedHashMap<String, String>();
        for (String qi : QIS) {
            String value = null;
            for (String[] path : tables.get(qi)) if (path[0].equals(row.get(qi))) {
                require(value == null, "CAPTURE_DUPLICATE_TRANSFORM_LEAF");
                value = path[vector.get(qi).intValue()];
            }
            require(value != null, "CAPTURE_MISSING_TRANSFORM_LEAF");
            result.put(qi, value);
        }
        result.put("salary-class", row.get("salary-class"));
        return result;
    }

    private static List<String> headers(DataHandle handle) {
        require(handle.getNumColumns() == PHYSICAL.size(), "CAPTURE_PHYSICAL_COLUMN_COUNT");
        List<String> result = new ArrayList<String>();
        for (int column = 0; column < handle.getNumColumns(); column++) result.add(handle.getAttributeName(column));
        require(result.equals(PHYSICAL), "CAPTURE_PHYSICAL_HEADER_ORDER");
        require(new HashSet<String>(result).size() == PHYSICAL.size(), "CAPTURE_HEADER_BIJECTION");
        return result;
    }

    private static Map<String, String> handleRow(DataHandle handle, List<String> headers, int index) {
        Map<String, String> physical = new LinkedHashMap<String, String>();
        for (int column = 0; column < headers.size(); column++) require(physical.put(headers.get(column),
                cell(handle.getValue(index, column))) == null, "CAPTURE_DUPLICATE_PHYSICAL_HEADER");
        Map<String, String> canonical = new LinkedHashMap<String, String>();
        for (String qi : QIS) canonical.put(qi, physical.get(qi));
        canonical.put("salary-class", physical.get("salary-class"));
        return canonical;
    }

    private static List<Map<String, String>> snapshot(DataHandle handle, List<String> headers) {
        List<Map<String, String>> result = new ArrayList<Map<String, String>>();
        for (int row = 0; row < handle.getNumRows(); row++) result.add(handleRow(handle, headers, row));
        return result;
    }

    private static Map<String, String> sourceRow(Object value) {
        require(value instanceof Map<?, ?>, "CAPTURE_SOURCE_ROW_TYPE");
        Map<?, ?> raw = (Map<?, ?>)value;
        require(raw.keySet().equals(new HashSet<String>(PHYSICAL)), "CAPTURE_SOURCE_ROW_KEYS");
        Map<String, String> copy = new LinkedHashMap<String, String>();
        for (String qi : QIS) copy.put(qi, cell(raw.get(qi)));
        copy.put("salary-class", cell(raw.get("salary-class")));
        return copy;
    }

    private static List<?> checkedList(Object value) {
        require(value instanceof List<?>, "CAPTURE_LIST_TYPE"); return (List<?>)value;
    }
    private static String cell(Object value) {
        require(value instanceof String, "CAPTURE_CELL_TYPE");
        String s = (String)value;
        require(!s.isEmpty() && s.equals(s.trim()) && !s.equals("?"), "CAPTURE_CELL_MISSING");
        for (int i = 0; i < s.length(); i++) require(s.charAt(i) >= 32 && s.charAt(i) < 127, "CAPTURE_SYNTHETIC_ASCII_CELL");
        return s;
    }
    private static String[][] copy(String[][] value) {
        String[][] result = new String[value.length][];
        for (int i = 0; i < value.length; i++) result[i] = value[i].clone();
        return result;
    }
    private static Set<String> set(String... values) { return new HashSet<String>(Arrays.asList(values)); }
    public static void require(boolean condition, String code) {
        if (!condition) throw new IllegalStateException(code);
    }
    public static Map<String, Object> map(Object... entries) {
        require(entries.length % 2 == 0, "CAPTURE_MAP_PAIRS");
        Map<String, Object> result = new LinkedHashMap<String, Object>();
        for (int i = 0; i < entries.length; i += 2) {
            require(entries[i] instanceof String, "CAPTURE_MAP_KEY");
            String key = (String)entries[i];
            require(!result.containsKey(key), "CAPTURE_MAP_DUPLICATE_KEY");
            result.put(key, entries[i + 1]);
        }
        return result;
    }
    public static String digest(Object value) throws Exception {
        byte[] bytes = MessageDigest.getInstance("SHA-256").digest(json(value).getBytes(StandardCharsets.US_ASCII));
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) result.append(String.format(java.util.Locale.ROOT, "%02x", Integer.valueOf(b & 255)));
        return result.toString();
    }


    public static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof String) return quote((String)value);
        if (value instanceof Boolean || value instanceof Integer || value instanceof Long) return value.toString();
        if (value instanceof Map<?, ?>) {
            TreeMap<String, Object> sorted = new TreeMap<String, Object>();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>)value).entrySet()) {
                require(entry.getKey() instanceof String, "CAPTURE_JSON_KEY");
                String key = (String)entry.getKey();
                for (int i = 0; i < key.length(); i++) require(key.charAt(i) < 127, "CAPTURE_JSON_ASCII_KEY_DOMAIN");
                sorted.put(key, entry.getValue());
            }
            StringBuilder result = new StringBuilder("{"); boolean first = true;
            for (Map.Entry<String, Object> entry : sorted.entrySet()) {
                if (!first) result.append(','); first = false;
                result.append(quote(entry.getKey())).append(':').append(json(entry.getValue()));
            }
            return result.append('}').toString();
        }
        if (value instanceof List<?>) {
            StringBuilder result = new StringBuilder("["); boolean first = true;
            for (Object item : (List<?>)value) { if (!first) result.append(','); first = false; result.append(json(item)); }
            return result.append(']').toString();
        }
        throw new IllegalStateException("CAPTURE_JSON_UNSUPPORTED_TYPE");
    }
    private static String quote(String value) {
        StringBuilder result = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': result.append("\\\""); break;
                case '\\': result.append("\\\\"); break;
                case '\b': result.append("\\b"); break;
                case '\f': result.append("\\f"); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (c < 32 || c >= 127) result.append(String.format(java.util.Locale.ROOT, "\\u%04x", Integer.valueOf(c)));
                    else result.append(c);
            }
        }
        return result.append('"').toString();
    }
}
