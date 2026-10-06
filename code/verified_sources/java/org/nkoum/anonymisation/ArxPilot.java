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
import java.security.NoSuchAlgorithmException;
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
import org.deidentifier.arx.AttributeType;
import org.deidentifier.arx.AttributeType.Hierarchy;
import org.deidentifier.arx.Data;
import org.deidentifier.arx.DataDefinition;
import org.deidentifier.arx.DataHandle;
import org.deidentifier.arx.metric.InformationLoss;
import org.deidentifier.arx.metric.Metric;
import org.deidentifier.arx.metric.v2.AbstractILMultiDimensional;
import org.deidentifier.arx.metric.v2.ILMultiDimensionalArithmeticMean;
import org.deidentifier.arx.metric.v2.MetricMDNMLoss;


public final class ArxPilot {

    private static final String REPORT_SCHEMA = "arx-cfg02-pilot-v1.2.3/1.1";
    private static final String CONFIG_ID = "CFG02";
    private static final int EXPECTED_ROWS = 30162;
    private static final int K = 5;
    private static final char INPUT_DELIMITER = ';';
    private static final char INPUT_QUOTE = '"';
    private static final char INPUT_ESCAPE = '"';
    private static final char[] INPUT_LINEBREAK = new char[] {'\n'};

    private static final List<String> PHYSICAL_SCHEMA = immutable(
        "sex", "age", "race", "marital-status", "education",
        "native-country", "workclass", "occupation", "salary-class");

    private static final List<String> EXPECTED_ARX_DIMENSION_ORDER = immutable(
        "sex", "age", "race", "marital-status", "education",
        "native-country", "workclass", "occupation");

    private static final List<String> COMPARISON_QI_ORDER = immutable(
        "age", "sex", "race", "marital-status", "education",
        "native-country", "workclass", "occupation");

    private static final List<String> CANONICAL_SCHEMA = immutable(
        "age", "sex", "race", "marital-status", "education",
        "native-country", "workclass", "occupation", "salary-class");

    private static final Set<String> ALLOWED_RUN_IDS = Collections.unmodifiableSet(
        new LinkedHashSet<String>(Arrays.asList(
            "PILOT_CFG02_RAW_R1",
            "PILOT_CFG02_RAW_R2",
            "PILOT_CFG02_SEMANTIC_R1",
            "PILOT_CFG02_SEMANTIC_R2")));

    private static final String RAW_ROOT =
        "data/raw/arx-adult/4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f";
    private static final String INPUT_RELATIVE = RAW_ROOT + "/adult.csv";
    private static final String MAPPING_RELATIVE =
        "manifest/adult_hierarchy_age_semantic_mapping.json";
    private static final String EFFECTIVE_MANIFEST_RELATIVE =
        "manifest/protocol_effective_v1_2_3.txt";
    private static final String JAR_RELATIVE = "vendor/arx-3.9.2/libarx-3.9.2.jar";

    private static final FileSpec ARX_JAR = new FileSpec(
        JAR_RELATIVE, 36161310L,
        "18040108e95ca7955d806bf32354b20601d664495653b8ee169d249f43f58d44");
    private static final FileSpec INPUT = new FileSpec(
        INPUT_RELATIVE, 2516935L,
        "c700df9304fbf3c4d4db5938bffc510561bd4a2dfad285a3feef9a20619391c5");
    private static final FileSpec MAPPING = new FileSpec(
        MAPPING_RELATIVE, 6547L,
        "a611a05b0deb35b6a578f50b32e887e0994fd30b9525f96f831aeec625e32775");
    private static final FileSpec EFFECTIVE_MANIFEST = new FileSpec(
        EFFECTIVE_MANIFEST_RELATIVE, 5390L,
        "3dc23bec78ec4f4a55a61d26f422bbd383f5388bd8ac48ebdbf719e513dfc36e");
    private static final FileSpec CFG_MATRIX_MANIFEST = new FileSpec(
        ArxConfigurationMatrix.MANIFEST_RELATIVE_PATH,
        ArxConfigurationMatrix.MANIFEST_BYTES,
        ArxConfigurationMatrix.MANIFEST_SHA256);

    private static final List<HierarchySpec> HIERARCHIES = Collections.unmodifiableList(
        Arrays.asList(
            new HierarchySpec("sex", RAW_ROOT + "/adult_hierarchy_sex.csv", 16L,
                "537d23f7b6969b916b5a5490eb1b32c273fefdc62ca050a7a813e23bbf3b78b2", 1),
            new HierarchySpec("age", RAW_ROOT + "/adult_hierarchy_age.csv", 2232L,
                "463f35372e8b1ad31fc624eb73c5da9297878a044ae5d61038eaf7b431ac55ca", 4),
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
                "16dc420d5d7f8ab4d1e6144eb1d19ab8314ef42523fe8c4ee202372db1c98126", 2)));

    private static final HierarchySpec SEMANTIC_AGE = new HierarchySpec(
        "age", "data/derived/hierarchies/adult_hierarchy_age_semantic.csv", 2282L,
        "de2a5bdc9b0ad72a31ca8199e7be5d39346646da604bf1fb8954afc7626e0ba5", 4);

    private ArxPilot() {

    }

    public static void main(String[] args) {
        try {
            Arguments arguments = Arguments.parse(args);
            RunOutcome outcome = run(arguments);
            System.out.println("RUN_ID=" + arguments.runId);
            System.out.println("OUTPUT_FILE=" + outcome.outputPath.toString());
            System.out.println("OUTPUT_BYTES=" + outcome.outputBytes);
            System.out.println("OUTPUT_SHA256=" + outcome.outputSha256);
            System.out.println("REPORT_FILE=" + outcome.reportPath.toString());
            System.out.println("REPORT_BYTES=" + outcome.reportBytes);
            System.out.println("REPORT_SHA256=" + outcome.reportSha256);
            System.out.println("CANONICAL_SEMANTIC_SHA256=" + outcome.canonicalSemanticSha256);
            System.out.println("RESULT=PASS");
        } catch (Throwable error) {
            String message = error.getMessage();
            if (message == null || message.isEmpty()) {
                message = "no detail";
            }
            System.err.println("RESULT=FAIL");
            System.err.println("ERROR_CLASS=" + error.getClass().getName());
            System.err.println("ERROR_MESSAGE=" + sanitizeDiagnostic(message));
            System.exit(1);
        }
    }

    private static RunOutcome run(Arguments arguments) throws Exception {
        final boolean rawVariant = arguments.runId.contains("_RAW_");
        final String variant = rawVariant ? "raw" : "semantic";

        verifyFile(arguments.repoRoot, ARX_JAR);
        verifyFile(arguments.repoRoot, INPUT);
        verifyFile(arguments.repoRoot, MAPPING);
        verifyFile(arguments.repoRoot, EFFECTIVE_MANIFEST);
        verifyFile(arguments.repoRoot, CFG_MATRIX_MANIFEST);
        GeneratedArtifactIdentity matrixTestReport = verifyMatrixTestReport(
            arguments.matrixTestReport, arguments.runDir);


        verifyFile(arguments.repoRoot, findHierarchy("age"));
        verifyFile(arguments.repoRoot, SEMANTIC_AGE);
        verifyLoadedArxJar(arguments.repoRoot.resolve(JAR_RELATIVE));

        List<ResolvedHierarchy> resolvedHierarchies = new ArrayList<ResolvedHierarchy>();
        for (HierarchySpec spec : HIERARCHIES) {
            HierarchySpec selected = "age".equals(spec.qi) && !rawVariant ? SEMANTIC_AGE : spec;
            verifyFile(arguments.repoRoot, selected);
            String[][] table = readStrictHierarchy(arguments.repoRoot.resolve(selected.relativePath),
                                                    selected.maxGeneralization + 1);
            resolvedHierarchies.add(new ResolvedHierarchy(selected, table));
        }

        String[][] rawAgeTable = readStrictHierarchy(
            arguments.repoRoot.resolve(findHierarchy("age").relativePath), 5);
        String[][] semanticAgeTable = readStrictHierarchy(
            arguments.repoRoot.resolve(SEMANTIC_AGE.relativePath), 5);
        AgeMapping ageMapping = AgeMapping.loadAndValidate(
            arguments.repoRoot.resolve(MAPPING.relativePath), rawAgeTable, semanticAgeTable);

        assertEquals(100, rawAgeTable.length, "raw age hierarchy row count");
        assertEquals(100, semanticAgeTable.length, "semantic age hierarchy row count");
        validateAgePartitionShape(rawAgeTable, "raw");
        validateAgePartitionShape(semanticAgeTable, "semantic");
        validateTransformationSpace(resolvedHierarchies);

        Data data = Data.create(arguments.repoRoot.resolve(INPUT.relativePath).toFile(),
                                StandardCharsets.UTF_8,
                                INPUT_DELIMITER,
                                INPUT_QUOTE,
                                INPUT_ESCAPE,
                                INPUT_LINEBREAK.clone());
        DataHandle inputHandle = data.getHandle();
        assertSchema(inputHandle, PHYSICAL_SCHEMA, "input");
        assertEquals(EXPECTED_ROWS, inputHandle.getNumRows(), "input row count");
        Map<String, Integer> inputSalaryCounts = countColumn(inputHandle, 8);
        assertSalaryCounts(inputSalaryCounts, "input");

        DataDefinition definition = data.getDefinition();
        for (ResolvedHierarchy resolved : resolvedHierarchies) {
            Hierarchy hierarchy = Hierarchy.create(
                arguments.repoRoot.resolve(resolved.spec.relativePath).toFile(),
                StandardCharsets.UTF_8,
                INPUT_DELIMITER,
                INPUT_QUOTE,
                INPUT_ESCAPE,
                INPUT_LINEBREAK.clone());
            definition.setAttributeType(resolved.spec.qi, hierarchy);
            definition.setMinimumGeneralization(resolved.spec.qi, 0);
            definition.setMaximumGeneralization(resolved.spec.qi,
                                                resolved.spec.maxGeneralization);
        }
        Map<String, String[][]> expectedHierarchies =
            expectedHierarchyMap(resolvedHierarchies);
        ArxConfigurationMatrix matrix = ArxConfigurationMatrix.load(
            arguments.repoRoot.resolve(CFG_MATRIX_MANIFEST.relativePath));
        ArxConfigurationMatrix.PreparedConfiguration prepared =
            matrix.prepare(CONFIG_ID, data, expectedHierarchies);
        ArxConfigurationMatrix.AssertionReceipt preparationReceipt =
            prepared.preparationReceipt();
        ARXResult result = prepared.anonymizeOnce();
        ArxConfigurationMatrix.AssertionReceipt immediateReceipt =
            prepared.immediateReceipt();

        check(result.isResultAvailable(), "ARX result is unavailable");
        check(result.getOptimumFound(), "ARX did not prove that the optimum was found");
        ARXNode node = result.getGlobalOptimum();
        check(node != null, "global optimum node is null");
        check(node.isChecked(), "global optimum node is not checked");
        check(node.getAnonymity() == ARXLattice.Anonymity.ANONYMOUS,
              "global optimum node is not exactly ANONYMOUS");

        ARXConfiguration effectiveConfiguration = result.getConfiguration();
        DataDefinition effectiveDefinition = result.getDataDefinition();
        ArxConfigurationMatrix.AssertionReceipt effectiveReceipt =
            matrix.assertEffective(prepared, effectiveConfiguration, effectiveDefinition);

        String[] actualOrderArray = node.getQuasiIdentifyingAttributes().clone();
        List<String> actualOrder = immutableCopy(actualOrderArray);
        assertDimensionBridge(node, actualOrderArray);

        int[] rawTransformation = node.getTransformation().clone();
        Map<String, Integer> transformationByName = assertTransformation(
            node, actualOrderArray, rawTransformation, effectiveDefinition);
        int ageLevel = required(transformationByName, "age");

        LossEvidence loss = extractAndValidateLoss(node, effectiveConfiguration,
                                                   actualOrderArray);

        DataHandle output = result.getOutput(node, false);
        check(output != null, "ARX output handle is null");
        check(!output.isOptimized(), "output indicates local recoding/optimization");
        assertSchema(output, PHYSICAL_SCHEMA, "output");
        assertEquals(EXPECTED_ROWS, output.getNumRows(), "output row count");

        MaterializedOutput materialized = materializeOutput(output, rawVariant, ageLevel,
                                                             ageMapping);
        validateRows(materialized.rows, materialized.outlierRowIndices);

        byte[] outputBytes = serializeRows(materialized.rows, PHYSICAL_SCHEMA, null, -1);
        byte[] canonicalBytes = serializeRows(materialized.rows, CANONICAL_SCHEMA,
                                              ageMapping, rawVariant ? ageLevel : -ageLevel - 1);
        String outputSha256 = sha256(outputBytes);
        String canonicalSha256 = sha256(canonicalBytes);

        ValidatorEvidence validators = computeValidators(materialized.rows,
                                                         materialized.outlierRowIndices);

        String outputFilename = arguments.runId + ".output.tsv";
        String reportFilename = arguments.runId + ".report.json";
        Path outputPath = arguments.runDir.resolve(outputFilename);
        Path reportPath = arguments.runDir.resolve(reportFilename);

        LinkedHashMap<String, Object> report = buildReport(
            arguments.runId, variant, resolvedHierarchies, actualOrder,
            rawTransformation, transformationByName, loss, validators,
            outputFilename, outputBytes.length, outputSha256,
            reportFilename, canonicalBytes.length, canonicalSha256,
            materialized.outlierRowIndices, matrixTestReport,
            preparationReceipt, immediateReceipt, effectiveReceipt);
        byte[] reportBytes = (JsonWriter.write(report) + "\n").getBytes(StandardCharsets.UTF_8);

        Files.createDirectories(arguments.runDir);
        check(Files.isDirectory(arguments.runDir), "run-dir is not a directory");
        preflightTarget(outputPath, outputBytes);
        preflightTarget(reportPath, reportBytes);
        writeIdempotent(outputPath, outputBytes);
        writeIdempotent(reportPath, reportBytes);

        return new RunOutcome(outputPath, reportPath, outputBytes.length, reportBytes.length,
                              outputSha256, sha256(reportBytes), canonicalSha256);
    }

    private static void assertDimensionBridge(ARXNode node, String[] actualOrder) {
        check(Arrays.equals(actualOrder, EXPECTED_ARX_DIMENSION_ORDER.toArray(new String[0])),
              "actual ARX dimension order differs from the frozen expected order: " +
              Arrays.toString(actualOrder));
        assertEquals(8, actualOrder.length, "actual ARX dimension count");
        Set<String> unique = new HashSet<String>();
        Set<Integer> indices = new HashSet<Integer>();
        for (int i = 0; i < actualOrder.length; i++) {
            String name = actualOrder[i];
            check(name != null && !name.isEmpty(), "null/empty ARX dimension name at index " + i);
            check(unique.add(name), "duplicate ARX dimension name: " + name);
            int dimension = node.getDimension(name);
            assertEquals(i, dimension, "forward dimension index for " + name);
            check(indices.add(dimension), "duplicate ARX dimension index: " + dimension);
        }
        check(unique.equals(new HashSet<String>(EXPECTED_ARX_DIMENSION_ORDER)),
              "actual ARX dimension set mismatch");
        for (String qi : COMPARISON_QI_ORDER) {
            int dimension = node.getDimension(qi);
            check(dimension >= 0 && dimension < actualOrder.length,
                  "invalid reverse dimension index for " + qi);
            check(actualOrder[dimension].equals(qi),
                  "reverse dimension lookup mismatch for " + qi);
        }
        for (int i = 0; i < actualOrder.length; i++) {
            check(indices.contains(i), "dimension permutation omits index " + i);
        }
    }

    private static Map<String, Integer> assertTransformation(ARXNode node,
                                                              String[] actualOrder,
                                                              int[] transformation,
                                                              DataDefinition definition) {
        assertEquals(8, transformation.length, "raw transformation length");
        LinkedHashMap<String, Integer> byName = new LinkedHashMap<String, Integer>();
        for (int i = 0; i < transformation.length; i++) {
            String qi = actualOrder[i];
            int level = transformation[i];
            assertEquals(level, node.getGeneralization(qi),
                         "node generalization/raw transformation mismatch for " + qi);
            int minimum = definition.getMinimumGeneralization(qi);
            int maximum = definition.getMaximumGeneralization(qi);
            assertEquals(0, minimum, "runtime minimum generalization for " + qi);
            assertEquals(findHierarchy(qi).maxGeneralization, maximum,
                         "runtime maximum generalization for " + qi);
            check(level >= minimum && level <= maximum,
                  "generalization level outside bounds for " + qi + ": " + level);
            check(byName.put(qi, Integer.valueOf(level)) == null,
                  "duplicate transformation name " + qi);
        }
        check(byName.keySet().equals(new LinkedHashSet<String>(EXPECTED_ARX_DIMENSION_ORDER)),
              "transformation map is not a complete dimension bijection");
        return byName;
    }

    private static LossEvidence extractAndValidateLoss(ARXNode node,
                                                       ARXConfiguration configuration,
                                                       String[] actualOrder) {
        InformationLoss<?> highestCandidate = node.getHighestScore();
        InformationLoss<?> lowestCandidate = node.getLowestScore();
        check(highestCandidate != null, "highest score candidate is null");
        check(lowestCandidate != null, "lowest score candidate is null");
        Class<?> expectedClass = ILMultiDimensionalArithmeticMean.class;
        check(highestCandidate.getClass().equals(expectedClass),
              "highest score class mismatch: " + highestCandidate.getClass().getName());
        check(lowestCandidate.getClass().equals(expectedClass),
              "lowest score class mismatch: " + lowestCandidate.getClass().getName());

        double[] highestComponents = extractComponents(highestCandidate, "highest candidate");
        double[] lowestComponents = extractComponents(lowestCandidate, "lowest candidate");
        assertDoubleArrayBits(highestComponents, lowestComponents,
                              "highest/lowest score components");

        Metric<?> effectiveMetric = configuration.getQualityModel();
        check(effectiveMetric.getClass().equals(MetricMDNMLoss.class),
              "effective metric class changed before score extraction");
        double[] weights = new double[actualOrder.length];
        for (int i = 0; i < actualOrder.length; i++) {
            weights[i] = configuration.getAttributeWeight(actualOrder[i]);
            assertBits(1.0d, weights[i], "runtime weight for " + actualOrder[i]);
        }

        InformationLoss<?> metricMin = effectiveMetric.createInstanceOfLowestScore();
        InformationLoss<?> metricMax = effectiveMetric.createInstanceOfHighestScore();
        check(metricMin != null && metricMax != null, "metric bound instance is null");
        check(metricMin.getClass().equals(expectedClass), "metric minimum class mismatch");
        check(metricMax.getClass().equals(expectedClass), "metric maximum class mismatch");
        double[] minimumComponents = extractComponents(metricMin, "metric minimum");
        double[] maximumComponents = extractComponents(metricMax, "metric maximum");
        for (int i = 0; i < minimumComponents.length; i++) {
            assertBits(+0.0d, minimumComponents[i], "metric minimum component " + i);
            assertBits(1.0d, maximumComponents[i], "metric maximum component " + i);
        }

        double highestTypedTotal = highestCandidate.relativeTo(metricMin, metricMax);
        double lowestTypedTotal = lowestCandidate.relativeTo(metricMin, metricMax);
        assertFiniteUnit(highestTypedTotal, "highest typed total");
        assertFiniteUnit(lowestTypedTotal, "lowest typed total");

        double foldedMin = aggregate(minimumComponents, weights);
        double foldedMax = aggregate(maximumComponents, weights);
        double foldedHighestScore = aggregate(highestComponents, weights);
        double foldedLowestScore = aggregate(lowestComponents, weights);
        double foldedHighestTotal =
            (foldedHighestScore - foldedMin) / (foldedMax - foldedMin);
        double foldedLowestTotal =
            (foldedLowestScore - foldedMin) / (foldedMax - foldedMin);

        assertBits(+0.0d, foldedMin, "source-identical folded minimum");
        assertBits(1.0d, foldedMax, "source-identical folded maximum");
        assertFiniteUnit(foldedHighestScore, "folded highest score");
        assertFiniteUnit(foldedLowestScore, "folded lowest score");
        assertFiniteUnit(foldedHighestTotal, "folded highest total");
        assertFiniteUnit(foldedLowestTotal, "folded lowest total");
        assertBits(highestTypedTotal, foldedHighestTotal,
                   "highest typed/source-identical total");
        assertBits(lowestTypedTotal, foldedLowestTotal,
                   "lowest typed/source-identical total");
        assertBits(highestTypedTotal, lowestTypedTotal,
                   "highest/lowest typed totals");
        assertBits(foldedHighestScore, foldedLowestScore,
                   "highest/lowest folded scores");
        assertBits(foldedHighestTotal, foldedLowestTotal,
                   "highest/lowest folded totals");


        InformationLoss<?> score = highestCandidate;
        double[] components = highestComponents.clone();
        double lossTotal = highestTypedTotal;
        InformationLoss<?> equalityWitness = lowestCandidate;
        double equalityWitnessTotal = lowestTypedTotal;
        check(score != null && equalityWitness != null, "authoritative score assignment failed");

        LinkedHashMap<String, Double> byName = new LinkedHashMap<String, Double>();
        for (int i = 0; i < actualOrder.length; i++) {
            check(byName.put(actualOrder[i], Double.valueOf(components[i])) == null,
                  "duplicate loss component name " + actualOrder[i]);
        }
        check(byName.keySet().equals(new LinkedHashSet<String>(EXPECTED_ARX_DIMENSION_ORDER)),
              "named loss component bridge is incomplete");
        for (String qi : COMPARISON_QI_ORDER) {
            check(byName.containsKey(qi), "named loss component missing for " + qi);
        }

        return new LossEvidence(highestComponents, lowestComponents,
                                minimumComponents, maximumComponents, weights,
                                foldedMin, foldedMax, foldedHighestScore,
                                foldedLowestScore, foldedHighestTotal,
                                foldedLowestTotal, lossTotal,
                                equalityWitnessTotal, byName);
    }


    private static double aggregate(double[] values, double[] weights) {
        check(values.length == weights.length, "aggregate array length mismatch");
        double result = 0d;
        for (int i = 0; i < values.length; i++) {
            result += (values[i] / (double) values.length) * weights[i];
        }
        return result;
    }

    private static double[] extractComponents(InformationLoss<?> candidate, String label) {
        AbstractILMultiDimensional multidimensional =
            (AbstractILMultiDimensional) candidate;
        double[] values = multidimensional.getValue().clone();
        assertEquals(8, values.length, label + " component count");
        for (int i = 0; i < values.length; i++) {
            assertFiniteUnit(values[i], label + " component " + i);
        }
        return values;
    }

    private static MaterializedOutput materializeOutput(DataHandle output,
                                                         boolean rawVariant,
                                                         int ageLevel,
                                                         AgeMapping mapping) {
        List<String[]> rows = new ArrayList<String[]>(output.getNumRows());
        List<Integer> outlierIndices = new ArrayList<Integer>();
        for (int rowIndex = 0; rowIndex < output.getNumRows(); rowIndex++) {
            if (output.isOutlier(rowIndex)) {
                outlierIndices.add(Integer.valueOf(rowIndex));
            }
            String[] row = new String[PHYSICAL_SCHEMA.size()];
            for (int columnIndex = 0; columnIndex < row.length; columnIndex++) {
                String value = output.getValue(rowIndex, columnIndex);
                check(value != null, "null output value at row " + rowIndex +
                      ", column " + columnIndex);
                rejectTsvControl(value, "output value at row " + rowIndex +
                                 ", column " + columnIndex);
                row[columnIndex] = value;
            }
            mapping.validateOutputAge(row[1], ageLevel, rawVariant);
            rows.add(row);
        }
        return new MaterializedOutput(rows, outlierIndices);
    }

    private static ValidatorEvidence computeValidators(List<String[]> rows,
                                                       List<Integer> outlierRowIndices) {
        assertEquals(EXPECTED_ROWS, rows.size(), "materialized output row count");
        assertEquals(0, outlierRowIndices.size(), "CFG02 outlier count");

        int[] qiIndices = indices(PHYSICAL_SCHEMA, COMPARISON_QI_ORDER);
        int[] fullIndices = indices(PHYSICAL_SCHEMA, PHYSICAL_SCHEMA);
        Map<List<String>, Integer> qiClasses = countKeys(rows, qiIndices);
        Map<List<String>, Integer> fullClasses = countKeys(rows, fullIndices);

        int classSizeSum = 0;
        int kHat = Integer.MAX_VALUE;
        int uniqueQiRows = 0;
        List<Integer> sortedClassSizes = new ArrayList<Integer>(qiClasses.values());
        Collections.sort(sortedClassSizes);
        for (Integer size : qiClasses.values()) {
            int value = size.intValue();
            classSizeSum += value;
            kHat = Math.min(kHat, value);
            if (value == 1) {
                uniqueQiRows += value;
            }
        }
        int uniqueFullRows = 0;
        for (Integer size : fullClasses.values()) {
            if (size.intValue() == 1) {
                uniqueFullRows += 1;
            }
        }
        check(kHat != Integer.MAX_VALUE, "no equivalence classes were constructed");
        assertEquals(rows.size(), classSizeSum, "equivalence-class size sum");
        check(kHat >= K, "empirical k_hat is below 5: " + kHat);
        assertEquals(0, uniqueQiRows, "U_QI unique-row numerator");

        Map<String, Integer> salaryCounts = countColumn(rows, 8);
        assertSalaryCounts(salaryCounts, "output");
        double uQi = ((double) uniqueQiRows) / ((double) rows.size());
        double uFull = ((double) uniqueFullRows) / ((double) rows.size());
        assertBits(+0.0d, uQi, "U_QI");
        assertFiniteUnit(uFull, "U_full");
        int classCount = sortedClassSizes.size();
        int medianNumerator;
        int medianDenominator;
        if ((classCount & 1) == 1) {
            medianNumerator = sortedClassSizes.get(classCount / 2).intValue();
            medianDenominator = 1;
        } else {
            medianNumerator = sortedClassSizes.get(classCount / 2 - 1).intValue() +
                              sortedClassSizes.get(classCount / 2).intValue();
            medianDenominator = 2;
        }
        int p95Rank = (95 * classCount + 99) / 100;
        check(p95Rank >= 1 && p95Rank <= classCount, "invalid EC p95 nearest rank");
        int p95 = sortedClassSizes.get(p95Rank - 1).intValue();
        int maximum = sortedClassSizes.get(classCount - 1).intValue();
        return new ValidatorEvidence(rows.size(), rows.size(), outlierRowIndices.size(),
                                     qiClasses.size(), classSizeSum, kHat,
                                     uniqueQiRows, uQi, fullClasses.size(),
                                     uniqueFullRows, uFull, salaryCounts,
                                     medianNumerator, medianDenominator, p95, maximum);
    }

    private static void validateRows(List<String[]> rows, List<Integer> outlierRows) {
        assertEquals(EXPECTED_ROWS, rows.size(), "retained physical row count");
        assertEquals(0, outlierRows.size(), "outlier count before serialization");
        for (int i = 0; i < rows.size(); i++) {
            String[] row = rows.get(i);
            assertEquals(PHYSICAL_SCHEMA.size(), row.length,
                         "physical field count at row " + i);
            for (int j = 0; j < row.length; j++) {
                check(row[j] != null, "null physical field at row " + i + ", column " + j);
                rejectTsvControl(row[j], "physical field at row " + i + ", column " + j);
            }
        }
    }

    private static byte[] serializeRows(List<String[]> physicalRows,
                                        List<String> targetSchema,
                                        AgeMapping mapping,
                                        int ageMode) {
        int[] targetIndices = indices(PHYSICAL_SCHEMA, targetSchema);
        ByteArrayOutputStream output = new ByteArrayOutputStream(3000000);
        writeTsvRow(output, targetSchema.toArray(new String[0]));
        for (String[] physicalRow : physicalRows) {
            String[] row = new String[targetSchema.size()];
            for (int i = 0; i < targetIndices.length; i++) {
                String value = physicalRow[targetIndices[i]];
                if (mapping != null && "age".equals(targetSchema.get(i))) {
                    if (ageMode >= 0) {
                        value = mapping.normalizeRaw(value, ageMode);
                    } else {
                        int semanticLevel = -ageMode - 1;
                        mapping.validateOutputAge(value, semanticLevel, false);
                    }
                }
                row[i] = value;
            }
            writeTsvRow(output, row);
        }
        return output.toByteArray();
    }

    private static void writeTsvRow(ByteArrayOutputStream output, String[] fields) {
        for (int i = 0; i < fields.length; i++) {
            String value = fields[i];
            check(value != null, "null TSV field");
            rejectTsvControl(value, "TSV field");
            if (i != 0) {
                output.write('\t');
            }
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            output.write(bytes, 0, bytes.length);
        }
        output.write('\n');
    }

    private static LinkedHashMap<String, Object> buildReport(
            String runId,
            String variant,
            List<ResolvedHierarchy> hierarchies,
            List<String> actualOrder,
            int[] rawTransformation,
            Map<String, Integer> transformationByName,
            LossEvidence loss,
            ValidatorEvidence validators,
            String outputFilename,
            int outputBytes,
            String outputSha256,
            String reportFilename,
            int canonicalBytes,
            String canonicalSha256,
            List<Integer> outlierRowIndices,
            GeneratedArtifactIdentity matrixTestReport,
            ArxConfigurationMatrix.AssertionReceipt preparationReceipt,
            ArxConfigurationMatrix.AssertionReceipt immediateReceipt,
            ArxConfigurationMatrix.AssertionReceipt effectiveReceipt) {

        LinkedHashMap<String, Object> root = object();
        root.put("report_schema", REPORT_SCHEMA);
        root.put("status", "PASS");
        root.put("run_id", runId);
        root.put("config_id", CONFIG_ID);
        root.put("age_hierarchy_variant", variant);
        root.put("main_runs_authorized", Boolean.FALSE);
        root.put("pre_anonymization_assertions",
                 preAnonymizationAssertions(immediateReceipt));
        root.put("runtime_assertions", runtimeAssertions());
        LinkedHashMap<String, Object> receiptReport = object();
        receiptReport.put("preparation", assertionReceipt(preparationReceipt));
        receiptReport.put("immediate_pre_anonymization",
                          assertionReceipt(immediateReceipt));
        receiptReport.put("effective", assertionReceipt(effectiveReceipt));
        root.put("configuration_assertion_receipts", receiptReport);

        LinkedHashMap<String, Object> provenance = object();
        provenance.put("effective_protocol_version", "v1.2.3");
        provenance.put("effective_protocol_control_commit",
                       "70c42273dfa1b2e2f53f4612057c601f70e83181");
        provenance.put("effective_protocol_manifest", fileReport(EFFECTIVE_MANIFEST));
        provenance.put("cfg_matrix_manifest", fileReport(CFG_MATRIX_MANIFEST));
        provenance.put("cfg_matrix_test_report", generatedFileReport(matrixTestReport));
        provenance.put("arx_version", "3.9.2");
        provenance.put("arx_jar", fileReport(ARX_JAR));
        provenance.put("input", fileReport(INPUT));
        provenance.put("age_mapping", fileReport(MAPPING));
        provenance.put("arx_jar_sha256", ARX_JAR.sha256);
        provenance.put("arx_jar_bytes", Long.valueOf(ARX_JAR.bytes));
        provenance.put("input_sha256", INPUT.sha256);
        provenance.put("raw_age_hierarchy_sha256", findHierarchy("age").sha256);
        provenance.put("semantic_age_hierarchy_sha256", SEMANTIC_AGE.sha256);
        provenance.put("age_mapping_sha256", MAPPING.sha256);
        provenance.put("effective_protocol_manifest_sha256", EFFECTIVE_MANIFEST.sha256);
        provenance.put("cfg_matrix_manifest_sha256", CFG_MATRIX_MANIFEST.sha256);
        provenance.put("cfg_matrix_test_report_sha256", matrixTestReport.sha256);
        HierarchySpec usedAge = "raw".equals(variant) ? findHierarchy("age") : SEMANTIC_AGE;
        provenance.put("age_hierarchy_used_sha256", usedAge.sha256);
        provenance.put("age_hierarchy_used_relative_path", usedAge.relativePath);

        List<Object> inputArtifacts = new ArrayList<Object>();
        inputArtifacts.add(inputArtifact("effective_protocol_manifest", null,
                                         EFFECTIVE_MANIFEST));
        inputArtifacts.add(inputArtifact("cfg_matrix_manifest", null,
                                         CFG_MATRIX_MANIFEST));
        inputArtifacts.add(inputArtifact("arx_jar", null, ARX_JAR));
        inputArtifacts.add(inputArtifact("adult_input", null, INPUT));
        inputArtifacts.add(inputArtifact("raw_age_hierarchy", "age", findHierarchy("age")));
        inputArtifacts.add(inputArtifact("semantic_age_hierarchy", "age", SEMANTIC_AGE));
        inputArtifacts.add(inputArtifact("age_mapping", "age", MAPPING));
        for (HierarchySpec spec : HIERARCHIES) {
            if (!"age".equals(spec.qi)) {
                inputArtifacts.add(inputArtifact("non_age_hierarchy", spec.qi, spec));
            }
        }
        provenance.put("input_artifacts", inputArtifacts);

        List<Object> nonAgeHierarchyReports = new ArrayList<Object>();
        for (HierarchySpec spec : HIERARCHIES) {
            if (!"age".equals(spec.qi)) {
                LinkedHashMap<String, Object> item = object();
                item.put("qi", spec.qi);
                item.put("relative_path", spec.relativePath);
                item.put("bytes", Long.valueOf(spec.bytes));
                item.put("sha256", spec.sha256);
                nonAgeHierarchyReports.add(item);
            }
        }
        provenance.put("non_age_hierarchies", nonAgeHierarchyReports);
        List<Object> hierarchyReports = new ArrayList<Object>();
        for (ResolvedHierarchy hierarchy : hierarchies) {
            LinkedHashMap<String, Object> item = fileReport(hierarchy.spec);
            item.put("qi", hierarchy.spec.qi);
            item.put("rows", Integer.valueOf(hierarchy.table.length));
            item.put("levels_including_leaf",
                     Integer.valueOf(hierarchy.spec.maxGeneralization + 1));
            item.put("minimum_generalization", Integer.valueOf(0));
            item.put("maximum_generalization",
                     Integer.valueOf(hierarchy.spec.maxGeneralization));
            hierarchyReports.add(item);
        }
        provenance.put("hierarchies", hierarchyReports);
        root.put("provenance", provenance);

        LinkedHashMap<String, Object> config = object();
        config.put("family", "k-only");
        config.put("k", Integer.valueOf(K));
        config.put("privacy_models", immutable("KAnonymity(5)"));
        config.put("suppression_limit", doubleValue(0.0d));
        config.put("suppression_limit_decimal", "0.0");
        config.put("suppression_always_enabled", Boolean.TRUE);
        config.put("suppressed_attribute_types",
                   immutable("QUASI_IDENTIFYING_ATTRIBUTE"));
        config.put("algorithm", "OPTIMAL");
        config.put("heuristic_search_threshold", Integer.valueOf(Integer.MAX_VALUE));
        config.put("practical_monotonicity", Boolean.FALSE);
        config.put("salary_class_internal_type", "INSENSITIVE_ATTRIBUTE");
        config.put("salary_class_attribute_type", "INSENSITIVE_ATTRIBUTE");
        config.put("l_or_t_model_present", Boolean.FALSE);
        config.put("quality_model_class", MetricMDNMLoss.class.getName());
        config.put("quality_model",
                   "Loss(generalization-suppression,gs-factor=0.5,aggregate-function=arithmetic-mean)");
        config.put("quality_model_factory",
                   "Metric.createLossMetric(0.5d, ARITHMETIC_MEAN)");
        config.put("gs_factor", doubleValue(0.5d));
        config.put("aggregate_function", "ARITHMETIC_MEAN");
        config.put("attribute_weights_arx_order",
                   namedDoubleArray(EXPECTED_ARX_DIMENSION_ORDER,
                                    allOnes(EXPECTED_ARX_DIMENSION_ORDER.size())));
        config.put("microaggregation_qis", Collections.emptyList());
        config.put("local_recoding_invoked", Boolean.FALSE);
        config.put("local_recoding_applied", Boolean.FALSE);
        config.put("state_reused", Boolean.FALSE);
        config.put("generic_cfg_builder_used", Boolean.TRUE);
        config.put("mapper_verified_before_anonymize", Boolean.TRUE);
        config.put("configuration_fingerprint", immediateReceipt.fingerprint());
        config.put("pre_anonymization_assertions",
                   preAnonymizationAssertions(immediateReceipt));
        root.put("configuration", config);

        root.put("expected_arx_dimension_order", EXPECTED_ARX_DIMENSION_ORDER);
        root.put("actual_arx_dimension_order", actualOrder);
        root.put("comparison_qi_order", COMPARISON_QI_ORDER);
        root.put("raw_transformation", intList(rawTransformation));
        root.put("transformation_by_qi",
                 namedIntegerList(COMPARISON_QI_ORDER, transformationByName));

        LinkedHashMap<String, Object> lossReport = object();
        lossReport.put("information_loss_class",
                       ILMultiDimensionalArithmeticMean.class.getName());
        lossReport.put("metric_min_components_arx_order",
                       namedDoubleArray(actualOrder, loss.minimumComponents));
        lossReport.put("metric_max_components_arx_order",
                       namedDoubleArray(actualOrder, loss.maximumComponents));
        lossReport.put("weights_arx_order",
                       namedDoubleArray(actualOrder, loss.weights));
        lossReport.put("highest_components_arx_order",
                       namedDoubleArray(actualOrder, loss.highestComponents));
        lossReport.put("lowest_components_arx_order",
                       namedDoubleArray(actualOrder, loss.lowestComponents));
        lossReport.put("folded_min", doubleValue(loss.foldedMin));
        lossReport.put("folded_max", doubleValue(loss.foldedMax));
        lossReport.put("folded_highest_score", doubleValue(loss.foldedHighestScore));
        lossReport.put("folded_lowest_score", doubleValue(loss.foldedLowestScore));
        lossReport.put("folded_highest_total", doubleValue(loss.foldedHighestTotal));
        lossReport.put("folded_lowest_total", doubleValue(loss.foldedLowestTotal));
        lossReport.put("authoritative_source", "node.getHighestScore()");
        lossReport.put("loss_total", doubleValue(loss.lossTotal));
        lossReport.put("equality_witness_source", "node.getLowestScore()");
        lossReport.put("equality_witness_total", doubleValue(loss.equalityWitnessTotal));
        lossReport.put("loss_by_qi",
                       namedDoubleMap(COMPARISON_QI_ORDER, loss.componentsByName));
        lossReport.put("component_count", Integer.valueOf(8));
        lossReport.put("all_exact_assertions_passed", Boolean.TRUE);
        root.put("loss", lossReport);

        LinkedHashMap<String, Object> validatorReport = object();
        validatorReport.put("n_input", Integer.valueOf(EXPECTED_ROWS));
        validatorReport.put("n_output_rows", Integer.valueOf(validators.nOutput));
        validatorReport.put("n_retained", Integer.valueOf(validators.nRetained));
        validatorReport.put("outliers", Integer.valueOf(validators.outliers));
        validatorReport.put("outlier_row_indices", new ArrayList<Integer>(outlierRowIndices));
        validatorReport.put("equivalence_class_count",
                            Integer.valueOf(validators.equivalenceClassCount));
        validatorReport.put("equivalence_class_size_sum",
                            Integer.valueOf(validators.equivalenceClassSizeSum));
        LinkedHashMap<String, Object> ecDiagnostics = object();
        ecDiagnostics.put("count", Integer.valueOf(validators.equivalenceClassCount));
        ecDiagnostics.put("min", Integer.valueOf(validators.kHat));
        LinkedHashMap<String, Object> median = object();
        median.put("numerator", Integer.valueOf(validators.ecMedianNumerator));
        median.put("denominator", Integer.valueOf(validators.ecMedianDenominator));
        ecDiagnostics.put("median", median);
        ecDiagnostics.put("p95_nearest_rank", Integer.valueOf(validators.ecP95NearestRank));
        ecDiagnostics.put("max", Integer.valueOf(validators.ecMaximum));
        ecDiagnostics.put("p95_definition", "nearest-rank ceil(0.95*m)");
        validatorReport.put("equivalence_class_diagnostics", ecDiagnostics);
        validatorReport.put("k_hat", Integer.valueOf(validators.kHat));
        validatorReport.put("u_qi_unique_rows", Integer.valueOf(validators.uQiUniqueRows));
        validatorReport.put("u_qi_decimal", Double.valueOf(validators.uQi));
        LinkedHashMap<String, Object> uQi = object();
        uQi.put("numerator", Integer.valueOf(validators.uQiUniqueRows));
        uQi.put("denominator", Integer.valueOf(validators.nRetained));
        uQi.put("decimal", Double.valueOf(validators.uQi));
        validatorReport.put("u_qi", uQi);
        validatorReport.put("u_full_class_count", Integer.valueOf(validators.uFullClassCount));
        validatorReport.put("u_full_unique_rows", Integer.valueOf(validators.uFullUniqueRows));
        validatorReport.put("u_full_decimal", Double.valueOf(validators.uFull));
        LinkedHashMap<String, Object> uFull = object();
        uFull.put("numerator", Integer.valueOf(validators.uFullUniqueRows));
        uFull.put("denominator", Integer.valueOf(validators.nRetained));
        uFull.put("decimal", Double.valueOf(validators.uFull));
        validatorReport.put("u_full", uFull);
        List<Object> salary = new ArrayList<Object>();
        salary.add(valueCount("<=50K", required(validators.salaryCounts, "<=50K")));
        salary.add(valueCount(">50K", required(validators.salaryCounts, ">50K")));
        validatorReport.put("salary_class_counts", salary);
        validatorReport.put("schema", PHYSICAL_SCHEMA);
        validatorReport.put("physical_schema", PHYSICAL_SCHEMA);
        validatorReport.put("canonical_semantic_schema", CANONICAL_SCHEMA);
        validatorReport.put("all_assertions_passed", Boolean.TRUE);
        root.put("validators", validatorReport);

        root.put("output_file_sha256", outputSha256);
        root.put("canonical_semantic_sha256", canonicalSha256);
        LinkedHashMap<String, Object> artifacts = object();
        LinkedHashMap<String, Object> outputArtifact = object();
        outputArtifact.put("filename", outputFilename);
        outputArtifact.put("bytes", Integer.valueOf(outputBytes));
        outputArtifact.put("sha256", outputSha256);
        outputArtifact.put("format",
            "TSV; UTF-8 without BOM; LF with final LF; no quoting; physical schema");
        artifacts.put("output", outputArtifact);
        LinkedHashMap<String, Object> canonicalArtifact = object();
        canonicalArtifact.put("published", Boolean.FALSE);
        canonicalArtifact.put("bytes", Integer.valueOf(canonicalBytes));
        canonicalArtifact.put("sha256", canonicalSha256);
        canonicalArtifact.put("format",
            "TSV; UTF-8 without BOM; LF with final LF; no quoting; semantic age labels");
        artifacts.put("canonical_semantic", canonicalArtifact);
        artifacts.put("report_filename", reportFilename);
        root.put("artifacts", artifacts);

        LinkedHashMap<String, Object> runtime = object();
        runtime.put("java_version", safeProperty("java.version"));
        runtime.put("java_vendor", safeProperty("java.vendor"));
        runtime.put("os_name", safeProperty("os.name"));
        runtime.put("os_arch", safeProperty("os.arch"));
        runtime.put("arx_loaded_from_expected_jar", Boolean.TRUE);
        runtime.put("one_run_per_process", Boolean.TRUE);
        runtime.put("runtime_assertions", runtimeAssertions());
        root.put("runtime", runtime);

        LinkedHashMap<String, Object> scope = object();
        scope.put("single_run_result", "PASS");
        scope.put("compatibility_oracle_gate_result", "NOT_EVALUATED_BY_SINGLE_RUN");
        scope.put("gate_a_status", "pending");
        scope.put("main_runs_authorized", Boolean.FALSE);
        root.put("scope", scope);
        return root;
    }

    private static List<Object> namedDoubleArray(List<String> names, double[] values) {
        assertEquals(names.size(), values.length, "named double-array length");
        List<Object> result = new ArrayList<Object>();
        for (int i = 0; i < names.size(); i++) {
            LinkedHashMap<String, Object> item = object();
            item.put("qi", names.get(i));
            item.put("value", doubleValue(values[i]));
            result.add(item);
        }
        return result;
    }

    private static List<Object> namedDoubleMap(List<String> names, Map<String, Double> values) {
        List<Object> result = new ArrayList<Object>();
        for (String name : names) {
            Double value = values.get(name);
            check(value != null, "missing named double for " + name);
            LinkedHashMap<String, Object> item = object();
            item.put("qi", name);
            item.put("value", doubleValue(value.doubleValue()));
            result.add(item);
        }
        return result;
    }

    private static List<Object> namedIntegerList(List<String> names,
                                                  Map<String, Integer> values) {
        List<Object> result = new ArrayList<Object>();
        for (String name : names) {
            Integer value = values.get(name);
            check(value != null, "missing named integer for " + name);
            LinkedHashMap<String, Object> item = object();
            item.put("qi", name);
            item.put("level", value);
            result.add(item);
        }
        return result;
    }

    private static LinkedHashMap<String, Object> doubleValue(double value) {
        check(Double.isFinite(value), "non-finite double cannot be reported");
        LinkedHashMap<String, Object> result = object();
        result.put("decimal", Double.toString(value));
        result.put("hex", Double.toHexString(value));
        result.put("bits_hex", bitsHex(value));
        return result;
    }

    private static List<Integer> intList(int[] values) {
        List<Integer> result = new ArrayList<Integer>(values.length);
        for (int value : values) {
            result.add(Integer.valueOf(value));
        }
        return result;
    }

    private static double[] allOnes(int count) {
        double[] result = new double[count];
        Arrays.fill(result, 1.0d);
        return result;
    }

    private static LinkedHashMap<String, Object> fileReport(FileSpec spec) {
        LinkedHashMap<String, Object> result = object();
        result.put("relative_path", spec.relativePath);
        result.put("bytes", Long.valueOf(spec.bytes));
        result.put("sha256", spec.sha256);
        return result;
    }

    private static LinkedHashMap<String, Object> generatedFileReport(
            GeneratedArtifactIdentity identity) {
        LinkedHashMap<String, Object> result = object();
        result.put("filename", identity.filename);
        result.put("bytes", Long.valueOf(identity.bytes));
        result.put("sha256", identity.sha256);
        return result;
    }

    private static LinkedHashMap<String, Object> assertionReceipt(
            ArxConfigurationMatrix.AssertionReceipt receipt) {
        check(receipt != null && receipt.allPassed(),
              "configuration assertion receipt is absent or incomplete");
        LinkedHashMap<String, Object> result = object();
        result.put("phase", receipt.phase());
        result.put("config_id", receipt.specification().id());
        result.put("family", receipt.specification().family().token());
        result.put("manifest_relative_path", ArxConfigurationMatrix.MANIFEST_RELATIVE_PATH);
        result.put("manifest_bytes", Long.valueOf(receipt.manifestBytes()));
        result.put("manifest_sha256", receipt.manifestSha256());
        result.put("configuration_fingerprint", receipt.fingerprint());
        result.put("passed_assertions",
                   new ArrayList<String>(receipt.passedAssertions()));
        result.put("assertion_count",
                   Integer.valueOf(receipt.passedAssertions().size()));
        result.put("all_passed", Boolean.TRUE);
        return result;
    }

    private static LinkedHashMap<String, Object> inputArtifact(String role,
                                                                String qi,
                                                                FileSpec spec) {
        LinkedHashMap<String, Object> result = object();
        result.put("role", role);
        result.put("qi", qi);
        result.put("relative_path", spec.relativePath);
        result.put("bytes", Long.valueOf(spec.bytes));
        result.put("sha256", spec.sha256);
        return result;
    }

    private static LinkedHashMap<String, Object> valueCount(String value, int count) {
        LinkedHashMap<String, Object> result = object();
        result.put("value", value);
        result.put("count", Integer.valueOf(count));
        return result;
    }

    private static LinkedHashMap<String, Object> preAnonymizationAssertions(
            ArxConfigurationMatrix.AssertionReceipt receipt) {
        check(receipt != null && receipt.allPassed(),
              "immediate pre-anonymization receipt did not pass");
        LinkedHashMap<String, Object> result = object();
        result.put("physical_schema_exact", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_RELEASE_SCHEMA")));
        result.put("input_row_count_30162", Boolean.TRUE);
        result.put("input_artifact_identities_exact", Boolean.TRUE);
        result.put("exactly_eight_hierarchy_qis", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_QI_SET")));
        result.put("salary_class_not_qi", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_SALARY_NOT_QI")));
        result.put("exactly_one_k_anonymity_5", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_PRIVACY_MODEL_SET_CLASS_TARGET_VALUE")));
        result.put("salary_class_insensitive_attribute", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_SALARY_TYPE_AND_ATTRIBUTE_SETS")));
        result.put("no_l_or_t_privacy_model", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_PRIVACY_MODEL_SET_CLASS_TARGET_VALUE")));
        result.put("salary_class_no_hierarchy", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_SALARY_NO_HIERARCHY_OR_MICROAGGREGATION")));
        result.put("salary_class_not_generalized", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_SALARY_NO_HIERARCHY_OR_MICROAGGREGATION")));
        result.put("salary_class_in_release_schema", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_RELEASE_SCHEMA")));
        result.put("suppression_limit_positive_zero", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_SUPPRESSION_POLICY")));
        result.put("suppression_always_enabled", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_SUPPRESSION_POLICY")));
        result.put("algorithm_optimal", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_ALGORITHM_THRESHOLD_MONOTONICITY")));
        result.put("practical_monotonicity_false", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_ALGORITHM_THRESHOLD_MONOTONICITY")));
        result.put("heuristic_threshold_integer_max", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_ALGORITHM_THRESHOLD_MONOTONICITY")));
        result.put("loss_metric_class_exact", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_METRIC_EXACT")));
        result.put("loss_gs_factor_0_5_bits", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_METRIC_EXACT")));
        result.put("loss_aggregate_arithmetic_mean", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_METRIC_EXACT")));
        result.put("eight_qi_weights_1_bits", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_WEIGHT_SET_AND_VALUES")));
        result.put("microaggregation_empty", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_MICROAGGREGATION")));
        result.put("hierarchy_bounds_exact", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_HIERARCHY_SET_CONTENT_BOUNDS")));
        result.put("transformation_space_6480", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_TRANSFORMATION_SPACE")));
        result.put("fresh_objects_one_run_process", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_STATE_FRESH_DATA_DEFINITION") &&
            receipt.contains("CFG_ASSERT_STATE_FRESH_CONFIGURATION_CRITERIA")));
        result.put("state_reuse_false", Boolean.valueOf(
            receipt.contains("CFG_ASSERT_STATE_FRESH_DATA_DEFINITION") &&
            receipt.contains("CFG_ASSERT_STATE_FRESH_CONFIGURATION_CRITERIA")));
        check(!result.containsValue(Boolean.FALSE),
              "legacy assertion adapter observed a missing receipt code");
        return result;
    }

    private static LinkedHashMap<String, Object> runtimeAssertions() {
        LinkedHashMap<String, Object> result = object();
        result.put("result_available", Boolean.TRUE);
        result.put("optimum_found", Boolean.TRUE);
        result.put("global_optimum_nonnull", Boolean.TRUE);
        result.put("global_optimum_checked", Boolean.TRUE);
        result.put("global_optimum_anonymous", Boolean.TRUE);
        result.put("local_recoding_not_invoked", Boolean.TRUE);
        result.put("output_not_optimized", Boolean.TRUE);
        result.put("microaggregation_empty", Boolean.TRUE);
        result.put("score_candidates_nonnull", Boolean.TRUE);
        result.put("score_concrete_class_exact", Boolean.TRUE);
        result.put("actual_order_exact", Boolean.TRUE);
        result.put("dimension_names_unique_complete", Boolean.TRUE);
        result.put("dimension_forward_bijection", Boolean.TRUE);
        result.put("dimension_inverse_bijection", Boolean.TRUE);
        result.put("raw_transformation_length", Boolean.TRUE);
        result.put("raw_transformation_matches_node", Boolean.TRUE);
        result.put("transformation_bounds", Boolean.TRUE);
        result.put("candidate_component_lengths", Boolean.TRUE);
        result.put("candidate_components_finite_unit", Boolean.TRUE);
        result.put("highest_lowest_component_bits_equal", Boolean.TRUE);
        result.put("effective_metric_exact", Boolean.TRUE);
        result.put("weights_one_bits", Boolean.TRUE);
        result.put("metric_bounds_exact_class_length", Boolean.TRUE);
        result.put("metric_min_positive_zero_bits", Boolean.TRUE);
        result.put("metric_max_one_bits", Boolean.TRUE);
        result.put("typed_totals_finite_unit", Boolean.TRUE);
        result.put("source_identical_fold_bits", Boolean.TRUE);
        result.put("highest_lowest_total_bits_equal", Boolean.TRUE);
        result.put("named_loss_bridge_complete", Boolean.TRUE);
        result.put("authoritative_assignment_after_assertions", Boolean.TRUE);
        result.put("output_schema_exact", Boolean.TRUE);
        result.put("output_rows_30162", Boolean.TRUE);
        result.put("outliers_zero", Boolean.TRUE);
        result.put("canonical_serialization_exact", Boolean.TRUE);
        result.put("validators_passed", Boolean.TRUE);
        return result;
    }

    private static void verifyLoadedArxJar(Path expectedJar) throws Exception {
        URI location = ARXAnonymizer.class.getProtectionDomain().getCodeSource().getLocation().toURI();
        Path loaded = Paths.get(location).toRealPath();
        Path expected = expectedJar.toRealPath();
        check(Files.isSameFile(loaded, expected),
              "ARX classes were not loaded from the pinned repository JAR");
    }

    private static void verifyFile(Path root, FileSpec spec) throws IOException {
        Path path = root.resolve(spec.relativePath).normalize();
        check(path.startsWith(root), "relative path escapes repository: " + spec.relativePath);
        check(Files.isRegularFile(path), "required file missing: " + spec.relativePath);
        assertEquals(spec.bytes, Files.size(path), "byte length of " + spec.relativePath);
        String actual = sha256(Files.readAllBytes(path));
        check(spec.sha256.equals(actual), "SHA-256 mismatch for " + spec.relativePath);
    }

    private static GeneratedArtifactIdentity verifyMatrixTestReport(
            Path report, Path runDirectory) throws IOException {
        Path normalizedReport = report.toAbsolutePath().normalize();
        Path expected = runDirectory.toAbsolutePath().normalize()
            .resolve("cfg_matrix_test_report.json").normalize();
        check(normalizedReport.equals(expected),
              "matrix-test report must be cfg_matrix_test_report.json in run-dir");
        check(Files.isRegularFile(normalizedReport),
              "matrix-test report is missing or not a regular file");
        long beforeBytes = Files.size(normalizedReport);
        byte[] bytes = Files.readAllBytes(normalizedReport);
        long afterBytes = Files.size(normalizedReport);
        check(beforeBytes > 0L && beforeBytes == afterBytes &&
              beforeBytes == bytes.length,
              "matrix-test report changed while it was read");
        check(!(bytes.length >= 3 && (bytes[0] & 0xff) == 0xef &&
                (bytes[1] & 0xff) == 0xbb && (bytes[2] & 0xff) == 0xbf),
              "matrix-test report has a UTF-8 BOM");
        for (byte value : bytes) {
            check(value != '\r' && value != 0,
                  "matrix-test report contains CR or NUL");
        }
        check(bytes[bytes.length - 1] == '\n',
              "matrix-test report lacks final LF");
        String text = new String(bytes, StandardCharsets.UTF_8);
        check(Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8)),
              "matrix-test report is not strict UTF-8");
        check(text.contains("\"report_schema\": \"arx-cfg-matrix-tests-v1.2.3/1.0\"") &&
              text.contains("\"status\": \"PASS\""),
              "matrix-test report lacks the expected schema or PASS marker");
        return new GeneratedArtifactIdentity(
            normalizedReport.getFileName().toString(), bytes.length, sha256(bytes));
    }

    private static Map<String, String[][]> expectedHierarchyMap(
            List<ResolvedHierarchy> hierarchies) {
        LinkedHashMap<String, String[][]> result =
            new LinkedHashMap<String, String[][]>();
        for (ResolvedHierarchy hierarchy : hierarchies) {
            check(result.put(hierarchy.spec.qi, hierarchy.table) == null,
                  "duplicate resolved hierarchy for " + hierarchy.spec.qi);
        }
        check(result.keySet().equals(new HashSet<String>(EXPECTED_ARX_DIMENSION_ORDER)),
              "resolved hierarchy set differs from the eight QIs");
        return Collections.unmodifiableMap(result);
    }

    private static void validateTransformationSpace(List<ResolvedHierarchy> hierarchies) {
        int product = 1;
        for (ResolvedHierarchy hierarchy : hierarchies) {
            assertEquals(hierarchy.spec.maxGeneralization + 1,
                         hierarchy.table[0].length,
                         "hierarchy height for " + hierarchy.spec.qi);
            product *= hierarchy.spec.maxGeneralization + 1;
        }
        assertEquals(6480, product, "transformation-space size");
    }

    private static void validateAgePartitionShape(String[][] table, String label) {
        int[] expectedDistinct = new int[] {100, 20, 10, 5, 1};
        for (int row = 0; row < table.length; row++) {
            assertEquals(Integer.toString(row + 1), table[row][0],
                         label + " age leaf at row " + row);
        }
        for (int level = 0; level < 5; level++) {
            Set<String> nodes = new LinkedHashSet<String>();
            for (String[] row : table) {
                nodes.add(row[level]);
            }
            assertEquals(expectedDistinct[level], nodes.size(),
                         label + " distinct age nodes at level " + level);
        }
        for (String[] row : table) {
            check("*".equals(row[4]), label + " age root is not '*'");
        }
    }

    private static String[][] readStrictHierarchy(Path path, int expectedColumns) throws IOException {
        byte[] bytes = Files.readAllBytes(path);
        String text = new String(bytes, StandardCharsets.UTF_8);
        check(!text.startsWith("\ufeff"), "UTF-8 BOM in hierarchy " + path.getFileName());
        check(text.indexOf('\r') < 0, "CR in hierarchy " + path.getFileName());
        String[] lines = text.split("\n", -1);
        int count = lines.length;
        if (count > 0 && lines[count - 1].isEmpty()) {
            count--;
        }
        check(count > 0, "empty hierarchy " + path.getFileName());
        String[][] result = new String[count][];
        for (int i = 0; i < count; i++) {
            check(!lines[i].isEmpty(), "empty hierarchy row " + i + " in " + path.getFileName());
            String[] fields = lines[i].split(";", -1);
            assertEquals(expectedColumns, fields.length,
                         "hierarchy column count at row " + i + " in " + path.getFileName());
            for (String field : fields) {
                check(!field.isEmpty(), "empty hierarchy field in " + path.getFileName());
                check(field.indexOf('"') < 0,
                      "quoted hierarchy field is outside the pinned simple-file contract");
                rejectTsvControl(field, "hierarchy field");
            }
            result[i] = fields;
        }
        return result;
    }

    private static int[] indices(List<String> source, List<String> target) {
        int[] result = new int[target.size()];
        for (int i = 0; i < target.size(); i++) {
            int index = source.indexOf(target.get(i));
            check(index >= 0, "target column missing from source schema: " + target.get(i));
            result[i] = index;
        }
        return result;
    }

    private static Map<List<String>, Integer> countKeys(List<String[]> rows, int[] indices) {
        Map<List<String>, Integer> counts = new LinkedHashMap<List<String>, Integer>();
        for (String[] row : rows) {
            List<String> key = new ArrayList<String>(indices.length);
            for (int index : indices) {
                key.add(row[index]);
            }
            Integer previous = counts.get(key);
            counts.put(key, Integer.valueOf(previous == null ? 1 : previous.intValue() + 1));
        }
        return counts;
    }

    private static Map<String, Integer> countColumn(DataHandle handle, int column) {
        Map<String, Integer> result = new LinkedHashMap<String, Integer>();
        for (int row = 0; row < handle.getNumRows(); row++) {
            increment(result, handle.getValue(row, column));
        }
        return result;
    }

    private static Map<String, Integer> countColumn(List<String[]> rows, int column) {
        Map<String, Integer> result = new LinkedHashMap<String, Integer>();
        for (String[] row : rows) {
            increment(result, row[column]);
        }
        return result;
    }

    private static void increment(Map<String, Integer> counts, String value) {
        Integer previous = counts.get(value);
        counts.put(value, Integer.valueOf(previous == null ? 1 : previous.intValue() + 1));
    }

    private static void assertSalaryCounts(Map<String, Integer> counts, String label) {
        assertEquals(2, counts.size(), label + " salary-class cardinality");
        assertEquals(22654, required(counts, "<=50K").intValue(), label + " <=50K count");
        assertEquals(7508, required(counts, ">50K").intValue(), label + " >50K count");
    }

    private static void assertSchema(DataHandle handle, List<String> expected, String label) {
        assertEquals(expected.size(), handle.getNumColumns(), label + " column count");
        for (int i = 0; i < expected.size(); i++) {
            assertEquals(expected.get(i), handle.getAttributeName(i),
                         label + " column at index " + i);
            rejectTsvControl(handle.getAttributeName(i), label + " header at index " + i);
        }
    }

    private static void preflightTarget(Path target, byte[] bytes) throws IOException {
        if (Files.exists(target)) {
            check(Files.isRegularFile(target), "output target is not a regular file: " + target);
            check(Arrays.equals(Files.readAllBytes(target), bytes),
                  "refusing to overwrite different bytes at " + target);
        }
    }

    private static void writeIdempotent(Path target, byte[] bytes) throws IOException {
        if (Files.exists(target)) {
            check(Arrays.equals(Files.readAllBytes(target), bytes),
                  "refusing to overwrite different bytes at " + target);
            return;
        }
        Path temporary = Files.createTempFile(target.getParent(), ".cfg02-pilot-", ".tmp");
        boolean moved = false;
        try {
            Files.write(temporary, bytes, StandardOpenOption.TRUNCATE_EXISTING,
                        StandardOpenOption.WRITE);
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException error) {
                Files.move(temporary, target);
            }
            moved = true;
        } catch (java.nio.file.FileAlreadyExistsException race) {
            check(Files.isRegularFile(target) &&
                  Arrays.equals(Files.readAllBytes(target), bytes),
                  "concurrent writer created different bytes at " + target);
        } finally {
            if (!moved) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    private static String sha256(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return toHex(digest.digest(bytes));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        }
        return result.toString();
    }

    private static String bitsHex(double value) {
        String raw = Long.toUnsignedString(Double.doubleToLongBits(value), 16);
        StringBuilder result = new StringBuilder(16);
        for (int i = raw.length(); i < 16; i++) {
            result.append('0');
        }
        result.append(raw);
        return result.toString();
    }

    private static void assertDoubleArrayBits(double[] expected, double[] actual, String label) {
        assertEquals(expected.length, actual.length, label + " length");
        for (int i = 0; i < expected.length; i++) {
            assertBits(expected[i], actual[i], label + " at index " + i);
        }
    }

    private static void assertBits(double expected, double actual, String label) {
        long expectedBits = Double.doubleToLongBits(expected);
        long actualBits = Double.doubleToLongBits(actual);
        check(expectedBits == actualBits,
              label + " bit mismatch: expected 0x" + bitsHex(expected) +
              ", actual 0x" + bitsHex(actual));
    }

    private static void assertFiniteUnit(double value, String label) {
        check(Double.isFinite(value), label + " is not finite");
        check(value >= 0.0d && value <= 1.0d, label + " is outside [0,1]: " + value);
    }

    private static void rejectTsvControl(String value, String label) {
        check(value.indexOf('\t') < 0 && value.indexOf('\r') < 0 && value.indexOf('\n') < 0,
              label + " contains TAB, CR, or LF");
    }

    private static String sanitizeDiagnostic(String value) {
        return value.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ');
    }

    private static String safeProperty(String name) {
        String value = System.getProperty(name);
        return value == null ? "UNKNOWN" : value;
    }

    private static HierarchySpec findHierarchy(String qi) {
        for (HierarchySpec spec : HIERARCHIES) {
            if (spec.qi.equals(qi)) {
                return spec;
            }
        }
        throw new IllegalStateException("unknown hierarchy QI: " + qi);
    }

    private static <T> T required(Map<String, T> values, String key) {
        T value = values.get(key);
        check(value != null, "required key missing: " + key);
        return value;
    }

    private static LinkedHashMap<String, Object> object() {
        return new LinkedHashMap<String, Object>();
    }

    private static List<String> immutable(String... values) {
        return Collections.unmodifiableList(Arrays.asList(values.clone()));
    }

    private static List<String> immutableCopy(String[] values) {
        return Collections.unmodifiableList(new ArrayList<String>(Arrays.asList(values.clone())));
    }

    private static void assertEquals(long expected, long actual, String label) {
        check(expected == actual, label + " mismatch: expected " + expected + ", actual " + actual);
    }

    private static void assertEquals(Object expected, Object actual, String label) {
        check(expected == null ? actual == null : expected.equals(actual),
              label + " mismatch: expected " + expected + ", actual " + actual);
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    private static final class Arguments {
        final Path repoRoot;
        final String runId;
        final Path runDir;
        final Path matrixTestReport;

        Arguments(Path repoRoot, String runId, Path runDir,
                  Path matrixTestReport) {
            this.repoRoot = repoRoot;
            this.runId = runId;
            this.runDir = runDir;
            this.matrixTestReport = matrixTestReport;
        }

        static Arguments parse(String[] args) throws IOException {
            check(args.length == 8,
                  "usage: --repo-root <absolute> --run-id <allowed-id> " +
                  "--run-dir <absolute> --matrix-test-report <absolute>");
            Map<String, String> parsed = new HashMap<String, String>();
            for (int i = 0; i < args.length; i += 2) {
                String flag = args[i];
                check(flag.equals("--repo-root") || flag.equals("--run-id") ||
                      flag.equals("--run-dir") ||
                      flag.equals("--matrix-test-report"),
                      "unknown argument: " + flag);
                check(!parsed.containsKey(flag), "duplicate argument: " + flag);
                parsed.put(flag, args[i + 1]);
            }
            check(parsed.size() == 4, "all four arguments are required");
            String runId = parsed.get("--run-id");
            check(ALLOWED_RUN_IDS.contains(runId), "invalid run-id: " + runId);
            Path repoInput = Paths.get(parsed.get("--repo-root"));
            Path runInput = Paths.get(parsed.get("--run-dir"));
            Path matrixTestInput = Paths.get(parsed.get("--matrix-test-report"));
            check(repoInput.isAbsolute(), "repo-root must be absolute");
            check(runInput.isAbsolute(), "run-dir must be absolute");
            check(matrixTestInput.isAbsolute(),
                  "matrix-test-report must be absolute");
            Path repoRoot = repoInput.toRealPath();
            check(Files.isDirectory(repoRoot), "repo-root is not a directory");
            Path runDir = runInput.toAbsolutePath().normalize();
            Path expectedRunDir = repoRoot.resolve(
                "runs/section_9_2_qualifying_candidate").normalize();
            check(runDir.equals(expectedRunDir),
                  "run-dir must be <repo-root>/runs/section_9_2_qualifying_candidate");
            check(Files.isDirectory(runDir), "run-dir must already exist");
            Path matrixTestReport = matrixTestInput.toAbsolutePath().normalize();
            return new Arguments(repoRoot, runId, runDir, matrixTestReport);
        }
    }

    private static final class GeneratedArtifactIdentity {
        final String filename;
        final long bytes;
        final String sha256;

        GeneratedArtifactIdentity(String filename, long bytes, String sha256) {
            this.filename = filename;
            this.bytes = bytes;
            this.sha256 = sha256;
        }
    }

    private static class FileSpec {
        final String relativePath;
        final long bytes;
        final String sha256;

        FileSpec(String relativePath, long bytes, String sha256) {
            this.relativePath = relativePath;
            this.bytes = bytes;
            this.sha256 = sha256;
        }
    }

    private static final class HierarchySpec extends FileSpec {
        final String qi;
        final int maxGeneralization;

        HierarchySpec(String qi, String relativePath, long bytes, String sha256,
                      int maxGeneralization) {
            super(relativePath, bytes, sha256);
            this.qi = qi;
            this.maxGeneralization = maxGeneralization;
        }
    }

    private static final class ResolvedHierarchy {
        final HierarchySpec spec;
        final String[][] table;

        ResolvedHierarchy(HierarchySpec spec, String[][] table) {
            this.spec = spec;
            this.table = table;
        }
    }

    private static final class MaterializedOutput {
        final List<String[]> rows;
        final List<Integer> outlierRowIndices;

        MaterializedOutput(List<String[]> rows, List<Integer> outlierRowIndices) {
            this.rows = rows;
            this.outlierRowIndices = outlierRowIndices;
        }
    }

    private static final class ValidatorEvidence {
        final int nOutput;
        final int nRetained;
        final int outliers;
        final int equivalenceClassCount;
        final int equivalenceClassSizeSum;
        final int kHat;
        final int uQiUniqueRows;
        final double uQi;
        final int uFullClassCount;
        final int uFullUniqueRows;
        final double uFull;
        final Map<String, Integer> salaryCounts;
        final int ecMedianNumerator;
        final int ecMedianDenominator;
        final int ecP95NearestRank;
        final int ecMaximum;

        ValidatorEvidence(int nOutput, int nRetained, int outliers,
                          int equivalenceClassCount, int equivalenceClassSizeSum,
                          int kHat, int uQiUniqueRows, double uQi,
                          int uFullClassCount, int uFullUniqueRows, double uFull,
                          Map<String, Integer> salaryCounts,
                          int ecMedianNumerator, int ecMedianDenominator,
                          int ecP95NearestRank, int ecMaximum) {
            this.nOutput = nOutput;
            this.nRetained = nRetained;
            this.outliers = outliers;
            this.equivalenceClassCount = equivalenceClassCount;
            this.equivalenceClassSizeSum = equivalenceClassSizeSum;
            this.kHat = kHat;
            this.uQiUniqueRows = uQiUniqueRows;
            this.uQi = uQi;
            this.uFullClassCount = uFullClassCount;
            this.uFullUniqueRows = uFullUniqueRows;
            this.uFull = uFull;
            this.salaryCounts = salaryCounts;
            this.ecMedianNumerator = ecMedianNumerator;
            this.ecMedianDenominator = ecMedianDenominator;
            this.ecP95NearestRank = ecP95NearestRank;
            this.ecMaximum = ecMaximum;
        }
    }

    private static final class LossEvidence {
        final double[] highestComponents;
        final double[] lowestComponents;
        final double[] minimumComponents;
        final double[] maximumComponents;
        final double[] weights;
        final double foldedMin;
        final double foldedMax;
        final double foldedHighestScore;
        final double foldedLowestScore;
        final double foldedHighestTotal;
        final double foldedLowestTotal;
        final double lossTotal;
        final double equalityWitnessTotal;
        final Map<String, Double> componentsByName;

        LossEvidence(double[] highestComponents, double[] lowestComponents,
                     double[] minimumComponents, double[] maximumComponents,
                     double[] weights, double foldedMin, double foldedMax,
                     double foldedHighestScore, double foldedLowestScore,
                     double foldedHighestTotal, double foldedLowestTotal,
                     double lossTotal, double equalityWitnessTotal,
                     Map<String, Double> componentsByName) {
            this.highestComponents = highestComponents;
            this.lowestComponents = lowestComponents;
            this.minimumComponents = minimumComponents;
            this.maximumComponents = maximumComponents;
            this.weights = weights;
            this.foldedMin = foldedMin;
            this.foldedMax = foldedMax;
            this.foldedHighestScore = foldedHighestScore;
            this.foldedLowestScore = foldedLowestScore;
            this.foldedHighestTotal = foldedHighestTotal;
            this.foldedLowestTotal = foldedLowestTotal;
            this.lossTotal = lossTotal;
            this.equalityWitnessTotal = equalityWitnessTotal;
            this.componentsByName = componentsByName;
        }
    }

    private static final class RunOutcome {
        final Path outputPath;
        final Path reportPath;
        final int outputBytes;
        final int reportBytes;
        final String outputSha256;
        final String reportSha256;
        final String canonicalSemanticSha256;

        RunOutcome(Path outputPath, Path reportPath, int outputBytes, int reportBytes,
                   String outputSha256, String reportSha256,
                   String canonicalSemanticSha256) {
            this.outputPath = outputPath;
            this.reportPath = reportPath;
            this.outputBytes = outputBytes;
            this.reportBytes = reportBytes;
            this.outputSha256 = outputSha256;
            this.reportSha256 = reportSha256;
            this.canonicalSemanticSha256 = canonicalSemanticSha256;
        }
    }


    private static final class AgeMapping {
        private final Map<Integer, Map<String, String>> rawToSemantic;
        private final Map<Integer, Set<String>> semanticLabels;

        AgeMapping(Map<Integer, Map<String, String>> rawToSemantic,
                   Map<Integer, Set<String>> semanticLabels) {
            this.rawToSemantic = rawToSemantic;
            this.semanticLabels = semanticLabels;
        }

        String normalizeRaw(String rawLabel, int level) {
            Map<String, String> mapping = rawToSemantic.get(Integer.valueOf(level));
            check(mapping != null, "age mapping level missing: " + level);
            String result = mapping.get(rawLabel);
            check(result != null, "raw age label is not in the validated mapping at level " +
                  level + ": " + rawLabel);
            return result;
        }

        void validateOutputAge(String label, int level, boolean raw) {
            check(level >= 0 && level <= 4, "invalid age generalization level: " + level);
            if (raw) {
                check(rawToSemantic.get(Integer.valueOf(level)).containsKey(label),
                      "unexpected raw age output label at level " + level + ": " + label);
            } else {
                check(semanticLabels.get(Integer.valueOf(level)).contains(label),
                      "unexpected semantic age output label at level " + level + ": " + label);
            }
        }

        @SuppressWarnings("unchecked")
        static AgeMapping loadAndValidate(Path mappingPath,
                                          String[][] raw,
                                          String[][] semantic) throws IOException {
            Object parsed = new JsonParser(
                new String(Files.readAllBytes(mappingPath), StandardCharsets.UTF_8)).parse();
            check(parsed instanceof Map, "age mapping root is not an object");
            Map<String, Object> root = (Map<String, Object>) parsed;
            assertJsonString(root, "report_schema", "adult-age-semantic-hierarchy/1.1");
            assertJsonString(root, "source_sha256",
                "463f35372e8b1ad31fc624eb73c5da9297878a044ae5d61038eaf7b431ac55ca");
            assertJsonString(root, "derived_sha256",
                "de2a5bdc9b0ad72a31ca8199e7be5d39346646da604bf1fb8954afc7626e0ba5");
            assertJsonLong(root, "rows", 100L);
            assertJsonLong(root, "levels_including_leaf", 5L);
            check(Boolean.TRUE.equals(root.get("leaf_values_unchanged")),
                  "mapping leaf_values_unchanged is not true");
            check(Boolean.TRUE.equals(root.get("root_unchanged")),
                  "mapping root_unchanged is not true");
            assertJsonString(root, "static_partition_equivalence", "PASS");

            for (int row = 0; row < 100; row++) {
                assertEquals(raw[row][0], semantic[row][0],
                             "age leaf equality at row " + row);
                check("*".equals(raw[row][4]) && "*".equals(semantic[row][4]),
                      "age root equality at row " + row);
            }

            Map<Integer, Map<String, List<String>>> rawGroups = groups(raw);
            Map<Integer, Map<String, List<String>>> semanticGroups = groups(semantic);
            Map<Integer, Map<String, String>> maps = new LinkedHashMap<Integer, Map<String, String>>();
            Map<Integer, Set<String>> semanticLabels = new LinkedHashMap<Integer, Set<String>>();
            for (int level = 0; level <= 4; level++) {
                maps.put(Integer.valueOf(level), new LinkedHashMap<String, String>());
                semanticLabels.put(Integer.valueOf(level),
                    new LinkedHashSet<String>(semanticGroups.get(Integer.valueOf(level)).keySet()));
            }
            for (String label : rawGroups.get(Integer.valueOf(0)).keySet()) {
                maps.get(Integer.valueOf(0)).put(label, label);
            }
            maps.get(Integer.valueOf(4)).put("*", "*");

            Object mappingsObject = root.get("intermediate_label_mappings");
            check(mappingsObject instanceof List,
                  "intermediate_label_mappings is not an array");
            List<Object> mappings = (List<Object>) mappingsObject;
            assertEquals(35, mappings.size(), "intermediate age mapping count");
            for (Object itemObject : mappings) {
                check(itemObject instanceof Map, "age mapping entry is not an object");
                Map<String, Object> item = (Map<String, Object>) itemObject;
                int level = exactInt(item, "level");
                check(level >= 1 && level <= 3, "intermediate mapping level outside 1..3");
                String oldLabel = exactString(item, "old_label");
                String newLabel = exactString(item, "new_label");
                List<String> rawLeaves = required(rawGroups.get(Integer.valueOf(level)), oldLabel);
                List<String> semanticLeaves = required(
                    semanticGroups.get(Integer.valueOf(level)), newLabel);
                check(new LinkedHashSet<String>(rawLeaves).equals(
                          new LinkedHashSet<String>(semanticLeaves)),
                      "age mapping leaf-set mismatch for " + oldLabel + " -> " + newLabel);
                assertEquals(rawLeaves.size(), exactInt(item, "leaf_count"),
                             "age mapping leaf_count for " + oldLabel);
                int minimum = Integer.MAX_VALUE;
                int maximum = Integer.MIN_VALUE;
                for (String leaf : rawLeaves) {
                    int value = Integer.parseInt(leaf);
                    minimum = Math.min(minimum, value);
                    maximum = Math.max(maximum, value);
                }
                assertEquals(minimum, exactInt(item, "minimum_leaf"),
                             "age mapping minimum leaf for " + oldLabel);
                assertEquals(maximum, exactInt(item, "maximum_leaf"),
                             "age mapping maximum leaf for " + oldLabel);
                check(maps.get(Integer.valueOf(level)).put(oldLabel, newLabel) == null,
                      "duplicate old age label mapping: " + oldLabel);
            }

            for (int level = 0; level <= 4; level++) {
                Map<String, String> levelMap = maps.get(Integer.valueOf(level));
                check(levelMap.keySet().equals(rawGroups.get(Integer.valueOf(level)).keySet()),
                      "mapping does not cover exactly all raw labels at level " + level);
                check(new LinkedHashSet<String>(levelMap.values()).equals(
                          semanticGroups.get(Integer.valueOf(level)).keySet()),
                      "mapping does not cover exactly all semantic labels at level " + level);
                for (Map.Entry<String, String> entry : levelMap.entrySet()) {
                    List<String> left = rawGroups.get(Integer.valueOf(level)).get(entry.getKey());
                    List<String> right = semanticGroups.get(Integer.valueOf(level)).get(entry.getValue());
                    check(new LinkedHashSet<String>(left).equals(new LinkedHashSet<String>(right)),
                          "validated age partition mismatch at level " + level);
                }
            }
            return new AgeMapping(maps, semanticLabels);
        }

        private static Map<Integer, Map<String, List<String>>> groups(String[][] table) {
            Map<Integer, Map<String, List<String>>> result =
                new LinkedHashMap<Integer, Map<String, List<String>>>();
            for (int level = 0; level < 5; level++) {
                Map<String, List<String>> byLabel = new LinkedHashMap<String, List<String>>();
                for (String[] row : table) {
                    String label = row[level];
                    List<String> leaves = byLabel.get(label);
                    if (leaves == null) {
                        leaves = new ArrayList<String>();
                        byLabel.put(label, leaves);
                    }
                    leaves.add(row[0]);
                }
                result.put(Integer.valueOf(level), byLabel);
            }
            return result;
        }

        private static void assertJsonString(Map<String, Object> map, String key,
                                             String expected) {
            assertEquals(expected, exactString(map, key), "mapping JSON key " + key);
        }

        private static void assertJsonLong(Map<String, Object> map, String key,
                                           long expected) {
            Object value = map.get(key);
            check(value instanceof Long, "mapping JSON key is not an integer: " + key);
            assertEquals(expected, ((Long) value).longValue(), "mapping JSON key " + key);
        }

        private static int exactInt(Map<String, Object> map, String key) {
            Object value = map.get(key);
            check(value instanceof Long, "mapping integer key missing/invalid: " + key);
            long number = ((Long) value).longValue();
            check(number >= Integer.MIN_VALUE && number <= Integer.MAX_VALUE,
                  "mapping integer out of range: " + key);
            return (int) number;
        }

        private static String exactString(Map<String, Object> map, String key) {
            Object value = map.get(key);
            check(value instanceof String, "mapping string key missing/invalid: " + key);
            return (String) value;
        }
    }


    private static final class JsonParser {
        private final String source;
        private int position;

        JsonParser(String source) {
            this.source = source;
        }

        Object parse() {
            check(!source.startsWith("\ufeff"), "JSON mapping has a BOM");
            Object value = parseValue();
            whitespace();
            check(position == source.length(), "trailing data in JSON mapping");
            return value;
        }

        private Object parseValue() {
            whitespace();
            check(position < source.length(), "unexpected end of JSON mapping");
            char c = source.charAt(position);
            if (c == '{') return parseObject();
            if (c == '[') return parseArray();
            if (c == '"') return parseString();
            if (c == 't') { literal("true"); return Boolean.TRUE; }
            if (c == 'f') { literal("false"); return Boolean.FALSE; }
            if (c == 'n') { literal("null"); return null; }
            if (c == '-' || (c >= '0' && c <= '9')) return parseNumber();
            throw new IllegalStateException("invalid JSON token at character " + position);
        }

        private Map<String, Object> parseObject() {
            expect('{');
            LinkedHashMap<String, Object> result = new LinkedHashMap<String, Object>();
            whitespace();
            if (peek('}')) { position++; return result; }
            while (true) {
                whitespace();
                check(peek('"'), "JSON object key is not a string");
                String key = parseString();
                check(!result.containsKey(key), "duplicate JSON object key: " + key);
                whitespace();
                expect(':');
                result.put(key, parseValue());
                whitespace();
                if (peek('}')) { position++; return result; }
                expect(',');
            }
        }

        private List<Object> parseArray() {
            expect('[');
            List<Object> result = new ArrayList<Object>();
            whitespace();
            if (peek(']')) { position++; return result; }
            while (true) {
                result.add(parseValue());
                whitespace();
                if (peek(']')) { position++; return result; }
                expect(',');
            }
        }

        private String parseString() {
            expect('"');
            StringBuilder result = new StringBuilder();
            while (position < source.length()) {
                char c = source.charAt(position++);
                if (c == '"') return result.toString();
                check(c >= 0x20, "control character in JSON string");
                if (c != '\\') {
                    result.append(c);
                    continue;
                }
                check(position < source.length(), "truncated JSON escape");
                char escape = source.charAt(position++);
                switch (escape) {
                case '"': result.append('"'); break;
                case '\\': result.append('\\'); break;
                case '/': result.append('/'); break;
                case 'b': result.append('\b'); break;
                case 'f': result.append('\f'); break;
                case 'n': result.append('\n'); break;
                case 'r': result.append('\r'); break;
                case 't': result.append('\t'); break;
                case 'u':
                    check(position + 4 <= source.length(), "truncated Unicode escape");
                    int code = 0;
                    for (int i = 0; i < 4; i++) {
                        int digit = Character.digit(source.charAt(position++), 16);
                        check(digit >= 0, "invalid Unicode escape");
                        code = (code << 4) | digit;
                    }
                    result.append((char) code);
                    break;
                default:
                    throw new IllegalStateException("invalid JSON escape: " + escape);
                }
            }
            throw new IllegalStateException("unterminated JSON string");
        }

        private Long parseNumber() {
            int start = position;
            if (peek('-')) position++;
            check(position < source.length(), "truncated JSON number");
            if (peek('0')) {
                position++;
            } else {
                check(source.charAt(position) >= '1' && source.charAt(position) <= '9',
                      "invalid JSON number");
                while (position < source.length() && Character.isDigit(source.charAt(position))) {
                    position++;
                }
            }
            check(position == source.length() ||
                  (source.charAt(position) != '.' && source.charAt(position) != 'e' &&
                   source.charAt(position) != 'E'),
                  "non-integer JSON number is outside the mapping contract");
            try {
                return Long.valueOf(source.substring(start, position));
            } catch (NumberFormatException error) {
                throw new IllegalStateException("JSON integer out of range", error);
            }
        }

        private void literal(String value) {
            check(source.startsWith(value, position), "invalid JSON literal");
            position += value.length();
        }

        private void expect(char expected) {
            whitespace();
            check(position < source.length() && source.charAt(position) == expected,
                  "expected JSON character '" + expected + "' at " + position);
            position++;
        }

        private boolean peek(char value) {
            return position < source.length() && source.charAt(position) == value;
        }

        private void whitespace() {
            while (position < source.length()) {
                char c = source.charAt(position);
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                    position++;
                } else {
                    return;
                }
            }
        }
    }


    private static final class JsonWriter {
        static String write(Object value) {
            StringBuilder output = new StringBuilder(16384);
            append(output, value);
            return output.toString();
        }

        @SuppressWarnings("unchecked")
        private static void append(StringBuilder output, Object value) {
            if (value == null) {
                output.append("null");
            } else if (value instanceof String) {
                string(output, (String) value);
            } else if (value instanceof Boolean || value instanceof Integer ||
                       value instanceof Long) {
                output.append(value.toString());
            } else if (value instanceof Double) {
                double number = ((Double) value).doubleValue();
                check(Double.isFinite(number), "cannot encode non-finite JSON number");
                output.append(Double.toString(number));
            } else if (value instanceof List) {
                output.append('[');
                boolean first = true;
                for (Object item : (List<Object>) value) {
                    if (!first) output.append(',');
                    append(output, item);
                    first = false;
                }
                output.append(']');
            } else if (value instanceof Map) {
                check(value instanceof LinkedHashMap,
                      "deterministic JSON requires LinkedHashMap");
                output.append('{');
                boolean first = true;
                for (Map.Entry<String, Object> entry :
                     ((Map<String, Object>) value).entrySet()) {
                    if (!first) output.append(',');
                    string(output, entry.getKey());
                    output.append(':');
                    append(output, entry.getValue());
                    first = false;
                }
                output.append('}');
            } else {
                throw new IllegalStateException("unsupported JSON value type: " +
                                                value.getClass().getName());
            }
        }

        private static void string(StringBuilder output, String value) {
            output.append('"');
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                switch (c) {
                case '"': output.append("\\\""); break;
                case '\\': output.append("\\\\"); break;
                case '\b': output.append("\\b"); break;
                case '\f': output.append("\\f"); break;
                case '\n': output.append("\\n"); break;
                case '\r': output.append("\\r"); break;
                case '\t': output.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        output.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        output.append(c);
                    }
                }
            }
            output.append('"');
        }
    }
}
