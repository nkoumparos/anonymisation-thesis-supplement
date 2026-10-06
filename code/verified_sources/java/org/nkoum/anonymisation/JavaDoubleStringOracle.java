package org.nkoum.anonymisation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;


public final class JavaDoubleStringOracle {

    private JavaDoubleStringOracle() {

    }

    public static void main(String[] args) {
        try {
            byte[] output = convert(args);
            System.out.write(output);
            System.out.flush();
        } catch (IllegalArgumentException | IOException error) {
            String message = error.getMessage();
            System.err.println("ERROR=" + (message == null ? "conversion failed" : message));
            System.exit(1);
        }
    }

    private static byte[] convert(String[] arguments) {
        if (arguments.length == 0) {
            throw new IllegalArgumentException(
                "expected one or more 16-character lowercase hexadecimal arguments");
        }

        Set<String> observed = new HashSet<String>();
        StringBuilder output = new StringBuilder(arguments.length * 38);
        for (String bitsHex : arguments) {
            if (!isLowercaseHex64(bitsHex)) {
                throw new IllegalArgumentException(
                    "malformed binary64 bits: " + String.valueOf(bitsHex));
            }
            if (!observed.add(bitsHex)) {
                throw new IllegalArgumentException("duplicate binary64 bits: " + bitsHex);
            }

            long bits = Long.parseUnsignedLong(bitsHex, 16);
            double value = Double.longBitsToDouble(bits);
            if (!Double.isFinite(value)) {
                throw new IllegalArgumentException("non-finite binary64 value: " + bitsHex);
            }
            output.append(bitsHex)
                  .append('\t')
                  .append(Double.toString(value))
                  .append('\n');
        }
        return output.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static boolean isLowercaseHex64(String value) {
        if (value == null || value.length() != 16) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= '0' && character <= '9') ||
                  (character >= 'a' && character <= 'f'))) {
                return false;
            }
        }
        return true;
    }
}
