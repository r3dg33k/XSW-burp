package burp.utilities.helpers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public class EncodingHelpers {
    /**
     * {@value #URL_ENCODED}
     */
    public static final int URL_ENCODED = 1;

    /**
     * {@value #BASE64_ENCODED}
     */
    public static final int BASE64_ENCODED = 2;

    /**
     * {@value #DEFLATED}
     */
    public static final int DEFLATED = 3;

    public static int getEncoding(String data) {

        if (isURLEncoded(data)) {
            return URL_ENCODED;
        } else if (isBase64Encoded(data)) {
            return BASE64_ENCODED;
        } else try {
            if (isDeflated(data.getBytes(StandardCharsets.UTF_8))) {
                return DEFLATED;
            }
        } catch (IOException ex) {

        }
        return -1;
    }

    public static String decodeSamlParam(String samlParam) throws IOException, DataFormatException, IllegalArgumentException {
        byte[] tmp;
        boolean isCompressed = false;
        boolean isURL = false;
        boolean isBase64 = false;

        if (isURLEncoded(samlParam)) {
            samlParam = URLDecoder.decode(samlParam, StandardCharsets.UTF_8);
            isURL = true;
        }
        if (isBase64Encoded(samlParam)) {
            tmp = base64decode(samlParam);
            isBase64 = true;
        } else {
            tmp = samlParam.getBytes();
        }
        if (isDeflated(tmp)) {
            isCompressed = true;
            tmp = decompress(tmp);
        }
        return new String(tmp);
    }

    public static String encodeSamlParam(byte[] input, boolean isCompressed, boolean isBase64, boolean isURL) {
        String result = null;
        if (isCompressed) {
            input = compress(input);
        }
        if (isBase64) {
            input = Base64.getEncoder().encode(input);
        }
        if (isURL) {
            result = new String(input);
            result = URLEncoder.encode(result, StandardCharsets.UTF_8);
        }
        return result;
    }

    public static String decode(String input) {
        if (getEncoding(input) == -1) {
            return input;
        }
        if (isURLEncoded(input)) {
            input = URLDecoder.decode(input, StandardCharsets.UTF_8);
            if (getEncoding(input) < 0) {
                return input;
            }
        }
        byte[] byteString;
        try {
            if (isBase64Encoded(input)) {
                byteString = base64decode(input);
            } else {
                byteString = input.getBytes(StandardCharsets.UTF_8);
            }
        } catch (IllegalArgumentException e) {
            return null;
        }
        byte[] decompressed = null;
        {
            try {
                if (isDeflated(byteString)) {
                    try {
                        decompressed = decompress(byteString);
                    } catch (Exception ignored) {
                    }
                    if (decompressed != null) {
                        return new String(decompressed);
                    }
                } else {
                    return new String(byteString);
                }
            } catch (IOException ignored) {
            }
        }
        return null;
    }

    public static boolean isURLEncoded(String data) {
        if (data == null || data.isEmpty()) return false;

        for (int i = 0; i < data.length(); i++) {
            if (data.charAt(i) > 0x7F) {
                return false;
            }
        }

        final String decoded;
        try {
            decoded = URLDecoder.decode(data, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (decoded.equals(data)) {
            return false;
        }

        return containsPctHex(data);
    }

    public static boolean isBase64Encoded(String data) {
        if (data == null) return false;

        String noNewlines = data.strip();

        try {
            base64decode(noNewlines);
        } catch (IllegalArgumentException e) {
            return false;
        }

        return true;
    }

    public static boolean isDeflated(byte[] data) throws IOException {
        try {
            decompress(data);
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    private static byte[] compress(byte[] input) {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        try {
            deflater.setInput(input);
            deflater.finish();

            ByteArrayOutputStream baos = new ByteArrayOutputStream(Math.max(32, input.length / 2));
            byte[] buffer = new byte[8192];

            while (!deflater.finished()) {
                int written = deflater.deflate(buffer, 0, buffer.length, Deflater.NO_FLUSH);

                if (written > 0) {
                    baos.write(buffer, 0, written);
                    continue;
                }

                if (deflater.needsInput()) {
                    throw new IllegalStateException("Deflater needs more input after finish(); input likely incomplete.");
                }

                if (!deflater.finished()) {
                    throw new IllegalStateException("Deflater made no progress (possible invalid state).");
                }
            }

            return baos.toByteArray();
        } finally {
            deflater.end();
        }
    }

    private static byte[] base64decode(String input) throws IllegalArgumentException {
        try {
            return Base64.getDecoder().decode(input);
        } catch (Exception e) {
            try {
                return Base64.getUrlDecoder().decode(input);
            } catch (Exception ex) {
                throw new IllegalArgumentException(ex);
            }
        }
    }

    private static byte[] decompress(byte[] input) throws DataFormatException {
        Inflater inflater = new Inflater(true);
        try {
            inflater.setInput(input);

            ByteArrayOutputStream baos = new ByteArrayOutputStream(input.length * 2);
            byte[] buffer = new byte[8192];

            while (!inflater.finished()) {
                int read = inflater.inflate(buffer);

                if (read > 0) {
                    baos.write(buffer, 0, read);
                    continue;
                }

                if (inflater.needsDictionary()) {
                    throw new DataFormatException("Preset dictionary required for this stream.");
                }
                if (inflater.needsInput()) {
                    throw new DataFormatException("Truncated deflate stream (needs more input).");
                }

                throw new DataFormatException("Inflater made no progress (corrupt or invalid stream).");
            }

            return baos.toByteArray();
        } finally {
            inflater.end();
        }
    }

    private static String stripCRLF(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\r' && c != '\n') {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static boolean isBase64Alphabet(char c) {
        return (c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') ||
                c == '+' || c == '/';
    }

    private static boolean containsPctHex(String s) {
        for (int i = 0; i + 2 < s.length(); i++) {
            if (s.charAt(i) == '%' && isHex(s.charAt(i + 1)) && isHex(s.charAt(i + 2))) {
                return true;
            }
        }
        return false;
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') ||
                (c >= 'A' && c <= 'F') ||
                (c >= 'a' && c <= 'f');
    }
}
