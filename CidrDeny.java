import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.zip.GZIPInputStream;

public final class CidrDeny {
    private static final class Node {
        Node zero;
        Node one;
        boolean deny;
    }

    private final Node ipv4 = new Node();
    private final Node ipv6 = new Node();

    public void add(String cidr) {
        String[] parts = cidr.trim().split("/", -1);
        if (parts.length > 2) {
            throw new IllegalArgumentException("Invalid CIDR: " + cidr);
        }
        byte[] address = parseIp(parts[0]);
        int bits = address.length * 8;
        int prefix = bits;
        if (parts.length == 2) {
            if (!parts[1].matches("[0-9]{1,3}")) {
                throw new IllegalArgumentException("Invalid prefix: " + cidr);
            }
            prefix = Integer.parseInt(parts[1]);
        }
        if (prefix > bits) {
            throw new IllegalArgumentException("Prefix out of range: " + cidr);
        }
        Node node = address.length == 4 ? ipv4 : ipv6;
        for (int i = 0; i < prefix; i++) {
            if (node.deny) {
                return;
            }
            if (bit(address, i) == 0) {
                if (node.zero == null) node.zero = new Node();
                node = node.zero;
            } else {
                if (node.one == null) node.one = new Node();
                node = node.one;
            }
        }
        node.deny = true;
        node.zero = null;
        node.one = null;
    }

    public boolean isDenied(String ip) {
        byte[] address = parseIp(ip);
        Node node = address.length == 4 ? ipv4 : ipv6;
        for (int i = 0; i < address.length * 8 && node != null; i++) {
            if (node.deny) {
                return true;
            }
            node = bit(address, i) == 0 ? node.zero : node.one;
        }
        return node != null && node.deny;
    }

    public void load(Path path) throws IOException {
        try (InputStream raw = Files.newInputStream(path);
             InputStream input = path.toString().toLowerCase(Locale.ROOT).endsWith(".gz")
                     ? new GZIPInputStream(raw) : raw;
             BufferedReader reader = new BufferedReader(
                     new InputStreamReader(input, StandardCharsets.UTF_8))) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (lineNumber == 1 && line.startsWith("\uFEFF")) {
                    line = line.substring(1);
                }
                int comment = line.indexOf('#');
                if (comment >= 0) line = line.substring(0, comment);
                line = line.trim();
                if (line.isEmpty() || line.equals("}") || line.equals("location / {")) {
                    continue;
                }
                line = line.replaceFirst("^deny\\s+", "");
                if (line.endsWith(";")) line = line.substring(0, line.length() - 1).trim();
                try {
                    add(line);
                } catch (IllegalArgumentException error) {
                    throw new IOException(path + ":" + lineNumber + ": " + error.getMessage(), error);
                }
            }
        }
    }

    private static int bit(byte[] address, int index) {
        return (address[index / 8] >>> (7 - index % 8)) & 1;
    }

    private static byte[] parseIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            throw new IllegalArgumentException("IP is empty");
        }
        if (!ip.contains(":")) {
            String[] parts = ip.split("\\.", -1);
            if (parts.length != 4) throw new IllegalArgumentException("Invalid IPv4: " + ip);
            byte[] result = new byte[4];
            for (int i = 0; i < 4; i++) {
                if (!parts[i].matches("[0-9]{1,3}")) {
                    throw new IllegalArgumentException("Invalid IPv4: " + ip);
                }
                int value = Integer.parseInt(parts[i]);
                if (value > 255) throw new IllegalArgumentException("Invalid IPv4: " + ip);
                result[i] = (byte) value;
            }
            return result;
        }
        // Accept numeric literals only; never resolve host names through DNS.
        if (!ip.matches("[0-9a-fA-F:.]+")) {
            throw new IllegalArgumentException("Invalid IPv6: " + ip);
        }
        if (ip.contains(".")) parseIp(ip.substring(ip.lastIndexOf(':') + 1));
        try {
            byte[] address = InetAddress.getByName(ip).getAddress();
            // Java collapses IPv4-mapped IPv6 literals to four bytes. Restore them.
            if (address.length == 4) {
                byte[] mapped = new byte[16];
                mapped[10] = (byte) 0xFF;
                mapped[11] = (byte) 0xFF;
                System.arraycopy(address, 0, mapped, 12, 4);
                return mapped;
            }
            return address;
        } catch (UnknownHostException error) {
            throw new IllegalArgumentException("Invalid IPv6: " + ip, error);
        }
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: java CidrDeny <IP> <rules.txt|rules.gz> [more-files...]");
            System.exit(2);
        }
        try {
            CidrDeny rules = new CidrDeny();
            for (int i = 1; i < args.length; i++) rules.load(Paths.get(args[i]));
            System.out.println(rules.isDenied(args[0]) ? "DENY" : "ALLOW");
        } catch (IOException | IllegalArgumentException error) {
            System.err.println("ERROR: " + error.getMessage());
            System.exit(2);
        }
    }
}
