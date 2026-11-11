import java.nio.file.Paths;

public final class CidrDenyTest {
    private static int passed;

    public static void main(String[] args) throws Exception {
        passed = 0;
        String ipv4File = "D:\\Downloads\\firewall (1).txt.gz";
        String ipv6File = "D:\\Downloads\\firewall.txt.gz";

        // Optional arguments let you use the same test with different file paths.
        if (args.length == 2) {
            ipv4File = args[0];
            ipv6File = args[1];
        } else if (args.length != 0) {
            throw new IllegalArgumentException("Usage: CidrDenyTest [ipv4-file ipv6-file]");
        }

        CidrDeny deny = new CidrDeny();
        long started = System.nanoTime();
        deny.load(Paths.get(ipv4File));
        deny.load(Paths.get(ipv6File));
        System.out.println("Rules loaded in " + (System.nanoTime() - started) / 1_000_000 + " ms");

        // Expectations verified against the two supplied firewall files.
        check(deny, "1.0.1.0", true);
        check(deny, "1.0.1.1", true);
        check(deny, "1.0.1.255", true);
        check(deny, "8.8.8.8", false);
        check(deny, "127.0.0.1", false);
        check(deny, "2001:250::1", true);
        check(deny, "::ffff:1.0.1.1", true);
        check(deny, "::1", false);
        check(deny, "192.168.110.79", false);
        check(deny, "115.193.118.26", true);

        System.out.println("All " + passed + " tests passed.");
    }

    private static void check(CidrDeny deny, String ip, boolean expected) {
        boolean actual = deny.isDenied(ip);
        System.out.printf("%-22s %-5s expected=%-5s %s%n",
                ip, actual ? "DENY" : "ALLOW", expected ? "DENY" : "ALLOW",
                actual == expected ? "PASS" : "FAIL");
        if (actual != expected) {
            throw new AssertionError("Unexpected result for " + ip
                    + ": expected " + expected + ", got " + actual);
        }
        passed++;
    }
}
