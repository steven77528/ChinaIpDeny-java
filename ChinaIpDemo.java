import java.nio.file.Paths;
import java.util.Scanner;

public final class ChinaIpDemo {
    public static void main(String[] args) throws Exception {
        try (AutoUpdatingCidrDeny deny = new AutoUpdatingCidrDeny(Paths.get("china-cidr-cache.properties"));
             Scanner input = new Scanner(System.in)) {
            System.out.println("Updated at: " + deny.getLastUpdatedAt());
            System.out.println("Enter an IPv4/IPv6 address, or exit:");
            while (input.hasNextLine()) {
                String ip = input.nextLine().trim();
                if (ip.equalsIgnoreCase("exit")) break;
                if (ip.isEmpty()) continue;
                try {
                    System.out.println(deny.isDenied(ip) ? "DENY" : "ALLOW");
                } catch (IllegalArgumentException error) {
                    System.out.println("ERROR: " + error.getMessage());
                }
            }
        }
    }
}
