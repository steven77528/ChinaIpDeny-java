import java.nio.file.Paths;

public final class CS {
    public static void main(String[] args) throws Exception {

        CidrDeny deny = new CidrDeny();

        // 初始化时加载一次，直接读取你原来的两个压缩文件
        deny.load(Paths.get("D:\\Downloads\\firewall (1).txt.gz"));
        deny.load(Paths.get("D:\\Downloads\\firewall.txt.gz"));

        // 后续反复查询：true 表示命中 deny，false 表示未命中
        boolean blocked = deny.isDenied("192.168.110.79");
        boolean blockedV6 = deny.isDenied("2001:250::1");

        System.out.println("Blocked IPv4: " + blocked);
        System.out.println("Blocked IPv6: " + blockedV6);

    }
}
