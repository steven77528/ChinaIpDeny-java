# Java 中国 IP 列表自动更新

使用 IPdeny 的中国（CN）CIDR 列表。无需账户、Token 或第三方 Java 依赖，支持 Java 8 及以上。

## 接入 Java 服务

将 `CidrDeny.java` 和 `AutoUpdatingCidrDeny.java` 加入项目。应用启动时创建一个实例，重复使用：

```java
import java.nio.file.Paths;

AutoUpdatingCidrDeny deny = new AutoUpdatingCidrDeny(
    Paths.get("data/china-cidr-cache.properties")
);

boolean blocked = deny.isDenied("1.0.1.1");
boolean blockedV6 = deny.isDenied("2001:250::1");
```

`true` 表示命中中国 CN 列表，应执行你的 deny 逻辑；`false` 表示未命中。非法 IP 会抛出 `IllegalArgumentException`。每个请求只做内存查询，不发起网络请求。

可按需调用 `deny.refreshNow()` 强制更新，使用 `deny.getLastUpdatedAt()` 查看最后成功更新时间。应用关闭时调用 `deny.close()` 释放定时线程。关闭操作会等待正在执行的下载结束或超时。

## 定时规则

- 第一次启动、没有有效缓存：同步下载 IPv4 和 IPv6；下载失败则启动报错，不会用空规则运行。
- 已有有效缓存：立即加载，后台检查是否需要更新。
- 每 24 小时检查一次，按北京时间（Asia/Shanghai）判断月份。与上次成功更新不在同一月份时才下载。
- 跨月后在下一次检查时更新，通常在 24 小时内；停机错过的更新会在下次启动时补查。
- 下载失败、HTTP 错误、空列表、错误格式、地址族错误或已声明长度的响应不完整时：保留旧规则和旧缓存，记录日志，次日重试。
- 两份列表都下载并校验成功后，一起保存缓存并切换内存中的规则；更新过程中仍可查询旧规则。
- 服务进程需要持续运行，缓存路径需可写且所在文件系统支持原子文件替换。一个缓存文件只供一个服务实例使用。

## 数据源

- IPv4：https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone
- IPv6：https://www.ipdeny.com/ipv6/ipaddresses/aggregated/cn-aggregated.zone
- 数据源说明：https://www.ipdeny.com/ipblocks/

这是经你确认后采用的新数据源，与之前 IP2Location 的覆盖范围可能不同。只使用 CN 列表，不自动合并其他国家或地区的列表。IPv4 CIDR 同时适用于对应的 IPv4 映射 IPv6 写法，例如 `1.0.1.1` 和 `::ffff:1.0.1.1`。

2026-11-02 实际下载验证得到 IPv4 5,517 条、IPv6 2,036 条。条目数量会随数据更新变化；使用聚合 CIDR，不展开数亿条 IP。

## 本机运行示例

在这些文件所在目录运行：

```powershell
java -jar ChinaIpDeny.jar
```

输入 IPv4 或 IPv6 地址后回车，会输出 `DENY` 或 `ALLOW`；输入 `exit` 退出。本示例使用当前目录下的 `china-cidr-cache.properties` 保存缓存。

也可以从源码编译运行：

```powershell
javac CidrDeny.java AutoUpdatingCidrDeny.java ChinaIpDemo.java
java ChinaIpDemo
```

独立演示程序的入口是 `ChinaIpDemo.java`。实际服务只需前面的两个类，在服务生命周期内保持 `AutoUpdatingCidrDeny` 实例存活。
