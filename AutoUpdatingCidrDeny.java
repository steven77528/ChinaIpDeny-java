import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneId;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.GZIPInputStream;

public final class AutoUpdatingCidrDeny implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(AutoUpdatingCidrDeny.class.getName());
    private static final ZoneId ZONE = ZoneId.of("Asia/Shanghai");
    private static final int MAX_BYTES = 4 * 1024 * 1024;
    private static final URI CN_IPV4 = URI.create("https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone");
    private static final URI CN_IPV6 = URI.create("https://www.ipdeny.com/ipv6/ipaddresses/aggregated/cn-aggregated.zone");

    private final Path cacheFile;
    private final URI ipv4Url;
    private final URI ipv6Url;
    private final Clock clock;
    private final ScheduledExecutorService scheduler;
    private volatile Snapshot current;
    private boolean closed;

    private static final class Snapshot {
        final CidrDeny matcher;
        final Instant updatedAt;
        final int ipv4Count;
        final int ipv6Count;

        Snapshot(CidrDeny matcher, Instant updatedAt, int ipv4Count, int ipv6Count) {
            this.matcher = matcher;
            this.updatedAt = updatedAt;
            this.ipv4Count = ipv4Count;
            this.ipv6Count = ipv6Count;
        }
    }

    public AutoUpdatingCidrDeny(Path cacheFile) throws IOException {
        this(cacheFile, CN_IPV4, CN_IPV6, Clock.system(ZONE));
    }

    AutoUpdatingCidrDeny(Path cacheFile, URI ipv4Url, URI ipv6Url, Clock clock) throws IOException {
        this.cacheFile = cacheFile.toAbsolutePath();
        this.ipv4Url = ipv4Url;
        this.ipv6Url = ipv6Url;
        this.clock = clock;
        Files.createDirectories(this.cacheFile.getParent());
        if (Files.exists(this.cacheFile)) {
            try {
                current = readCache();
            } catch (IOException | RuntimeException error) {
                LOG.log(Level.WARNING, "Invalid CIDR cache; downloading a replacement", error);
            }
        }
        if (current == null) {
            refreshNow();
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "china-cidr-update");
            thread.setDaemon(true);
            return thread;
        });
        scheduler.scheduleWithFixedDelay(() -> {
            try {
                refreshIfNeeded();
            } catch (Exception error) {
                LOG.log(Level.WARNING, "CIDR update failed; keeping existing rules and retrying tomorrow", error);
            }
        }, 0, 24, TimeUnit.HOURS);
    }

    public boolean isDenied(String ip) {
        return current.matcher.isDenied(ip);
    }

    public Instant getLastUpdatedAt() {
        return current.updatedAt;
    }

    public synchronized void refreshNow() throws IOException {
        if (closed) throw new IOException("CIDR updater is closed");
        String ipv4 = download(ipv4Url);
        String ipv6 = download(ipv6Url);
        Instant updatedAt = clock.instant();
        Snapshot next = buildSnapshot(ipv4, ipv6, updatedAt);
        Properties cache = new Properties();
        cache.setProperty("ipv4Source", ipv4Url.toString());
        cache.setProperty("ipv6Source", ipv6Url.toString());
        cache.setProperty("updatedAt", updatedAt.toString());
        cache.setProperty("ipv4", ipv4);
        cache.setProperty("ipv6", ipv6);

        // Commit both families together, then publish the fully built matcher.
        Path temporary = Files.createTempFile(cacheFile.getParent(), "cidr-", ".tmp");
        try {
            try (OutputStream output = Files.newOutputStream(temporary)) {
                cache.store(output, "IPdeny CN CIDR cache");
            }
            Files.move(temporary, cacheFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            current = next;
        } finally {
            Files.deleteIfExists(temporary);
        }
        LOG.info("China CIDR updated: IPv4=" + next.ipv4Count + ", IPv6=" + next.ipv6Count);
    }

    synchronized void refreshIfNeeded() throws IOException {
        if (closed) return;
        YearMonth last = YearMonth.from(current.updatedAt.atZone(ZONE));
        YearMonth now = YearMonth.from(clock.instant().atZone(ZONE));
        if (!last.equals(now)) refreshNow();
    }

    private Snapshot readCache() throws IOException {
        if (Files.size(cacheFile) > MAX_BYTES * 3L) throw new IOException("CIDR cache is too large");
        Properties cache = new Properties();
        try (InputStream input = Files.newInputStream(cacheFile)) {
            cache.load(input);
        }
        if (!ipv4Url.toString().equals(cache.getProperty("ipv4Source"))
                || !ipv6Url.toString().equals(cache.getProperty("ipv6Source"))) {
            throw new IOException("CIDR cache belongs to a different source");
        }
        try {
            return buildSnapshot(cache.getProperty("ipv4"), cache.getProperty("ipv6"),
                    Instant.parse(cache.getProperty("updatedAt", "")));
        } catch (RuntimeException error) {
            throw new IOException("Invalid CIDR cache", error);
        }
    }

    private static Snapshot buildSnapshot(String ipv4, String ipv6, Instant updatedAt) throws IOException {
        CidrDeny matcher = new CidrDeny();
        int v4Count = addRules(matcher, ipv4, false);
        int v6Count = addRules(matcher, ipv6, true);
        return new Snapshot(matcher, updatedAt, v4Count, v6Count);
    }

    private static int addRules(CidrDeny matcher, String text, boolean ipv6) throws IOException {
        if (text == null) throw new IOException("Missing CIDR data");
        int count = 0;
        for (String raw : text.split("\\R")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            try {
                int slash = line.indexOf('/');
                if (slash <= 0 || line.contains(":") != ipv6) {
                    throw new IllegalArgumentException("Wrong address family or missing prefix");
                }
                matcher.add(line);
                int prefix = Integer.parseInt(line.substring(slash + 1));
                if (prefix == 0) throw new IllegalArgumentException("Country list cannot contain /0");
                if (!ipv6) {
                    // Apply each IPv4 rule to its mapped IPv6 spelling as well.
                    matcher.add("::ffff:" + line.substring(0, slash) + "/" + (96 + prefix));
                }
                count++;
            } catch (IllegalArgumentException error) {
                throw new IOException("Invalid IPv" + (ipv6 ? "6" : "4") + " CIDR: " + line, error);
            }
        }
        if (count == 0) throw new IOException("Empty IPv" + (ipv6 ? "6" : "4") + " list");
        return count;
    }

    private static String download(URI uri) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(30_000);
        connection.setInstanceFollowRedirects(true);
        connection.setRequestProperty("User-Agent", "ChinaCidrUpdater/1.0");
        connection.setRequestProperty("Accept", "text/plain");
        try {
            int status = connection.getResponseCode();
            if (status != 200) throw new IOException("CIDR download returned HTTP " + status);
            byte[] body;
            try (InputStream raw = connection.getInputStream()) {
                body = readLimited(raw);
            }
            long expected = connection.getContentLengthLong();
            if (expected >= 0 && body.length != expected) throw new IOException("Incomplete CIDR download");
            if ("gzip".equalsIgnoreCase(connection.getContentEncoding())) {
                try (InputStream gzip = new GZIPInputStream(new ByteArrayInputStream(body))) {
                    body = readLimited(gzip);
                }
            }
            return new String(body, StandardCharsets.UTF_8);
        } finally {
            connection.disconnect();
        }
    }

    private static byte[] readLimited(InputStream input) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        int length;
        while ((length = input.read(buffer)) != -1) {
            if (System.nanoTime() > deadline) throw new SocketTimeoutException("CIDR transfer timed out");
            if (bytes.size() + length > MAX_BYTES) throw new IOException("CIDR download is too large");
            bytes.write(buffer, 0, length);
        }
        return bytes.toByteArray();
    }

    @Override
    public synchronized void close() {
        closed = true;
        scheduler.shutdownNow();
    }
}
