/*
 * The sole network helper for the authority-bound EPUBCheck image producer.
 *
 * Production has exactly two modes and no upstream argument:
 *
 *   serve-discovery  - internal HTTP gateway, fixed Central HTTPS upstream
 *   prefetch-exact   - fresh fetch of one already-approved exact manifest
 *
 * Package-private constructors/interfaces are deliberate source-test seams.
 * They let a generated harness supply a loopback fixture without adding a
 * third public mode, an alternate production host, a proxy, or credentials.
 */
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;

public final class R2TMavenGateway {
  static final String CENTRAL = "https://repo.maven.apache.org/maven2/";
  static final String CENTRAL_HOST = "repo.maven.apache.org";
  static final int CENTRAL_PORT = 443;
  static final int PORT = 18080;
  static final int MAX_FILES = 4096;
  static final long MAX_BYTES = 2147483648L;
  static final Path CONFIG = Paths.get("/r2t/config");
  static final Path CACHE = Paths.get("/r2t/cache");
  static final Path OUTPUT = Paths.get("/r2t/output");
  static final Path ROOT_POM = CONFIG.resolve("root-pom.xml");
  static final Path ROOT_POM_SHA256 = CONFIG.resolve("root-pom.sha256");
  static final Path SEEDS = CONFIG.resolve("seeds.tsv");
  static final Path MANIFEST = CONFIG.resolve("canonical-manifest.tsv");
  static final Path CLIENT_CIDR = CONFIG.resolve("client-cidr.txt");

  static final Set<String> FAMILIES = Collections.unmodifiableSet(
      new HashSet<String>(Arrays.asList(
          "org.apache.maven.plugins", "org.apache.maven",
          "org.apache.maven.shared", "org.apache.maven.resolver",
          "org.apache.maven.surefire", "org.apache.maven.doxia",
          "org.apache.maven.reporting", "org.codehaus.plexus",
          "org.codehaus.mojo", "org.sonatype.plexus", "org.eclipse.sisu",
          "org.eclipse.aether", "org.apache.felix", "org.sonatype.central",
          "net.sf.saxon")));
  static final Set<String> BAD_CLASSIFIERS = Collections.unmodifiableSet(
      new HashSet<String>(Arrays.asList(
          "sources", "javadoc", "tests", "test-sources")));

  private R2TMavenGateway() {}

  public static void main(String[] args) {
    try {
      if (args.length != 1) {
        throw new Refusal("exactly one production mode is required");
      }
      if ("serve-discovery".equals(args[0])) {
        serveProduction();
      } else if ("prefetch-exact".equals(args[0])) {
        prefetchProduction();
      } else {
        throw new Refusal("unknown production mode");
      }
    } catch (Ceiling failure) {
      log("ceiling", "terminal", safe(failure.getMessage()));
      System.exit(64);
    } catch (IOException failure) {
      log("network-failure", "terminal", safe(failure.getMessage()));
      System.exit(64);
    } catch (Throwable failure) {
      log("refused", "terminal", safe(failure.getMessage()));
      System.exit(64);
    }
  }

  static void serveProduction() throws Exception {
    refuseInjectionEnvironment();
    Map<String, Seed> seeds = readSeeds(SEEDS);
    byte[] rootPom = regularBytes(ROOT_POM, 16 * 1024 * 1024);
    String rootSha256 = oneLine(ROOT_POM_SHA256);
    if (!exactHex(rootSha256, 64, "root pom SHA-256")
        .equals(hex("SHA-256", rootPom))) {
      throw new Refusal("root pom differs from bound SHA-256");
    }
    Engine engine = new Engine(new CentralTransport(), new Budget(), seeds,
                               CACHE, rootPom);
    engine.seedRootModel();
    final Cidr client = Cidr.parse(oneLine(CLIENT_CIDR));
    HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", PORT), 0);
    server.createContext("/", new GatewayHandler(engine, client));
    server.setExecutor(Executors.newFixedThreadPool(4));
    server.start();
    log("ready", "serve-discovery", "port=" + PORT);
  }

  static void prefetchProduction() throws Exception {
    refuseInjectionEnvironment();
    List<ManifestEntry> entries = readManifest(MANIFEST);
    requireEmptyDirectory(OUTPUT);
    Engine engine = new Engine(new CentralTransport(), new Budget(),
                               Collections.<String, Seed>emptyMap(),
                               OUTPUT, null);
    for (ManifestEntry entry : entries) {
      VerifiedFile payload = engine.fetchExact(entry);
      publish(OUTPUT, entry.path, payload.path);
      log("canonical-fetch", entry.path, entry.sha256);
    }
    verifyOutput(OUTPUT, entries);
    log("terminal", "complete", Integer.toString(entries.size()));
  }

  static void refuseInjectionEnvironment() {
    String[] keys = {
      "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
      "http_proxy", "https_proxy", "all_proxy", "no_proxy",
      "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS",
      "MAVEN_OPTS", "MAVEN_ARGS", "SSL_CERT_FILE", "SSL_CERT_DIR",
      "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE"
    };
    for (String key : keys) {
      if (System.getenv().containsKey(key)) {
        throw new Refusal("ambient injection variable is present: " + key);
      }
    }
  }

  interface Transport {
    Transfer get(String relativePath, Path target, long maximum) throws IOException;
  }

  interface CentralConnection extends Closeable {
    InputStream input() throws IOException;
    OutputStream output() throws IOException;
  }

  interface CentralConnector {
    CentralConnection open() throws IOException;
  }

  static final class Transfer {
    final long size;
    final String sha1;
    final String sha256;
    Transfer(long size, String sha1, String sha256) {
      this.size = size;
      this.sha1 = sha1;
      this.sha256 = sha256;
    }
  }

  static final class VerifiedFile {
    final Path path;
    final long size;
    final String sha1;
    final String sha256;
    VerifiedFile(Path path, long size, String sha1, String sha256) {
      this.path = path;
      this.size = size;
      this.sha1 = sha1;
      this.sha256 = sha256;
    }
  }

  static final class GatewayResponse {
    final byte[] inline;
    final VerifiedFile file;
    GatewayResponse(byte[] inline, VerifiedFile file) {
      this.inline = inline;
      this.file = file;
    }
    long size() { return inline == null ? file.size : inline.length; }
    void writeTo(OutputStream output) throws IOException {
      if (inline != null) {
        output.write(inline);
      } else {
        try (InputStream input = new BufferedInputStream(Files.newInputStream(file.path))) {
          byte[] buffer = new byte[65536];
          for (;;) {
            int count = input.read(buffer);
            if (count < 0) break;
            output.write(buffer, 0, count);
          }
        }
      }
    }
  }

  static final class SocketCentralConnection implements CentralConnection {
    final SSLSocket socket;
    SocketCentralConnection(SSLSocket socket) { this.socket = socket; }
    public InputStream input() throws IOException { return socket.getInputStream(); }
    public OutputStream output() throws IOException { return socket.getOutputStream(); }
    public void close() throws IOException { socket.close(); }
  }

  static final class TlsCentralConnector implements CentralConnector {
    public CentralConnection open() throws IOException {
      // Resolve exactly once and select exactly one address.  Failure on that
      // address is terminal for this request; there is no address fallback.
      InetAddress address = InetAddress.getByName(CENTRAL_HOST);
      Socket tcp = new Socket();
      SSLSocket tls = null;
      try {
        tcp.connect(new InetSocketAddress(address, CENTRAL_PORT), 30000);
        tcp.setSoTimeout(120000);
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        tls = (SSLSocket) factory.createSocket(
            tcp, CENTRAL_HOST, CENTRAL_PORT, true);
        tls.setSoTimeout(120000);
        SSLParameters parameters = tls.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        parameters.setServerNames(
            Collections.singletonList(new SNIHostName(CENTRAL_HOST)));
        tls.setSSLParameters(parameters);
        tls.startHandshake();
        return new SocketCentralConnection(tls);
      } catch (IOException failure) {
        if (tls != null) {
          try { tls.close(); } catch (IOException ignored) { }
        } else {
          try { tcp.close(); } catch (IOException ignored) { }
        }
        throw failure;
      } catch (RuntimeException failure) {
        if (tls != null) {
          try { tls.close(); } catch (IOException ignored) { }
        } else {
          try { tcp.close(); } catch (IOException ignored) { }
        }
        throw failure;
      }
    }
  }

  static final class FixedLengthInputStream extends FilterInputStream {
    long remaining;
    FixedLengthInputStream(InputStream input, long length) {
      super(input);
      remaining = length;
    }
    public int read() throws IOException {
      if (remaining == 0) return -1;
      int value = super.read();
      if (value < 0) throw new IOException("Central body ended before Content-Length");
      remaining--;
      return value;
    }
    public int read(byte[] output, int offset, int length) throws IOException {
      if (remaining == 0) return -1;
      int bounded = (int) Math.min((long) length, remaining);
      int count = super.read(output, offset, bounded);
      if (count < 0) throw new IOException("Central body ended before Content-Length");
      remaining -= count;
      return count;
    }
  }

  static final class CentralResponse {
    final int status;
    final long contentLength;
    final InputStream body;
    CentralResponse(int status, long contentLength, InputStream body) {
      this.status = status;
      this.contentLength = contentLength;
      this.body = body;
    }
  }

  static String responseLine(InputStream input) throws IOException {
    ByteArrayOutputStream line = new ByteArrayOutputStream();
    for (;;) {
      int value = input.read();
      if (value < 0) throw new IOException("Central response header ended early");
      if (value == '\n') {
        byte[] raw = line.toByteArray();
        if (raw.length == 0 || raw[raw.length - 1] != '\r') {
          throw new Refusal("Central response header is not CRLF framed");
        }
        return new String(raw, 0, raw.length - 1, StandardCharsets.US_ASCII);
      }
      if (value > 127 || value == 0 || line.size() >= 8192) {
        throw new Refusal("Central response header line is malformed/oversized");
      }
      line.write(value);
    }
  }

  static String oneHeader(Map<String, List<String>> headers, String name) {
    List<String> values = headers.get(name);
    if (values == null) return null;
    if (values.size() != 1) throw new Refusal("Central repeats " + name);
    return values.get(0);
  }

  static CentralResponse centralResponse(InputStream raw, long maximum)
      throws IOException {
    if (maximum < 0) throw new Refusal("negative Central response bound");
    BufferedInputStream input = new BufferedInputStream(raw);
    String statusLine = responseLine(input);
    if (!statusLine.matches("HTTP/1\\.[01] [0-9]{3}( .*)?")) {
      throw new Refusal("Central status line is malformed");
    }
    int status = Integer.parseInt(statusLine.substring(9, 12));
    Map<String, List<String>> headers = new LinkedHashMap<String, List<String>>();
    int headerBytes = statusLine.length() + 2;
    for (int count = 0; ; count++) {
      if (count == 256 || headerBytes > 65536) {
        throw new Refusal("Central response headers exceed their bound");
      }
      String line = responseLine(input);
      headerBytes += line.length() + 2;
      if (line.length() == 0) break;
      if (line.charAt(0) == ' ' || line.charAt(0) == '\t') {
        throw new Refusal("Central response uses a folded header");
      }
      int colon = line.indexOf(':');
      if (colon <= 0) throw new Refusal("Central response header lacks a name");
      String name = line.substring(0, colon);
      if (!name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+")) {
        throw new Refusal("Central response header name is malformed");
      }
      String rawValue = line.substring(colon + 1);
      for (int index = 0; index < rawValue.length(); index++) {
        char ch = rawValue.charAt(index);
        if (ch < 32 && ch != '\t') {
          throw new Refusal("Central response header value is malformed");
        }
      }
      String value = rawValue.trim();
      name = name.toLowerCase(Locale.ROOT);
      List<String> values = headers.get(name);
      if (values == null) {
        values = new ArrayList<String>();
        headers.put(name, values);
      }
      values.add(value);
    }
    if (status != 200) throw new IOException("Central returned status " + status);
    if (headers.containsKey("location")) {
      throw new Refusal("Central response unexpectedly names a redirect");
    }
    String encoding = oneHeader(headers, "content-encoding");
    if (encoding != null && !"identity".equalsIgnoreCase(encoding)) {
      throw new Refusal("Central response is content-encoded");
    }
    String transferEncoding = oneHeader(headers, "transfer-encoding");
    String lengthText = oneHeader(headers, "content-length");
    if (transferEncoding != null) {
      // Central's immutable payload endpoint is expected to provide a length
      // or close-delimit the response.  Rejecting transfer coding is a
      // fail-closed protocol choice and avoids a second HTTP implementation.
      throw new Refusal("Central response is transfer-encoded");
    }
    long declared = -1;
    if (lengthText != null) {
      if (!lengthText.matches("0|[1-9][0-9]*")) {
        throw new Refusal("Central Content-Length is malformed");
      }
      try {
        declared = Long.parseLong(lengthText);
      } catch (NumberFormatException failure) {
        throw new Refusal("Central Content-Length is outside long range");
      }
      if (declared > maximum) {
        throw new Ceiling("Central Content-Length exceeds remaining ceiling");
      }
    }
    return new CentralResponse(status, declared,
        declared < 0 ? input : new FixedLengthInputStream(input, declared));
  }

  static final class CentralTransport implements Transport {
    final CentralConnector connector;
    CentralTransport() { this(new TlsCentralConnector()); }
    CentralTransport(CentralConnector connector) {
      if (connector == null) throw new Refusal("Central connector is null");
      this.connector = connector;
    }
    public Transfer get(String relativePath, Path target, long maximum) throws IOException {
      validateCentralPath(relativePath, true);
      log("upstream", relativePath, "repo.maven.apache.org:443");
      byte[] request = ("GET /maven2/" + relativePath + " HTTP/1.1\r\n"
          + "Host: repo.maven.apache.org\r\n"
          + "Accept-Encoding: identity\r\n"
          + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
      // There is deliberately one connector.open(), one request write, and no
      // catch/loop around either operation.  An I/O failure is terminal.
      try (CentralConnection connection = connector.open()) {
        OutputStream requestStream = connection.output();
        requestStream.write(request);
        requestStream.flush();
        CentralResponse response = centralResponse(connection.input(), maximum);
        return streamTo(response.body, target, maximum);
      }
    }
  }

  static final class Budget {
    int files;
    long bytes;
    final Set<String> paths = new HashSet<String>();

    synchronized void before(String path, long declared) {
      if (paths.contains(path)) return;
      if (files >= MAX_FILES) throw new Ceiling("Central response file 4097");
      if (bytes < 0 || bytes > MAX_BYTES) {
        throw new Ceiling("Central byte counter is outside its ceiling");
      }
      if (declared >= 0 && declared > MAX_BYTES - bytes) {
        throw new Ceiling("Central response Content-Length crosses 2 GiB");
      }
    }

    synchronized void accept(String path, long size) {
      if (paths.contains(path)) return;
      if (files >= MAX_FILES) throw new Ceiling("Central response file 4097");
      if (size < 0) throw new Refusal("Central response size is negative");
      if (bytes < 0 || bytes > MAX_BYTES || size > MAX_BYTES - bytes) {
        throw new Ceiling("Central byte 2147483649");
      }
      paths.add(path);
      files++;
      bytes += size;
    }

    synchronized long remaining(long perResponseMaximum) {
      long remaining = MAX_BYTES - bytes;
      return Math.min(perResponseMaximum, remaining);
    }
  }

  static final class Seed {
    final Coordinate coordinate;
    final String sha1;
    final String sha256;

    Seed(Coordinate coordinate, String sha1, String sha256) {
      this.coordinate = coordinate;
      this.sha1 = exactHex(sha1, 40, "seed SHA-1");
      this.sha256 = exactHex(sha256, 64, "seed SHA-256");
    }
  }

  static final class ManifestEntry {
    final String path;
    final Coordinate coordinate;
    final long size;
    final String sha1;
    final String sha256;

    ManifestEntry(String path, Coordinate coordinate, long size,
                  String sha1, String sha256) {
      this.path = validatePayloadPath(path);
      this.coordinate = coordinate;
      if (!coordinate.path().equals(path)) throw new Refusal("manifest path/GAV differ");
      if (size < 0) throw new Refusal("manifest size is negative");
      this.size = size;
      this.sha1 = exactHex(sha1, 40, "manifest SHA-1");
      this.sha256 = exactHex(sha256, 64, "manifest SHA-256");
    }
  }

  static final class Coordinate {
    final String group;
    final String artifact;
    final String version;
    final String extension;
    final String classifier;
    final boolean localProject;

    Coordinate(String group, String artifact, String version,
               String extension, String classifier) {
      this(group, artifact, version, extension, classifier, false);
    }

    Coordinate(String group, String artifact, String version,
               String extension, String classifier, boolean localProject) {
      this.group = token(group, "groupId");
      this.artifact = token(artifact, "artifactId");
      this.version = token(version, "version");
      if (!localProject && version.toUpperCase(Locale.ROOT).contains("SNAPSHOT")) {
        throw new Refusal("snapshot coordinate");
      }
      if (!"jar".equals(extension) && !"pom".equals(extension)) {
        throw new Refusal("non-JAR/POM extension");
      }
      this.extension = extension;
      if (classifier != null) {
        classifier = token(classifier, "classifier");
        if (BAD_CLASSIFIERS.contains(classifier.toLowerCase(Locale.ROOT))) {
          throw new Refusal("source/test classifier");
        }
      }
      this.classifier = classifier;
      this.localProject = localProject;
    }

    String gav() { return group + ":" + artifact + ":" + version; }
    String key() { return gav() + ":" + (classifier == null ? "-" : classifier); }
    Coordinate asPom() {
      return new Coordinate(group, artifact, version, "pom", null, localProject);
    }
    Coordinate asJar() {
      return new Coordinate(group, artifact, version, "jar", null, localProject);
    }
    String path() {
      if (localProject) throw new Refusal("local project has no Central payload path");
      String name = artifact + "-" + version
          + (classifier == null ? "" : "-" + classifier) + "." + extension;
      return group.replace('.', '/') + "/" + artifact + "/" + version + "/" + name;
    }

    static Coordinate parse(String path) {
      path = validatePayloadPath(path);
      String[] parts = path.split("/");
      if (parts.length < 4) throw new Refusal("short Maven path");
      String artifact = parts[parts.length - 3];
      String version = parts[parts.length - 2];
      String filename = parts[parts.length - 1];
      StringBuilder group = new StringBuilder();
      for (int i = 0; i < parts.length - 3; i++) {
        if (i > 0) group.append('.');
        group.append(parts[i]);
      }
      String prefix = artifact + "-" + version;
      if (!filename.startsWith(prefix)) throw new Refusal("filename/GAV differ");
      String tail = filename.substring(prefix.length());
      int dot = tail.lastIndexOf('.');
      if (dot < 0) throw new Refusal("payload has no extension");
      String classifier = null;
      if (dot > 0) {
        if (tail.charAt(0) != '-') throw new Refusal("malformed classifier");
        classifier = tail.substring(1, dot);
      }
      Coordinate result = new Coordinate(group.toString(), artifact, version,
                                         tail.substring(dot + 1), classifier);
      if (!result.path().equals(path)) throw new Refusal("noncanonical Maven path");
      return result;
    }
  }

  static final class Engine {
    final Transport transport;
    final Budget budget;
    final Map<String, Seed> seeds;
    final Path cache;
    final byte[] rootPom;
    final Map<String, VerifiedFile> verified = new HashMap<String, VerifiedFile>();
    final Map<String, String> centralSha1 = new HashMap<String, String>();
    final Set<String> admitted = new HashSet<String>();
    final Set<String> authenticating = new HashSet<String>();
    final Set<String> modelled = new HashSet<String>();
    final Set<String> reportedAccepted = new HashSet<String>();
    final Map<String, EffectiveModel> models = new HashMap<String, EffectiveModel>();
    final MediationState projectState = new MediationState("project");
    final Map<String, ModelEdge> projectManagement = projectState.management;
    final Set<String> projectNearest = projectState.nearest;
    final Map<String, List<ExpansionContext>> projectDeferred =
        projectState.deferred;
    final List<String> projectRootOrder = projectState.rootOrder;
    final Map<String, MediationState> pluginStates =
        new LinkedHashMap<String, MediationState>();
    final Map<String, List<MediationState>> deferredStates =
        new LinkedHashMap<String, List<MediationState>>();
    volatile Refusal fatal;

    Engine(Transport transport, Budget budget, Map<String, Seed> seeds,
           Path cache, byte[] rootPom) {
      this.transport = transport;
      this.budget = budget;
      this.seeds = seeds;
      this.cache = cache;
      this.rootPom = rootPom;
      for (String path : seeds.keySet()) admitted.add(path);
    }

    synchronized void trip(Throwable failure) {
      if (fatal == null) {
        fatal = failure instanceof Refusal
            ? (Refusal) failure
            : new Refusal("gateway terminal failure: " + safe(failure.getMessage()));
      }
    }

    void seedRootModel() throws Exception {
      if (rootPom == null) throw new Refusal("discovery root pom is absent");
      RawPom root = RawPom.parse(rootPom, null);
      Coordinate local = root.localCoordinate();
      EffectiveModel model = effective(local, rootPom, new ArrayDeque<String>());
      projectManagement.clear();
      projectManagement.putAll(model.management);
      projectState.managementBound = true;
      List<String> seedPaths = new ArrayList<String>(seeds.keySet());
      Collections.sort(seedPaths);
      for (String path : seedPaths) {
        log("edge", path, "seed\tapproved-census\tmodel\t-");
      }
      walkProjectModel(local.gav(), model);
    }

    synchronized GatewayResponse request(String path) throws Exception {
      if (fatal != null) throw fatal;
      try {
        if (path.endsWith(".sha1")) {
          String payloadPath = path.substring(0, path.length() - 5);
          fetchPayload(payloadPath);
          return new GatewayResponse(
              (centralSha1.get(payloadPath) + "\n").getBytes(StandardCharsets.US_ASCII),
              null);
        }
        VerifiedFile payload = fetchPayload(path);
        reportAccepted(path, payload);
        return new GatewayResponse(null, payload);
      } catch (Exception failure) {
        trip(failure);
        throw failure;
      }
    }

    VerifiedFile fetchPayload(String path) throws Exception {
      path = validatePayloadPath(path);
      VerifiedFile prior = verified.get(path);
      if (prior != null) return prior;
      Coordinate coordinate = Coordinate.parse(path);
      Seed seed = seeds.get(path);
      if (seed == null && !admitted.contains(path)) {
        if (!FAMILIES.contains(coordinate.group)) {
          throw new Refusal("coordinate was not admitted before request");
        }
        // A family-root JAR first authenticates its same-GAV POM, independent
        // of Maven request order, then admits the main unclassified JAR.
        if (coordinate.classifier != null) throw new Refusal("new classifier not admitted");
        log("edge", coordinate.asPom().path(), "family-root\trequest\tmodel\t-");
        authenticatePom(coordinate.asPom(), new ArrayDeque<String>());
        walkArtifactModel(coordinate.gav(), models.get(coordinate.gav()));
        admitted.add(coordinate.asPom().path());
        admitted.add(coordinate.asJar().path());
        if (!admitted.contains(path)) throw new Refusal("family path is not main JAR/POM");
        prior = verified.get(path);
        if (prior != null) return prior;
      }
      if (seed == null && !modelled.contains(coordinate.gav())) {
        authenticatePom(coordinate.asPom(), new ArrayDeque<String>());
        walkArtifactModel(coordinate.gav(), models.get(coordinate.gav()));
        prior = verified.get(path);
        if (prior != null) return prior;
      }
      VerifiedFile file = verifiedFetch(path, seed == null ? null : seed.sha1,
                                        seed == null ? null : seed.sha256, -1);
      verified.put(path, file);
      if ("pom".equals(coordinate.extension) && coordinate.classifier == null) {
        authenticatePom(coordinate, new ArrayDeque<String>());
        walkArtifactModel(coordinate.gav(), models.get(coordinate.gav()));
      }
      return file;
    }

    VerifiedFile fetchExact(ManifestEntry entry) throws Exception {
      VerifiedFile file = verifiedFetch(entry.path, entry.sha1, entry.sha256, entry.size);
      verified.put(entry.path, file);
      reportAccepted(entry.path, file);
      return file;
    }

    void reportAccepted(String path, VerifiedFile file) {
      if (reportedAccepted.add(path)) {
        log("accepted", path, Long.toString(file.size) + "\t" + file.sha1
            + "\t" + file.sha256);
      }
    }

    VerifiedFile verifiedFetch(String path, String expectedSha1,
                               String expectedSha256, long expectedSize) throws Exception {
      validatePayloadPath(path);
      String sidecar = path + ".sha1";
      budget.before(sidecar, -1);
      Path shaTemp = newTemporary(cache, "sha1");
      Transfer shaTransfer;
      try {
        shaTransfer = transport.get(sidecar, shaTemp, budget.remaining(4096));
      } catch (Exception failure) {
        Files.deleteIfExists(shaTemp);
        throw failure;
      }
      budget.accept(sidecar, shaTransfer.size);
      String sha1;
      try {
        sha1 = parseSha1(regularBytes(shaTemp, 4096));
      } finally {
        Files.deleteIfExists(shaTemp);
      }
      if (expectedSha1 != null && !expectedSha1.equals(sha1)) {
        throw new Refusal("approved seed/manifest SHA-1 differs");
      }
      long maximum = expectedSize >= 0 ? expectedSize : budget.remaining(MAX_BYTES);
      maximum = budget.remaining(maximum);
      budget.before(path, expectedSize);
      Path payload = newTemporary(cache, "payload");
      Transfer transfer;
      try {
        transfer = transport.get(path, payload, maximum);
      } catch (Exception failure) {
        Files.deleteIfExists(payload);
        throw failure;
      }
      if (expectedSize >= 0 && transfer.size != expectedSize) {
        Files.deleteIfExists(payload);
        throw new Refusal("canonical payload size differs");
      }
      budget.accept(path, transfer.size);
      if (!sha1.equals(transfer.sha1)) {
        Files.deleteIfExists(payload);
        throw new Refusal("Central SHA-1 mismatch");
      }
      if (expectedSha256 != null && !expectedSha256.equals(transfer.sha256)) {
        Files.deleteIfExists(payload);
        throw new Refusal("approved seed/manifest SHA-256 differs");
      }
      setMode(payload, 0644);
      centralSha1.put(path, sha1);
      log("verified", path, Long.toString(transfer.size) + "\t" + sha1
          + "\t" + transfer.sha256);
      return new VerifiedFile(payload, transfer.size, sha1, transfer.sha256);
    }

    void authenticatePom(Coordinate pom, Deque<String> stack) throws Exception {
      pom = pom.asPom();
      String key = pom.gav();
      if (modelled.contains(key)) return;
      if (stack.contains(key) || authenticating.contains(key)) {
        throw new Refusal("raw-parent/effective-model cycle");
      }
      authenticating.add(key);
      stack.addLast(key);
      try {
        admitted.add(pom.path());
        VerifiedFile file = verified.get(pom.path());
        if (file == null) {
          Seed seed = seeds.get(pom.path());
          file = verifiedFetch(pom.path(), seed == null ? null : seed.sha1,
                               seed == null ? null : seed.sha256, -1);
          verified.put(pom.path(), file);
        }
        byte[] bytes = regularBytes(file.path, 16 * 1024 * 1024);
        EffectiveModel model = effective(pom, bytes, stack);
        models.put(key, model);
        modelled.add(key);
      } finally {
        stack.removeLast();
        authenticating.remove(key);
      }
    }

    EffectiveModel effective(Coordinate coordinate, byte[] bytes,
                             Deque<String> stack) throws Exception {
      EffectiveModel cached = models.get(coordinate.gav());
      if (cached != null) return cached;
      RawPom raw = RawPom.parse(bytes, coordinate);
      EffectiveModel parent = null;
      if (raw.parent != null) {
        Coordinate parentPom = resolveCoordinate(raw.parent, raw.baseProperties(),
                                                 "pom", null);
        admitted.add(parentPom.path());
        log("edge", parentPom.path(), "raw-parent\t" + coordinate.gav()
            + "\tmodel\t-");
        authenticatePom(parentPom, stack);
        parent = models.get(parentPom.gav());
        if (parent == null) throw new Refusal("parent did not produce an effective model");
      }
      EffectiveModel model = EffectiveModel.merge(parent, raw);
      // Child-first management: imported BOM fills only missing keys.
      List<ModelEdge> imports = new ArrayList<ModelEdge>(model.managementRaw);
      for (ModelEdge dependency : imports) {
        String scope = dependency.owner.resolve(dependency.raw.scope, "");
        String type = dependency.owner.resolve(dependency.raw.type, "jar");
        if ("import".equals(scope) && "pom".equals(type)) {
          Coordinate bom = model.coordinate(dependency, "pom", null);
          admitted.add(bom.path());
          log("edge", bom.path(), "imported-bom\t" + coordinate.gav()
              + "\tmodel\t-");
          authenticatePom(bom, stack);
          EffectiveModel imported = models.get(bom.gav());
          if (imported == null) throw new Refusal("imported BOM has no model");
          for (Map.Entry<String, ModelEdge> item : imported.management.entrySet()) {
            if (!model.management.containsKey(item.getKey())) {
              model.management.put(item.getKey(), item.getValue());
            }
          }
        }
      }
      models.put(coordinate.gav(), model);
      return model;
    }

    void walkProjectModel(String modelGav, EffectiveModel model) throws Exception {
      if (model == null) throw new Refusal("local project has no effective model");
      Deque<WalkItem> queue = new ArrayDeque<WalkItem>();
      enqueue(queue, model.dependencies, modelGav, "compile", 1,
              Collections.<String>emptySet());
      walkBreadthFirst(queue, projectState);

      Set<ModelEdge> assignedPluginDependencies = new HashSet<ModelEdge>();
      for (ModelEdge plugin : model.plugins) {
        String group = plugin.owner.resolve(plugin.raw.group, null);
        String artifact = plugin.owner.resolve(plugin.raw.artifact, null);
        if (group == null || artifact == null) throw new Refusal("plugin lacks G/A");
        String realm = group + ":" + artifact;
        if (pluginStates.containsKey(realm)) {
          throw new Refusal("effective project repeats a plugin realm");
        }
        MediationState state = new MediationState("plugin:" + realm);
        pluginStates.put(realm, state);
        Deque<WalkItem> pluginQueue = new ArrayDeque<WalkItem>();
        pluginQueue.addLast(new WalkItem(plugin, modelGav, "compile", 1,
                                         Collections.<String>emptySet()));
        for (ModelEdge dependency : model.pluginDependencies) {
          if (realm.equals(pluginOwnerKey(dependency))) {
            assignedPluginDependencies.add(dependency);
            pluginQueue.addLast(new WalkItem(dependency, modelGav, "compile", 1,
                                             Collections.<String>emptySet()));
          }
        }
        walkBreadthFirst(pluginQueue, state);
      }
      if (assignedPluginDependencies.size() != model.pluginDependencies.size()) {
        throw new Refusal("plugin dependency has no effective plugin realm");
      }
    }

    void walkArtifactModel(String modelGav, EffectiveModel model) throws Exception {
      if (model == null) throw new Refusal("authenticated family POM has no model");
      List<MediationState> states = deferredStates.get(modelGav);
      if (states == null || states.isEmpty()) {
        // A default-lifecycle family root is an independent plugin realm.  It
        // must not mediate against project dependencies or another plugin.
        MediationState implicit = new MediationState("implicit-plugin:" + modelGav);
        expandStateThrough(implicit, modelGav, model);
        return;
      }
      for (MediationState state : new ArrayList<MediationState>(states)) {
        expandStateThrough(state, modelGav, model);
      }
    }

    String pluginOwnerKey(ModelEdge dependency) {
      RawDependency plugin = dependency.raw.pluginOwner;
      if (plugin == null) throw new Refusal("plugin dependency lost its realm");
      String group = dependency.owner.resolve(plugin.group, null);
      String artifact = dependency.owner.resolve(plugin.artifact, null);
      if (group == null || artifact == null) throw new Refusal("plugin realm lacks G/A");
      return group + ":" + artifact;
    }

    void expandStateThrough(MediationState state, String modelGav,
                            EffectiveModel supplied) throws Exception {
      int rootIndex = state.rootOrder.indexOf(modelGav);
      if (rootIndex < 0) {
        expandOneStateModel(state, modelGav, supplied);
        return;
      }
      // No direct POM may expand alone: doing so would let its depth-three
      // edges run before a sibling's depth-two edges.  Authenticate the fixed
      // complete direct frontier lazily, enqueue it in root order, then run
      // one BFS.  Verification is not reported as accepted until Maven
      // actually requests each payload.
      Deque<WalkItem> frontier = new ArrayDeque<WalkItem>();
      for (String rootGav : state.rootOrder) {
        if (state.walked.contains(rootGav)) continue;
        List<ExpansionContext> contexts = state.deferred.get(rootGav);
        EffectiveModel model = rootGav.equals(modelGav) ? supplied : models.get(rootGav);
        if (model == null) {
          if (contexts == null || contexts.isEmpty()) {
            throw new Refusal("root mediation frontier lost its model context");
          }
          authenticatePom(contexts.get(0).coordinate.asPom(),
                          new ArrayDeque<String>());
          model = models.get(rootGav);
        }
        if (model == null) throw new Refusal("root POM has no effective model");
        state.walked.add(rootGav);
        if (!state.managementBound) {
          state.management.putAll(model.management);
          state.managementBound = true;
        }
        contexts = state.deferred.remove(rootGav);
        if (contexts == null || contexts.isEmpty()) {
          enqueue(frontier, model.dependencies, rootGav, "compile", 2,
                  Collections.<String>emptySet());
        } else {
          for (ExpansionContext context : contexts) {
            enqueue(frontier, model.dependencies, rootGav, context.parentScope,
                    context.depth, context.exclusions);
          }
        }
      }
      walkBreadthFirst(frontier, state);
    }

    void expandOneStateModel(MediationState state, String modelGav,
                             EffectiveModel supplied) throws Exception {
      if (state.walked.contains(modelGav)) return;
      List<ExpansionContext> contexts = state.deferred.get(modelGav);
      EffectiveModel model = supplied;
      if (model == null) model = models.get(modelGav);
      if (model == null) {
        if (contexts == null || contexts.isEmpty()) {
          throw new Refusal("mediation state lacks an authenticated model context");
        }
        authenticatePom(contexts.get(0).coordinate.asPom(),
                        new ArrayDeque<String>());
        model = models.get(modelGav);
      }
      if (model == null) throw new Refusal("authenticated POM has no effective model");
      if (!state.walked.add(modelGav)) return;
      if (!state.managementBound) {
        state.management.putAll(model.management);
        state.managementBound = true;
      }
      Deque<WalkItem> queue = new ArrayDeque<WalkItem>();
      contexts = state.deferred.remove(modelGav);
      if (contexts == null || contexts.isEmpty()) {
        enqueue(queue, model.dependencies, modelGav, "compile", 2,
                Collections.<String>emptySet());
      } else {
        for (ExpansionContext context : contexts) {
          enqueue(queue, model.dependencies, modelGav, context.parentScope,
                  context.depth, context.exclusions);
        }
      }
      walkBreadthFirst(queue, state);
    }

    void enqueue(Deque<WalkItem> queue, List<ModelEdge> edges, String from,
                 String parentScope, int depth, Set<String> exclusions) {
      for (ModelEdge edge : edges) {
        queue.addLast(new WalkItem(edge, from, parentScope, depth,
                                   new LinkedHashSet<String>(exclusions)));
      }
    }

    void deferExpansion(MediationState state, Coordinate payload, String scope,
                        int depth, Set<String> exclusions, boolean rootDirect) {
      List<ExpansionContext> contexts = state.deferred.get(payload.gav());
      if (contexts == null) {
        contexts = new ArrayList<ExpansionContext>();
        state.deferred.put(payload.gav(), contexts);
      }
      contexts.add(new ExpansionContext(payload, scope, depth,
          new LinkedHashSet<String>(exclusions)));
      List<MediationState> states = deferredStates.get(payload.gav());
      if (states == null) {
        states = new ArrayList<MediationState>();
        deferredStates.put(payload.gav(), states);
      }
      if (!states.contains(state)) states.add(state);
      if (rootDirect && !state.rootOrder.contains(payload.gav())) {
        state.rootOrder.add(payload.gav());
      }
    }

    void walkBreadthFirst(Deque<WalkItem> queue, MediationState state)
        throws Exception {
      while (!queue.isEmpty()) {
        WalkItem item = queue.removeFirst();
        ModelEdge edge = item.edge;
        RawDependency raw = edge.raw;
        EffectiveModel owner = edge.owner;
        String group = owner.resolve(raw.group, null);
        String artifact = owner.resolve(raw.artifact, null);
        if (group == null || artifact == null) throw new Refusal("edge lacks G/A");
        String ga = group + ":" + artifact;
        if (matchesExclusion(item.exclusions, group, artifact)) continue;
        String type = owner.resolve(raw.type, "jar");
        if (!"jar".equals(type) && !"pom".equals(type)) {
          throw new Refusal("edge type is not jar/pom");
        }
        String classifier = owner.resolve(raw.classifier, null);
        String nearestKey = ga + ":" + type + ":"
            + (classifier == null ? "-" : classifier);
        // Maven first injects missing dependency fields from the dependency's
        // own effective model.  Resolver's ClassicDependencyManager is a
        // separate layer: its version/scope/optional values only dominate
        // below the direct dependency level (manager depth >= 2).
        ModelEdge modelManaged = owner.management.get(nearestKey);
        ModelEdge resolverManaged = state.management.get(nearestKey);
        String optional = owner.resolve(raw.optional, null);
        if (item.depth >= 2 && resolverManaged != null) {
          String managedOptional = resolverManaged.owner.resolve(
              resolverManaged.raw.optional, null);
          if (managedOptional != null) optional = managedOptional;
        }
        if (optional == null) optional = "false";
        if (!"true".equals(optional) && !"false".equals(optional)) {
          throw new Refusal("edge optional value is not boolean");
        }
        if (item.depth > 1 && "true".equals(optional)) continue;
        String declaredScope = owner.resolve(raw.scope, null);
        if (declaredScope == null && modelManaged != null) {
          declaredScope = modelManaged.owner.resolve(modelManaged.raw.scope, null);
        }
        if (item.depth >= 2 && resolverManaged != null) {
          String managedScope = resolverManaged.owner.resolve(
              resolverManaged.raw.scope, null);
          if (managedScope != null) declaredScope = managedScope;
        }
        if (declaredScope == null) declaredScope = "compile";
        String scope = propagatedScope(item.parentScope, declaredScope, item.depth);
        if (scope == null) continue;
        if (!state.nearest.add(nearestKey)) continue;
        String version = owner.resolve(raw.version, null);
        if (version == null && modelManaged != null) {
          version = modelManaged.owner.resolve(modelManaged.raw.version, null);
        }
        if (item.depth >= 2 && resolverManaged != null) {
          String managedVersion = resolverManaged.owner.resolve(
              resolverManaged.raw.version, null);
          if (managedVersion != null) version = managedVersion;
        }
        if (version == null) throw new Refusal("edge version is unresolved");
        Coordinate payload = new Coordinate(group, artifact, version, type, classifier);
        if (classifier != null && !seeds.containsKey(payload.path())) {
          throw new Refusal("classifier is not an exact approved seed row");
        }
        Set<String> childExclusions = new LinkedHashSet<String>(item.exclusions);
        addResolvedExclusions(childExclusions, raw, owner);
        // Model injection fills exclusions only when the declaration has
        // none.  ClassicDependencyManager then unions resolver-managed
        // exclusions with that effective declaration at every depth.
        if (raw.exclusions.isEmpty() && modelManaged != null) {
          addResolvedExclusions(childExclusions, modelManaged.raw,
                                modelManaged.owner);
        }
        if (resolverManaged != null) {
          addResolvedExclusions(childExclusions, resolverManaged.raw,
                                resolverManaged.owner);
        }
        List<String> sortedExclusions = new ArrayList<String>(childExclusions);
        Collections.sort(sortedExclusions);
        log("edge", payload.path(), edge.kind + "\t" + item.from + "\t"
            + scope + "\t" + (sortedExclusions.isEmpty() ? "-"
                : join(sortedExclusions, ",")));
        Coordinate pom = payload.asPom();
        admitted.add(pom.path());
        admitted.add(payload.path());
        // The authenticated local root establishes direct admission without
        // contacting Central.  Maven's first POM/JAR request authenticates
        // that remote model and resumes this exact mediation context.  Scope,
        // exclusions and root nearest-wins choices must not be reset merely
        // because the remote POM bytes arrive later.
        if (item.depth == 1) {
          deferExpansion(state, payload, scope, item.depth + 1,
                         childExclusions, true);
          continue;
        }
        // Nested POMs, including complete approved seeds, must authenticate
        // and enqueue their children on this same queue.  Deferring a seeded
        // POM until Maven happened to request it would restart traversal and
        // make equal-depth nearest-wins mediation depend on request order.
        // Authentication still verifies the seed checksums; only the later
        // accepted event remains tied to Maven's actual request.
        boolean completeSeed = seeds.containsKey(pom.path())
            && ("pom".equals(type) || seeds.containsKey(payload.path()));
        if (completeSeed) {
          // Retain the model-to-state association used by a later Maven POM
          // request.  The state is marked walked below, so that request is a
          // no-op for graph expansion instead of creating an implicit realm.
          deferExpansion(state, payload, scope, item.depth + 1,
                         childExclusions, false);
        }
        authenticatePom(pom, new ArrayDeque<String>());
        EffectiveModel child = models.get(pom.gav());
        if (child == null) throw new Refusal("edge POM has no effective model");
        if (!state.walked.add(pom.gav())) continue;
        enqueue(queue, child.dependencies, pom.gav(), scope, item.depth + 1,
                childExclusions);
      }
    }

    void addResolvedExclusions(Set<String> target, RawDependency source,
                               EffectiveModel sourceOwner) {
      for (String exclusion : source.exclusions) {
        int split = exclusion.indexOf(':');
        String excludedGroup = sourceOwner.resolve(
            exclusion.substring(0, split), null);
        String excludedArtifact = sourceOwner.resolve(
            exclusion.substring(split + 1), null);
        validateExclusionPart(excludedGroup, "groupId");
        validateExclusionPart(excludedArtifact, "artifactId");
        target.add(excludedGroup + ":" + excludedArtifact);
      }
    }

    boolean matchesExclusion(Set<String> exclusions, String group, String artifact) {
      for (String exclusion : exclusions) {
        int split = exclusion.indexOf(':');
        if (split <= 0 || split == exclusion.length() - 1
            || exclusion.indexOf(':', split + 1) >= 0) {
          throw new Refusal("effective exclusion is malformed");
        }
        String excludedGroup = exclusion.substring(0, split);
        String excludedArtifact = exclusion.substring(split + 1);
        validateExclusionPart(excludedGroup, "groupId");
        validateExclusionPart(excludedArtifact, "artifactId");
        if (("*".equals(excludedGroup) || group.equals(excludedGroup))
            && ("*".equals(excludedArtifact) || artifact.equals(excludedArtifact))) {
          return true;
        }
      }
      return false;
    }

    String propagatedScope(String parent, String child, int depth) {
      if ("system".equals(child) || "import".equals(child)) {
        if ("system".equals(child)) throw new Refusal("system-scope edge is not portable");
        return null;
      }
      if (!Arrays.asList("compile", "runtime", "provided", "test").contains(child)) {
        throw new Refusal("unknown Maven dependency scope");
      }
      if (depth == 1) return child;
      if ("provided".equals(child) || "test".equals(child)) return null;
      if ("provided".equals(parent)) return "provided";
      if ("runtime".equals(parent)) return "runtime";
      if ("test".equals(parent)) return "test";
      return child;
    }
  }

  static final class GatewayHandler implements HttpHandler {
    final Engine engine;
    final Cidr clients;
    GatewayHandler(Engine engine, Cidr clients) { this.engine = engine; this.clients = clients; }

    public void handle(HttpExchange exchange) throws IOException {
      int status = 403;
      GatewayResponse response = new GatewayResponse(new byte[0], null);
      try {
        if (!"GET".equals(exchange.getRequestMethod())) throw new Refusal("method is not GET");
        if (!clients.contains(exchange.getRemoteAddress().getAddress())) {
          throw new Refusal("request did not originate on internal bridge");
        }
        URI uri = exchange.getRequestURI();
        if (uri.isAbsolute() || uri.getRawQuery() != null || uri.getRawFragment() != null
            || uri.getRawUserInfo() != null) throw new Refusal("request URI has authority/query");
        String raw = uri.getRawPath();
        if (raw == null || !raw.startsWith("/") || raw.contains("%")) {
          throw new Refusal("request path is encoded/malformed");
        }
        String path = raw.substring(1);
        response = engine.request(path);
        status = 200;
      } catch (Ceiling failure) {
        engine.trip(failure);
        status = 507;
        log("ceiling", "terminal", safe(failure.getMessage()));
      } catch (IOException failure) {
        engine.trip(failure);
        status = 502;
        log("network-failure", "terminal", safe(failure.getMessage()));
      } catch (Throwable failure) {
        engine.trip(failure);
        status = 403;
        log("refused", "coordinate", safe(failure.getMessage()));
      }
      Headers headers = exchange.getResponseHeaders();
      headers.set("Content-Type", "application/octet-stream");
      headers.set("Cache-Control", "no-store");
      exchange.sendResponseHeaders(status, response.size());
      OutputStream output = exchange.getResponseBody();
      response.writeTo(output);
      output.close();
    }
  }

  static final class Cidr {
    final byte[] network;
    final int bits;
    Cidr(byte[] network, int bits) { this.network = network; this.bits = bits; }

    static Cidr parse(String text) throws Exception {
      String[] parts = text.split("/", -1);
      if (parts.length != 2) throw new Refusal("client CIDR is malformed");
      String[] octets = parts[0].split("\\.", -1);
      if (octets.length != 4) throw new Refusal("client CIDR is not dotted IPv4");
      byte[] raw = new byte[4];
      for (int i = 0; i < octets.length; i++) {
        if (!octets[i].matches("0|[1-9][0-9]{0,2}")) {
          throw new Refusal("client CIDR octet is noncanonical");
        }
        int value;
        try { value = Integer.parseInt(octets[i]); }
        catch (NumberFormatException failure) { throw new Refusal("client CIDR octet malformed"); }
        if (value > 255) throw new Refusal("client CIDR octet out of range");
        raw[i] = (byte) value;
      }
      int bits;
      try { bits = Integer.parseInt(parts[1]); }
      catch (NumberFormatException failure) { throw new Refusal("client CIDR prefix malformed"); }
      if (bits < 0 || bits > 32) throw new Refusal("client CIDR prefix out of range");
      for (int bit = bits; bit < 32; bit++) {
        int mask = 1 << (7 - bit % 8);
        if ((raw[bit / 8] & mask) != 0) {
          throw new Refusal("client CIDR has nonzero host bits");
        }
      }
      return new Cidr(raw, bits);
    }

    boolean contains(InetAddress address) {
      if (!(address instanceof Inet4Address)) return false;
      byte[] raw = address.getAddress();
      for (int bit = 0; bit < bits; bit++) {
        int mask = 1 << (7 - bit % 8);
        if ((raw[bit / 8] & mask) != (network[bit / 8] & mask)) return false;
      }
      return true;
    }
  }

  static final class RawDependency {
    String group;
    String artifact;
    String version;
    String type;
    String classifier;
    String scope;
    String optional;
    RawDependency pluginOwner;
    final Set<String> exclusions = new LinkedHashSet<String>();
  }

  static final class ModelEdge {
    final RawDependency raw;
    final EffectiveModel owner;
    final String kind;
    ModelEdge(RawDependency raw, EffectiveModel owner, String kind) {
      this.raw = raw;
      this.owner = owner;
      this.kind = kind;
    }
  }

  static final class WalkItem {
    final ModelEdge edge;
    final String from;
    final String parentScope;
    final int depth;
    final Set<String> exclusions;
    WalkItem(ModelEdge edge, String from, String parentScope, int depth,
             Set<String> exclusions) {
      this.edge = edge;
      this.from = from;
      this.parentScope = parentScope;
      this.depth = depth;
      this.exclusions = exclusions;
    }
  }

  static final class ExpansionContext {
    final Coordinate coordinate;
    final String parentScope;
    final int depth;
    final Set<String> exclusions;
    ExpansionContext(Coordinate coordinate, String parentScope, int depth,
                     Set<String> exclusions) {
      this.coordinate = coordinate;
      this.parentScope = parentScope;
      this.depth = depth;
      this.exclusions = exclusions;
    }
  }

  static final class MediationState {
    final String identity;
    final Map<String, ModelEdge> management =
        new LinkedHashMap<String, ModelEdge>();
    final Set<String> nearest = new LinkedHashSet<String>();
    final Map<String, List<ExpansionContext>> deferred =
        new LinkedHashMap<String, List<ExpansionContext>>();
    final List<String> rootOrder = new ArrayList<String>();
    final Set<String> walked = new HashSet<String>();
    boolean managementBound;
    MediationState(String identity) { this.identity = identity; }
  }

  static final class RawPom {
    static final String FIXED_JAVA_VERSION = "1.8.0";
    String group;
    String artifact;
    String version;
    RawDependency parent;
    final Map<String, String> properties = new LinkedHashMap<String, String>();
    final List<RawDependency> management = new ArrayList<RawDependency>();
    final List<RawDependency> dependencies = new ArrayList<RawDependency>();
    final List<RawDependency> plugins = new ArrayList<RawDependency>();
    final List<RawDependency> pluginDependencies = new ArrayList<RawDependency>();

    Coordinate coordinate() {
      return coordinate(false);
    }

    Coordinate localCoordinate() {
      return coordinate(true);
    }

    Coordinate coordinate(boolean localProject) {
      String effectiveGroup = group;
      String effectiveVersion = version;
      if (effectiveGroup == null && parent != null) effectiveGroup = parent.group;
      if (effectiveVersion == null && parent != null) effectiveVersion = parent.version;
      if (effectiveGroup == null || artifact == null || effectiveVersion == null) {
        throw new Refusal("raw pom lacks resolvable project coordinate");
      }
      Map<String, String> base = baseProperties();
      return new Coordinate(resolveLiteral(effectiveGroup, base),
                            resolveLiteral(artifact, base),
                            resolveLiteral(effectiveVersion, base), "pom", null,
                            localProject);
    }

    Map<String, String> baseProperties() {
      Map<String, String> result = new LinkedHashMap<String, String>(properties);
      if (parent != null) {
        putAliases(result, "parent.groupId", parent.group);
        putAliases(result, "project.parent.groupId", parent.group);
        putAliases(result, "parent.version", parent.version);
        putAliases(result, "project.parent.version", parent.version);
      }
      String g = group != null ? group : parent == null ? null : parent.group;
      String v = version != null ? version : parent == null ? null : parent.version;
      putAliases(result, "project.groupId", g);
      putAliases(result, "pom.groupId", g);
      putAliases(result, "groupId", g);
      putAliases(result, "project.artifactId", artifact);
      putAliases(result, "pom.artifactId", artifact);
      putAliases(result, "artifactId", artifact);
      putAliases(result, "project.version", v);
      putAliases(result, "pom.version", v);
      putAliases(result, "version", v);
      return result;
    }

    static RawPom parse(byte[] bytes, Coordinate fallback) throws Exception {
      if (bytes.length > 16 * 1024 * 1024) throw new Refusal("pom exceeds 16 MiB");
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(false);
      factory.setXIncludeAware(false);
      factory.setExpandEntityReferences(false);
      setFeature(factory, "http://apache.org/xml/features/disallow-doctype-decl", true);
      setFeature(factory, "http://xml.org/sax/features/external-general-entities", false);
      setFeature(factory, "http://xml.org/sax/features/external-parameter-entities", false);
      setFeature(factory, "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
      try {
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
      } catch (IllegalArgumentException ignored) {
        // The four mandatory parser features above still close external input
        // on JDK 8 implementations without these JAXP 1.5 attributes.
      }
      InputSource source = new InputSource(new ByteArrayInputStream(bytes));
      source.setSystemId("urn:r2t:no-external-pom");
      Document document;
      try {
        javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
        builder.setErrorHandler(new DefaultHandler());
        document = builder.parse(source);
      } catch (Exception failure) {
        throw new Refusal("pom XML is malformed or contains forbidden external syntax");
      }
      Element project = document.getDocumentElement();
      if (!"project".equals(name(project))) throw new Refusal("pom root is not project");
      refuseRepositoryDeclarations(project);
      RawPom result = new RawPom();
      result.group = childText(project, "groupId");
      result.artifact = childText(project, "artifactId");
      result.version = childText(project, "version");
      Element parent = child(project, "parent");
      if (parent != null) result.parent = dependency(parent, true);
      Element properties = child(project, "properties");
      if (properties != null) {
        for (Element item : children(properties, null)) {
          if (result.properties.put(name(item), text(item)) != null) {
            throw new Refusal("pom repeats a property");
          }
        }
      }
      Element management = child(project, "dependencyManagement");
      if (management != null) {
        Element dependencies = child(management, "dependencies");
        if (dependencies != null) result.management.addAll(dependencies(dependencies));
      }
      Element dependencies = child(project, "dependencies");
      if (dependencies != null) result.dependencies.addAll(dependencies(dependencies));
      Element build = child(project, "build");
      readBuild(build, result);
      applyProfiles(project, result);
      if (fallback != null) {
        Coordinate actual = result.coordinate(fallback.localProject);
        if (!fallback.gav().equals(actual.gav())) {
          throw new Refusal("pom content coordinate differs from requested path");
        }
      }
      return result;
    }

    static void refuseRepositoryDeclarations(Element project) {
      if (child(project, "repositories") != null
          || child(project, "pluginRepositories") != null) {
        throw new Refusal("pom declares a repository outside fixed Central");
      }
      Element profiles = child(project, "profiles");
      if (profiles == null) return;
      for (Element profile : children(profiles, "profile")) {
        if (child(profile, "repositories") != null
            || child(profile, "pluginRepositories") != null) {
          throw new Refusal("pom profile declares a repository outside fixed Central");
        }
      }
    }

    static void readBuild(Element build, RawPom result) {
      if (build == null) return;
      Element plugins = child(build, "plugins");
      if (plugins == null) return;
      for (Element plugin : children(plugins, "plugin")) {
        RawDependency item = dependency(plugin, false);
        if (item.group == null) item.group = "org.apache.maven.plugins";
        if (item.type == null) item.type = "jar";
        result.plugins.add(item);
        Element pluginDependencies = child(plugin, "dependencies");
        if (pluginDependencies != null) {
          List<RawDependency> declared = dependencies(pluginDependencies);
          for (RawDependency dependency : declared) dependency.pluginOwner = item;
          result.pluginDependencies.addAll(declared);
        }
      }
    }

    static void applyProfiles(Element project, RawPom result) {
      Element profiles = child(project, "profiles");
      if (profiles == null) return;
      List<Element> all = children(profiles, "profile");
      Set<Element> explicit = new LinkedHashSet<Element>();
      List<Element> defaults = new ArrayList<Element>();
      for (Element profile : all) {
        Element activation = child(profile, "activation");
        if (activation == null) continue; // no -P: ordinary named profile is inactive
        boolean byDefault = "true".equals(childText(activation, "activeByDefault"));
        if (byDefault) defaults.add(profile);
        if (activationMatches(activation)) explicit.add(profile);
      }
      List<Element> active = new ArrayList<Element>(explicit);
      if (explicit.isEmpty()) active.addAll(defaults);
      for (Element profile : active) {
        Element properties = child(profile, "properties");
        if (properties != null) {
          for (Element item : children(properties, null)) {
            result.properties.put(name(item), text(item));
          }
        }
        Element management = child(profile, "dependencyManagement");
        if (management != null && child(management, "dependencies") != null) {
          result.management.addAll(dependencies(child(management, "dependencies")));
        }
        Element dependencies = child(profile, "dependencies");
        if (dependencies != null) result.dependencies.addAll(dependencies(dependencies));
        readBuild(child(profile, "build"), result);
      }
    }

    static boolean activationMatches(Element activation) {
      boolean hasCondition = false;
      boolean matches = true;
      Element file = child(activation, "file");
      if (file != null) {
        hasCondition = true;
        matches &= virtualEmptyProjectFileMatches(file);
      }
      String jdk = childText(activation, "jdk");
      if (jdk != null) {
        hasCondition = true;
        boolean negated = jdk.startsWith("!");
        String wanted = negated ? jdk.substring(1) : jdk;
        boolean selected = jdk8Matches(wanted);
        matches &= negated ? !selected : selected;
      }
      Element os = child(activation, "os");
      if (os != null) {
        hasCondition = true;
        if (childText(os, "version") != null) {
          throw new Refusal("kernel-version profile activation is not fixed");
        }
        matches &= activationToken(childText(os, "name"), "Linux");
        matches &= activationToken(childText(os, "family"), "unix");
        String arch = childText(os, "arch");
        if (arch != null) {
          boolean negated = arch.startsWith("!");
          String wanted = negated ? arch.substring(1) : arch;
          boolean selected = "amd64".equalsIgnoreCase(wanted)
              || "x86_64".equalsIgnoreCase(wanted);
          matches &= negated ? !selected : selected;
        }
      }
      Element property = child(activation, "property");
      if (property != null) {
        hasCondition = true;
        String propertyName = childText(property, "name");
        String wanted = childText(property, "value");
        if (propertyName == null) throw new Refusal("profile property activation lacks name");
        boolean absent = propertyName.startsWith("!");
        String key = absent ? propertyName.substring(1) : propertyName;
        if (key.length() == 0) {
          throw new Refusal("profile property activation has empty name");
        }
        String actual = fixedSystemProperty(key);
        if (wanted != null) {
          boolean negatedValue = wanted.startsWith("!");
          String expected = negatedValue ? wanted.substring(1) : wanted;
          if (expected.length() == 0) {
            throw new Refusal("profile property activation has empty negated value");
          }
          boolean equal = expected.equals(actual);
          matches &= negatedValue ? !equal : equal;
        } else {
          boolean present = actual != null && actual.length() != 0;
          matches &= absent ? !present : present;
        }
      }
      // activeByDefault is only the fallback selector.  If the same profile
      // also carries a matching real activator, Maven classifies it as
      // condition-active and it survives another explicit profile becoming
      // active in the same POM.
      return hasCondition && matches;
    }

    static boolean virtualEmptyProjectFileMatches(Element file) {
      List<Element> exists = children(file, "exists");
      List<Element> missing = children(file, "missing");
      if (exists.size() + missing.size() != 1) {
        throw new Refusal("file profile activation needs exactly one condition");
      }
      String path = text(exists.isEmpty() ? missing.get(0) : exists.get(0));
      validateVirtualProjectPath(path);
      // Maven 3.9.6 interpolates both names to the POM's project directory.
      // That directory itself exists even though the authenticated remote POM
      // has no checkout.  Every other safe relative path is modelled against
      // a fixed empty virtual basedir; never inspect the helper host.
      boolean pomDirectory = "${basedir}".equals(path)
          || "${project.basedir}".equals(path);
      return exists.isEmpty() ? !pomDirectory : pomDirectory;
    }

    static String validateVirtualProjectPath(String path) {
      if (path == null || path.length() > 1024 || path.startsWith("/")
          || path.contains("//") || path.contains("\\")
          || path.indexOf('\0') >= 0) {
        throw new Refusal("file profile path is not a safe relative path");
      }
      String relative = path;
      if ("${basedir}".equals(relative)
          || "${project.basedir}".equals(relative)) {
        return path; // fixed virtual root token; never resolved on the host
      }
      if (relative.startsWith("${basedir}/")) {
        relative = relative.substring("${basedir}/".length());
      } else if (relative.startsWith("${project.basedir}/")) {
        relative = relative.substring("${project.basedir}/".length());
      } else if (relative.contains("${")) {
        throw new Refusal("file profile path has an unsupported expression");
      }
      if (relative.endsWith("/")) relative = relative.substring(0, relative.length() - 1);
      if (relative.length() == 0) {
        throw new Refusal("file profile relative path is empty");
      }
      for (String part : relative.split("/", -1)) {
        if (part.length() == 0 || part.length() > 255
            || ".".equals(part) || "..".equals(part)
            || !part.matches("[A-Za-z0-9_.+\\-]+")) {
          throw new Refusal("file profile path has an unsafe component");
        }
      }
      return path;
    }

    static boolean jdk8Matches(String expression) {
      if (expression == null || expression.length() == 0) {
        throw new Refusal("empty JDK profile activation");
      }
      if (expression.startsWith("[") || expression.startsWith("(")) {
        if (!(expression.endsWith("]") || expression.endsWith(")"))) {
          throw new Refusal("malformed JDK profile range");
        }
        String body = expression.substring(1, expression.length() - 1);
        String[] bounds = body.split(",", -1);
        if (bounds.length != 2 || (bounds[0].length() == 0
            && bounds[1].length() == 0)) {
          throw new Refusal("unsupported JDK profile range");
        }
        boolean lowerInclusive = expression.charAt(0) == '[';
        boolean upperInclusive = expression.charAt(expression.length() - 1) == ']';
        int[] actual = javaVersion(FIXED_JAVA_VERSION);
        if (bounds[0].length() != 0) {
          int comparison = compareJavaVersions(actual, javaVersion(bounds[0]));
          if (comparison < 0 || (comparison == 0 && !lowerInclusive)) return false;
        }
        if (bounds[1].length() != 0) {
          int comparison = compareJavaVersions(actual, javaVersion(bounds[1]));
          if (comparison > 0 || (comparison == 0 && !upperInclusive)) return false;
        }
        return true;
      }
      // Maven's non-range form is a literal java.version prefix, not a
      // normalized feature-version comparison.
      javaVersion(expression); // validate the supported deterministic syntax
      return FIXED_JAVA_VERSION.startsWith(expression);
    }

    static int[] javaVersion(String value) {
      if (value == null || !value.matches(
          "(?:0|[1-9][0-9]*)(?:\\.(?:0|[1-9][0-9]*))*")) {
        throw new Refusal("unsupported JDK profile activation");
      }
      String[] fields = value.split("\\.");
      int[] parsed = new int[fields.length];
      for (int i = 0; i < fields.length; i++) {
        try {
          parsed[i] = Integer.parseInt(fields[i]);
        } catch (NumberFormatException failure) {
          throw new Refusal("JDK profile activation component is too large");
        }
      }
      int size = parsed.length;
      while (size > 1 && parsed[size - 1] == 0) size--;
      return Arrays.copyOf(parsed, size);
    }

    static int compareJavaVersions(int[] left, int[] right) {
      int size = Math.max(left.length, right.length);
      for (int i = 0; i < size; i++) {
        int a = i < left.length ? left[i] : 0;
        int b = i < right.length ? right[i] : 0;
        if (a < b) return -1;
        if (a > b) return 1;
      }
      return 0;
    }

    static boolean activationToken(String expression, String actual) {
      if (expression == null) return true;
      boolean negated = expression.startsWith("!");
      String wanted = negated ? expression.substring(1) : expression;
      boolean selected = wanted.equalsIgnoreCase(actual);
      return negated ? !selected : selected;
    }

    static String fixedSystemProperty(String key) {
      if ("style.color".equals(key)) return "never";
      if ("maven.repo.local".equals(key)) return "/opt/m2";
      if ("reuseForks".equals(key)) return "false";
      if ("failIfNoTests".equals(key)) return "true";
      if ("surefire.failIfNoSpecifiedTests".equals(key)) return "true";
      if ("java.version".equals(key)) return FIXED_JAVA_VERSION;
      if ("os.name".equals(key)) return "Linux";
      if ("os.arch".equals(key)) return "amd64";
      if ("user.home".equals(key)) return "/root";
      // Arbitrary user properties are absent because the Maven argv is exact,
      // but environment/JVM/Maven state has a much larger implicit property
      // surface.  Never turn an unmodelled live value into an invented
      // absence, especially for a negated activation.
      if (key.startsWith("env.") || key.startsWith("java.")
          || key.startsWith("jdk.") || key.startsWith("sun.")
          || key.startsWith("os.") || key.startsWith("user.")
          || key.startsWith("file.") || key.startsWith("path.")
          || key.startsWith("line.") || key.startsWith("maven.")
          || "basedir".equals(key) || "classworlds.conf".equals(key)
          || System.getProperties().containsKey(key)) {
        throw new Refusal("profile activation depends on unmodelled runtime property");
      }
      return null; // every other user property is absent from the exact argv
    }

    static List<RawDependency> dependencies(Element parent) {
      List<RawDependency> result = new ArrayList<RawDependency>();
      for (Element element : children(parent, "dependency")) {
        result.add(dependency(element, false));
      }
      return result;
    }

    static RawDependency dependency(Element element, boolean isParent) {
      RawDependency result = new RawDependency();
      result.group = childText(element, "groupId");
      result.artifact = childText(element, "artifactId");
      result.version = childText(element, "version");
      result.type = isParent ? "pom" : childText(element, "type");
      result.classifier = childText(element, "classifier");
      result.scope = childText(element, "scope");
      result.optional = childText(element, "optional");
      Element exclusions = child(element, "exclusions");
      if (exclusions != null) {
        for (Element exclusion : children(exclusions, "exclusion")) {
          String group = childText(exclusion, "groupId");
          String artifact = childText(exclusion, "artifactId");
          if (group == null || artifact == null) throw new Refusal("exclusion lacks G/A");
          result.exclusions.add(group + ":" + artifact);
        }
      }
      return result;
    }
  }

  static final class EffectiveModel {
    final Map<String, String> properties = new LinkedHashMap<String, String>();
    final Map<String, ModelEdge> management = new LinkedHashMap<String, ModelEdge>();
    final List<ModelEdge> managementRaw = new ArrayList<ModelEdge>();
    final List<ModelEdge> dependencies = new ArrayList<ModelEdge>();
    final List<ModelEdge> plugins = new ArrayList<ModelEdge>();
    final List<ModelEdge> pluginDependencies = new ArrayList<ModelEdge>();

    static EffectiveModel merge(EffectiveModel parent, RawPom raw) {
      EffectiveModel result = new EffectiveModel();
      if (parent != null) {
        result.properties.putAll(parent.properties);
      }
      result.properties.putAll(raw.properties);
      Map<String, String> base = raw.baseProperties();
      for (Map.Entry<String, String> item : base.entrySet()) {
        result.properties.put(item.getKey(), item.getValue());
      }
      // Resolve lazily only when a graph-affecting field consumes a value.
      // Maven permits unrelated configuration properties (for example the
      // pinned root's ${maven.build.timestamp}) that have no coordinate role.
      if (parent != null) {
        for (ModelEdge inherited : parent.management.values()) {
          ModelEdge edge = rebaseInherited(inherited, parent, result);
          result.management.put(result.managementKey(edge), edge);
        }
      }
      for (RawDependency item : raw.management) {
        result.managementRaw.add(new ModelEdge(item, result, "management"));
      }
      for (RawDependency item : raw.management) {
        ModelEdge edge = new ModelEdge(item, result, "management");
        String key = result.managementKey(edge);
        result.management.put(key, edge); // child replaces parent
      }
      mergeInherited(result.dependencies,
          parent == null ? Collections.<ModelEdge>emptyList() : parent.dependencies,
          raw.dependencies, parent, result, "dependency");
      mergeInherited(result.plugins,
          parent == null ? Collections.<ModelEdge>emptyList() : parent.plugins,
          raw.plugins, parent, result, "plugin");
      mergeInherited(result.pluginDependencies,
          parent == null ? Collections.<ModelEdge>emptyList() : parent.pluginDependencies,
          raw.pluginDependencies, parent, result, "plugin-dependency");
      return result;
    }

    static void mergeInherited(List<ModelEdge> target,
                               List<ModelEdge> inherited,
                               List<RawDependency> child,
                               EffectiveModel inheritedOwner,
                               EffectiveModel childOwner, String kind) {
      LinkedHashMap<String, ModelEdge> merged =
          new LinkedHashMap<String, ModelEdge>();
      for (ModelEdge inheritedEdge : inherited) {
        ModelEdge edge = rebaseInherited(inheritedEdge, inheritedOwner, childOwner);
        merged.put(inheritanceKey(edge), edge);
      }
      for (RawDependency raw : child) {
        ModelEdge edge = new ModelEdge(raw, childOwner, kind);
        // Maven inheritance is child-dominant for dependency and plugin
        // identity keys.  Replace before traversal so a parent scope/version
        // can never win merely because it was enqueued first.
        merged.put(inheritanceKey(edge), edge);
      }
      target.addAll(merged.values());
    }

    static ModelEdge rebaseInherited(ModelEdge edge,
                                     EffectiveModel inheritedOwner,
                                     EffectiveModel childOwner) {
      return edge.owner == inheritedOwner
          ? new ModelEdge(edge.raw, childOwner, edge.kind) : edge;
    }

    static String inheritanceKey(ModelEdge edge) {
      RawDependency raw = edge.raw;
      String group = edge.owner.resolve(raw.group, null);
      String artifact = edge.owner.resolve(raw.artifact, null);
      String type = edge.owner.resolve(raw.type, "jar");
      String classifier = edge.owner.resolve(raw.classifier, null);
      if (group == null || artifact == null) {
        throw new Refusal("inherited edge lacks G/A");
      }
      String realm = "";
      if (raw.pluginOwner != null) {
        String pluginGroup = edge.owner.resolve(raw.pluginOwner.group, null);
        String pluginArtifact = edge.owner.resolve(raw.pluginOwner.artifact, null);
        if (pluginGroup == null || pluginArtifact == null) {
          throw new Refusal("inherited plugin dependency lacks a realm");
        }
        realm = pluginGroup + ":" + pluginArtifact + "->";
      }
      return realm + group + ":" + artifact + ":" + type + ":"
          + (classifier == null ? "-" : classifier);
    }

    String managementKey(ModelEdge edge) {
      RawDependency raw = edge.raw;
      String group = edge.owner.resolve(raw.group, null);
      String artifact = edge.owner.resolve(raw.artifact, null);
      String type = edge.owner.resolve(raw.type, "jar");
      String classifier = edge.owner.resolve(raw.classifier, null);
      if (group == null || artifact == null) throw new Refusal("managed edge lacks G/A");
      return group + ":" + artifact + ":" + type + ":"
          + (classifier == null ? "-" : classifier);
    }

    String resolve(String value, String fallback) {
      if (value == null || value.length() == 0) return fallback;
      String current = value;
      for (int pass = 0; pass < 32; pass++) {
        int start = current.indexOf("${");
        if (start < 0) return current;
        int end = current.indexOf('}', start + 2);
        if (end < 0) throw new Refusal("unterminated pom expression");
        String key = current.substring(start + 2, end);
        String replacement = properties.get(key);
        if (replacement == null) throw new Refusal("unresolved pom expression: " + key);
        current = current.substring(0, start) + replacement + current.substring(end + 1);
      }
      throw new Refusal("pom expression recursion exceeds 32 substitutions");
    }

    Coordinate coordinate(ModelEdge edge, String defaultType,
                          String defaultClassifier) {
      RawDependency raw = edge.raw;
      String group = edge.owner.resolve(raw.group, null);
      String artifact = edge.owner.resolve(raw.artifact, null);
      String type = edge.owner.resolve(raw.type, defaultType);
      String classifier = edge.owner.resolve(raw.classifier, defaultClassifier);
      String version = edge.owner.resolve(raw.version, null);
      ModelEdge managed = management.get(group + ":" + artifact + ":" + type
          + ":" + (classifier == null ? "-" : classifier));
      if (version == null && managed != null) {
        version = managed.owner.resolve(managed.raw.version, null);
      }
      if (version == null) throw new Refusal("coordinate version is unresolved");
      return new Coordinate(group, artifact, version, type, classifier);
    }
  }

  static class Refusal extends RuntimeException {
    Refusal(String message) { super(message == null ? "unspecified refusal" : message); }
  }
  static final class Ceiling extends Refusal {
    Ceiling(String message) { super(message); }
  }

  static Map<String, Seed> readSeeds(Path path) throws Exception {
    List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
    if (lines.size() < 2 || !"r2t.epubcheck-seed-census/v1".equals(lines.get(0))) {
      throw new Refusal("seed census schema differs");
    }
    Map<String, Seed> result = new LinkedHashMap<String, Seed>();
    String prior = "";
    for (int i = 1; i < lines.size(); i++) {
      String[] fields = lines.get(i).split("\\t", -1);
      if (fields.length != 8) throw new Refusal("seed census row field count differs");
      String classifier = "-".equals(fields[5]) ? null : fields[5];
      Coordinate coordinate = new Coordinate(fields[1], fields[2], fields[3],
                                             fields[4], classifier);
      String pathValue = validatePayloadPath(fields[0]);
      if (!coordinate.path().equals(pathValue) || pathValue.compareTo(prior) <= 0) {
        throw new Refusal("seed census path/order differs");
      }
      Seed seed = new Seed(coordinate, fields[6], fields[7]);
      if (result.put(pathValue, seed) != null) throw new Refusal("seed path repeats");
      prior = pathValue;
    }
    return result;
  }

  static List<ManifestEntry> readManifest(Path path) throws Exception {
    List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
    if (lines.size() < 3
        || !"r2t.epubcheck-m2-manifest/v1".equals(lines.get(0))
        || !"path\tgroup_id\tartifact_id\tversion\textension\tclassifier\tsize\tsha1\tsha256"
            .equals(lines.get(1))) {
      throw new Refusal("canonical manifest schema/header differs");
    }
    List<ManifestEntry> result = new ArrayList<ManifestEntry>();
    String prior = "";
    long total = 0;
    for (int i = 2; i < lines.size(); i++) {
      String[] fields = lines.get(i).split("\\t", -1);
      if (fields.length != 9) throw new Refusal("manifest field count differs");
      long size;
      try { size = Long.parseLong(fields[6]); }
      catch (NumberFormatException failure) { throw new Refusal("manifest size malformed"); }
      if (!Long.toString(size).equals(fields[6])) throw new Refusal("manifest size noncanonical");
      String classifier = "-".equals(fields[5]) ? null : fields[5];
      ManifestEntry entry = new ManifestEntry(
          fields[0], new Coordinate(fields[1], fields[2], fields[3],
                                    fields[4], classifier),
          size, fields[7], fields[8]);
      if (entry.path.compareTo(prior) <= 0) throw new Refusal("manifest path/order differs");
      if (result.size() == MAX_FILES || size > MAX_BYTES - total) {
        throw new Ceiling("manifest ceiling");
      }
      total += size;
      result.add(entry);
      prior = entry.path;
    }
    return result;
  }

  static void verifyOutput(Path root, List<ManifestEntry> entries) throws Exception {
    Map<String, ManifestEntry> expected = new LinkedHashMap<String, ManifestEntry>();
    for (ManifestEntry entry : entries) expected.put(entry.path, entry);
    Set<String> seen = new HashSet<String>();
    Deque<Path> pending = new ArrayDeque<Path>();
    pending.add(root);
    while (!pending.isEmpty()) {
      Path directory = pending.removeFirst();
      if (Files.isSymbolicLink(directory)) throw new Refusal("output contains symlink");
      try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory)) {
        for (Path child : stream) {
          if (Files.isSymbolicLink(child)) throw new Refusal("output contains symlink");
          if (Files.isDirectory(child, LinkOption.NOFOLLOW_LINKS)) {
            requireMode(child, 0755);
            pending.add(child);
          } else if (Files.isRegularFile(child, LinkOption.NOFOLLOW_LINKS)) {
            requireMode(child, 0644);
            String relative = root.relativize(child).toString().replace(child.getFileSystem().getSeparator(), "/");
            relative = validatePayloadPath(relative);
            ManifestEntry entry = expected.get(relative);
            if (entry == null || !seen.add(relative)) throw new Refusal("output has extra/repeated file");
            Transfer measured = measureFile(child, entry.size);
            if (measured.size != entry.size
                || !entry.sha1.equals(measured.sha1)
                || !entry.sha256.equals(measured.sha256)) {
              throw new Refusal("published output differs from manifest");
            }
          } else {
            throw new Refusal("output contains special file");
          }
        }
      }
    }
    if (!seen.equals(expected.keySet())) throw new Refusal("output misses a manifest file");
  }

  static void publish(Path root, String relative, Path temporary) throws Exception {
    relative = validatePayloadPath(relative);
    Path target = root.resolve(relative).normalize();
    if (!target.startsWith(root)) throw new Refusal("publish path escapes output");
    Path parent = target.getParent();
    Files.createDirectories(parent);
    Path walk = root;
    for (Path part : root.relativize(parent)) {
      walk = walk.resolve(part);
      if (Files.isSymbolicLink(walk)) throw new Refusal("publish parent is symlink");
      setMode(walk, 0755);
    }
    if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new Refusal("publish target exists");
    if (!temporary.startsWith(root)
        || !Files.isRegularFile(temporary, LinkOption.NOFOLLOW_LINKS)
        || Files.isSymbolicLink(temporary)) throw new Refusal("publish temp is unjoined");
    setMode(temporary, 0644);
    try {
      Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
    } catch (AtomicMoveNotSupportedException failure) {
      Files.deleteIfExists(temporary);
      throw new Refusal("output filesystem lacks atomic publication");
    }
  }

  static Path newTemporary(Path root, String kind) throws IOException {
    if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)
        || Files.isSymbolicLink(root)) throw new Refusal("temporary root is not real");
    Path path = Files.createTempFile(root, ".r2t-" + kind + "-", ".part");
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
        || Files.isSymbolicLink(path)) throw new Refusal("temporary file is not real");
    setMode(path, 0600);
    return path;
  }

  static Transfer streamTo(InputStream input, Path target, long maximum)
      throws IOException {
    if (maximum < 0) throw new Refusal("negative response bound");
    MessageDigest sha1 = digest("SHA-1");
    MessageDigest sha256 = digest("SHA-256");
    long total = 0;
    try (InputStream in = new BufferedInputStream(input);
         OutputStream output = new BufferedOutputStream(Files.newOutputStream(target))) {
      byte[] buffer = new byte[65536];
      for (;;) {
        int count = in.read(buffer);
        if (count < 0) break;
        if (total > maximum - count) throw new Ceiling("response crosses exact bound");
        total += count;
        sha1.update(buffer, 0, count);
        sha256.update(buffer, 0, count);
        output.write(buffer, 0, count);
      }
    }
    return new Transfer(total, hex(sha1.digest()), hex(sha256.digest()));
  }

  static Transfer measureFile(Path path, long maximum) throws IOException {
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
        || Files.isSymbolicLink(path)) throw new Refusal("measured file is not real");
    MessageDigest sha1 = digest("SHA-1");
    MessageDigest sha256 = digest("SHA-256");
    long total = 0;
    try (InputStream input = new BufferedInputStream(Files.newInputStream(path))) {
      byte[] buffer = new byte[65536];
      for (;;) {
        int count = input.read(buffer);
        if (count < 0) break;
        if (total > maximum - count) throw new Ceiling("file crosses exact bound");
        total += count;
        sha1.update(buffer, 0, count);
        sha256.update(buffer, 0, count);
      }
    }
    return new Transfer(total, hex(sha1.digest()), hex(sha256.digest()));
  }

  static void requireEmptyDirectory(Path root) throws IOException {
    if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(root)) {
      throw new Refusal("output root is not a real directory");
    }
    try (DirectoryStream<Path> stream = Files.newDirectoryStream(root)) {
      if (stream.iterator().hasNext()) throw new Refusal("output root is not empty");
    }
    requireMode(root, 0755);
  }

  static byte[] regularBytes(Path path, int maximum) throws IOException {
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
      throw new Refusal("input is not a nofollow regular file");
    }
    return boundedRead(Files.newInputStream(path), maximum);
  }

  static byte[] boundedRead(InputStream input, int maximum) throws IOException {
    if (maximum < 0) throw new Refusal("negative response bound");
    ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(maximum, 65536));
    byte[] buffer = new byte[65536];
    int total = 0;
    try (InputStream in = new BufferedInputStream(input)) {
      while (true) {
        int count = in.read(buffer);
        if (count < 0) break;
        total += count;
        if (total > maximum) throw new Ceiling("response crosses exact bound");
        output.write(buffer, 0, count);
      }
    }
    return output.toByteArray();
  }

  static String validatePayloadPath(String path) {
    validateCentralPath(path, false);
    if (!path.endsWith(".jar") && !path.endsWith(".pom")) {
      throw new Refusal("path is not JAR/POM payload");
    }
    if (path.toUpperCase(Locale.ROOT).contains("SNAPSHOT")
        || path.contains("maven-metadata") || path.endsWith(".lastUpdated")
        || path.endsWith("_remote.repositories")) {
      throw new Refusal("metadata/snapshot payload path");
    }
    return path;
  }

  static void validateCentralPath(String path, boolean sidecarAllowed) {
    if (path == null || path.length() == 0 || path.startsWith("/")
        || path.endsWith("/") || path.contains("//") || path.contains("\\")
        || path.contains("?") || path.contains("#") || path.contains("%")
        || path.indexOf('\0') >= 0) throw new Refusal("malformed Central path");
    for (String part : path.split("/")) {
      if (part.length() == 0 || ".".equals(part) || "..".equals(part)
          || !part.matches("[A-Za-z0-9_.+\\-]+")) {
        throw new Refusal("Central path has unsafe component");
      }
    }
    String payload = path;
    if (sidecarAllowed && payload.endsWith(".sha1")) {
      payload = payload.substring(0, payload.length() - 5);
    }
    if (!payload.endsWith(".jar") && !payload.endsWith(".pom")) {
      throw new Refusal("Central path is not payload/SHA-1");
    }
  }

  static Coordinate resolveCoordinate(RawDependency raw, Map<String, String> properties,
                                      String type, String classifier) {
    String group = resolveLiteral(raw.group, properties);
    String artifact = resolveLiteral(raw.artifact, properties);
    String version = resolveLiteral(raw.version, properties);
    return new Coordinate(group, artifact, version, type, classifier);
  }

  static String resolveLiteral(String value, Map<String, String> properties) {
    if (value == null) throw new Refusal("required raw pom value is absent");
    String current = value;
    for (int pass = 0; pass < 32; pass++) {
      int start = current.indexOf("${");
      if (start < 0) return current;
      int end = current.indexOf('}', start + 2);
      if (end < 0) throw new Refusal("unterminated raw pom expression");
      String key = current.substring(start + 2, end);
      String replacement = properties.get(key);
      if (replacement == null) throw new Refusal("raw parent expression unresolved");
      current = current.substring(0, start) + replacement + current.substring(end + 1);
    }
    throw new Refusal("raw pom expression recursion");
  }

  static void putAliases(Map<String, String> values, String key, String value) {
    if (value != null && !values.containsKey(key)) values.put(key, value);
  }

  static void setFeature(DocumentBuilderFactory factory, String feature, boolean value) {
    try { factory.setFeature(feature, value); }
    catch (Exception failure) { throw new Refusal("XML parser lacks security feature"); }
  }

  static String name(Node node) {
    String value = node.getLocalName();
    if (value == null) value = node.getNodeName();
    int colon = value.indexOf(':');
    return colon < 0 ? value : value.substring(colon + 1);
  }

  static Element child(Element parent, String wanted) {
    for (Element element : children(parent, wanted)) return element;
    return null;
  }

  static List<Element> children(Element parent, String wanted) {
    List<Element> result = new ArrayList<Element>();
    NodeList nodes = parent.getChildNodes();
    for (int i = 0; i < nodes.getLength(); i++) {
      Node node = nodes.item(i);
      if (node instanceof Element && (wanted == null || wanted.equals(name(node)))) {
        result.add((Element) node);
      }
    }
    return result;
  }

  static String childText(Element parent, String wanted) {
    Element element = child(parent, wanted);
    return element == null ? null : text(element);
  }

  static String text(Element element) {
    String value = element.getTextContent();
    if (value == null) return null;
    value = value.trim();
    return value.length() == 0 ? null : value;
  }

  static String token(String value, String label) {
    if (value == null || !value.matches("[A-Za-z0-9_.+\\-]+")) {
      throw new Refusal(label + " is not a Maven token");
    }
    return value;
  }

  static String validateExclusionPart(String value, String label) {
    if ("*".equals(value)) return value;
    return token(value, label);
  }

  static String exactHex(String value, int size, String label) {
    if (value == null || value.length() != size || !value.matches("[0-9a-f]+")) {
      throw new Refusal(label + " is malformed");
    }
    return value;
  }

  static String parseSha1(byte[] raw) {
    String value = new String(raw, StandardCharsets.US_ASCII).trim().toLowerCase(Locale.ROOT);
    if (value.contains(" ")) value = value.substring(0, value.indexOf(' '));
    return exactHex(value, 40, "Central SHA-1 sidecar");
  }

  static String hex(String algorithm, byte[] raw) {
    return hex(digest(algorithm).digest(raw));
  }

  static MessageDigest digest(String algorithm) {
    try { return MessageDigest.getInstance(algorithm); }
    catch (NoSuchAlgorithmException failure) { throw new AssertionError(failure); }
  }

  static String hex(byte[] digest) {
    StringBuilder value = new StringBuilder();
    for (byte item : digest) {
      value.append(String.format(Locale.ROOT, "%02x", item & 0xff));
    }
    return value.toString();
  }

  static String oneLine(Path path) throws IOException {
    byte[] raw = regularBytes(path, 4096);
    String value = new String(raw, StandardCharsets.US_ASCII);
    if (!value.endsWith("\n") || value.indexOf('\r') >= 0
        || value.substring(0, value.length() - 1).indexOf('\n') >= 0) {
      throw new Refusal("configuration is not exactly one LF line");
    }
    return value.substring(0, value.length() - 1);
  }

  static void setMode(Path path, int mode) throws IOException {
    Set<PosixFilePermission> permissions = new HashSet<PosixFilePermission>();
    if ((mode & 0400) != 0) permissions.add(PosixFilePermission.OWNER_READ);
    if ((mode & 0200) != 0) permissions.add(PosixFilePermission.OWNER_WRITE);
    if ((mode & 0100) != 0) permissions.add(PosixFilePermission.OWNER_EXECUTE);
    if ((mode & 0040) != 0) permissions.add(PosixFilePermission.GROUP_READ);
    if ((mode & 0020) != 0) permissions.add(PosixFilePermission.GROUP_WRITE);
    if ((mode & 0010) != 0) permissions.add(PosixFilePermission.GROUP_EXECUTE);
    if ((mode & 0004) != 0) permissions.add(PosixFilePermission.OTHERS_READ);
    if ((mode & 0002) != 0) permissions.add(PosixFilePermission.OTHERS_WRITE);
    if ((mode & 0001) != 0) permissions.add(PosixFilePermission.OTHERS_EXECUTE);
    Files.setPosixFilePermissions(path, permissions);
  }

  static void requireMode(Path path, int mode) throws IOException {
    int actual = 0;
    Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path,
        LinkOption.NOFOLLOW_LINKS);
    if (permissions.contains(PosixFilePermission.OWNER_READ)) actual |= 0400;
    if (permissions.contains(PosixFilePermission.OWNER_WRITE)) actual |= 0200;
    if (permissions.contains(PosixFilePermission.OWNER_EXECUTE)) actual |= 0100;
    if (permissions.contains(PosixFilePermission.GROUP_READ)) actual |= 0040;
    if (permissions.contains(PosixFilePermission.GROUP_WRITE)) actual |= 0020;
    if (permissions.contains(PosixFilePermission.GROUP_EXECUTE)) actual |= 0010;
    if (permissions.contains(PosixFilePermission.OTHERS_READ)) actual |= 0004;
    if (permissions.contains(PosixFilePermission.OTHERS_WRITE)) actual |= 0002;
    if (permissions.contains(PosixFilePermission.OTHERS_EXECUTE)) actual |= 0001;
    if (actual != mode) throw new Refusal("filesystem mode differs");
  }

  static void log(String event, String subject, String detail) {
    String line = "{\"event\":\"" + json(event) + "\",\"subject\":\""
        + json(subject) + "\",\"detail\":\"" + json(detail) + "\"}";
    System.out.println(line);
    System.out.flush();
  }

  static String json(String value) {
    StringBuilder result = new StringBuilder();
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c == '"' || c == '\\') result.append('\\').append(c);
      else if (c == '\n') result.append("\\n");
      else if (c == '\r') result.append("\\r");
      else if (c == '\t') result.append("\\t");
      else if (c < 0x20) result.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
      else result.append(c);
    }
    return result.toString();
  }

  static String safe(String value) {
    if (value == null) return "unspecified";
    return value.length() <= 2048 ? value : value.substring(0, 2048);
  }

  static String join(List<String> values, String separator) {
    StringBuilder result = new StringBuilder();
    for (String value : values) {
      if (result.length() != 0) result.append(separator);
      result.append(value);
    }
    return result.toString();
  }
}
