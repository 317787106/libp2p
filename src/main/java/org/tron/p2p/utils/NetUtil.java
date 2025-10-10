package org.tron.p2p.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.tron.p2p.base.Constant;
import org.tron.p2p.discover.Node;
import org.tron.p2p.protos.Discover;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.DohResolver;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Type;
import org.xbill.DNS.lookup.LookupResult;
import org.xbill.DNS.lookup.LookupSession;

@Slf4j(topic = "net")
public class NetUtil {

  static Random gen = new Random();

  public static final Pattern PATTERN_IPv4 =
      Pattern.compile("^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[1-9])\\"
          + ".(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\"
          + ".(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\"
          + ".(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)$");

  //https://codeantenna.com/a/jvrULhCbdj
  public static final Pattern PATTERN_IPv6 = Pattern.compile(
      "^\\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:)))(%.+)?\\s*$");

  public static boolean validIpV4(String ip) {
    if (StringUtils.isEmpty(ip)) {
      return false;
    }
    return PATTERN_IPv4.matcher(ip).find();
  }

  public static boolean validIpV6(String ip) {
    if (StringUtils.isEmpty(ip)) {
      return false;
    }
    return PATTERN_IPv6.matcher(ip).find();
  }

  public static boolean validNode(Node node) {
    if (node == null || node.getId() == null) {
      return false;
    }
    if (node.getId().length != Constant.NODE_ID_LEN) {
      return false;
    }
    if (StringUtils.isEmpty(node.getHostV4()) && StringUtils.isEmpty(node.getHostV6())) {
      return false;
    }
    if (StringUtils.isNotEmpty(node.getHostV4()) && !validIpV4(node.getHostV4())) {
      return false;
    }
    if (StringUtils.isNotEmpty(node.getHostV6()) && !validIpV6(node.getHostV6())) {
      return false;
    }
    return true;
  }

  public static Node getNode(Discover.Endpoint endpoint) {
    return new Node(endpoint.getNodeId().toByteArray(),
        ByteArray.toStr(endpoint.getAddress().toByteArray()),
        ByteArray.toStr(endpoint.getAddressIpv6().toByteArray()), endpoint.getPort());
  }

  public static byte[] getNodeId() {
    byte[] id = new byte[Constant.NODE_ID_LEN];
    gen.nextBytes(id);
    return id;
  }

  private static String getExternalIp(String url, boolean isAskIpv4) {
    // try to get ipv4 or ipv6 by url directly first
    BufferedReader in = null;
    String ip = null;
    String domain = null;
    String errMsg = null;
    try {
      URL uri = new URL(url);
      domain = uri.getHost();
      URLConnection urlConnection = uri.openConnection();
      in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
      ip = in.readLine();
      if (ip == null || ip.trim().isEmpty()) {
        throw new IOException("Invalid address: " + ip);
      }
      InetAddress inetAddress = InetAddress.getByName(ip);
      if (isAskIpv4 && !validIpV4(inetAddress.getHostAddress())) {
        throw new IOException("Invalid address: " + ip);
      }
      if (!isAskIpv4 && !validIpV6(inetAddress.getHostAddress())) {
        throw new IOException("Invalid address: " + ip);
      }
      ip = inetAddress.getHostAddress();
    } catch (Exception e) {
      errMsg = e.getMessage();
    } finally {
      if (in != null) {
        try {
          in.close();
        } catch (IOException e) {
          //ignore
        }
      }
    }

    //if fails to get ipv6 directly, we use alternative method
    if (!isAskIpv4 && StringUtils.isEmpty(ip) && StringUtils.isNotEmpty(domain)) {
      try {
        ip = getExternalIPv6ByDoh(domain);
      } catch (Exception e) {
        // ignore
      }
    }
    if (StringUtils.isNotEmpty(ip)) {
      log.debug("Get {} from {} successfully", isAskIpv4 ? "ipv4" : "ipv6", url);
    } else if (StringUtils.isNotEmpty(errMsg)) {
      log.warn("Fail to get {} by {}, cause:{}",
          Constant.ipV4Urls.contains(url) ? "ipv4" : "ipv6", url, errMsg);
    }
    return ip;
  }

  /**
   * get external ipv6 through dns server. Ask the ipv6 of specified domain through dns resolver
   * first, and then execute `curl [ipv6]` to get the ipv6 of localhost
   */
  private static String getExternalIPv6ByDoh(String domain) throws Exception {
    log.debug("Try to get ipv6 by {} through doh {}", domain, Constant.dnsResolver);
    Resolver resolver = new DohResolver(Constant.dnsResolver);
    LookupSession session = LookupSession.defaultBuilder()
        .resolver(resolver)
        .build();

    Name name = Name.fromString(domain + ".");
    CompletableFuture<LookupResult> future =
        session.lookupAsync(name, Type.AAAA).toCompletableFuture();

    LookupResult result = future.get();

    InetAddress ipv6 = null;
    for (Record recordItem : result.getRecords()) {
      if (recordItem instanceof AAAARecord) {
        ipv6 = ((AAAARecord) recordItem).getAddress();
        break;
      }
    }
    if (ipv6 == null) {
      return null;
    }
    if (!(ipv6 instanceof Inet6Address)) {
      return null;
    }
    log.debug("ipv6 of domain {} is {}", domain, ipv6.getHostAddress());

    // use timeout 3s
    String command = String.format("curl --max-time 3 http://[%s]", ipv6.getHostAddress());

    Process process = Runtime.getRuntime().exec(command);
    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
    String ipv6Str = null;
    String line;
    while ((line = reader.readLine()) != null) {
      ipv6Str = line.trim();
    }
    reader.close();

    int exitCode = process.waitFor();
    if (exitCode == 0 && validIpV6(ipv6Str)) {
      return ipv6Str;
    }

    return null;
  }

  private static String getOuterIPv6Address() {
    Enumeration<NetworkInterface> networkInterfaces;
    try {
      networkInterfaces = NetworkInterface.getNetworkInterfaces();
    } catch (SocketException e) {
      log.warn("GetOuterIPv6Address failed", e);
      return null;
    }
    while (networkInterfaces.hasMoreElements()) {
      Enumeration<InetAddress> inetAds = networkInterfaces.nextElement().getInetAddresses();
      while (inetAds.hasMoreElements()) {
        InetAddress inetAddress = inetAds.nextElement();
        if (inetAddress instanceof Inet6Address && !isReservedAddress(inetAddress)) {
          String ipAddress = inetAddress.getHostAddress();
          int index = ipAddress.indexOf('%');
          if (index > 0) {
            ipAddress = ipAddress.substring(0, index);
          }
          return ipAddress;
        }
      }
    }
    return null;
  }

  public static Set<String> getAllLocalAddress() {
    Set<String> localIpSet = new HashSet<>();
    Enumeration<NetworkInterface> networkInterfaces;
    try {
      networkInterfaces = NetworkInterface.getNetworkInterfaces();
    } catch (SocketException e) {
      log.warn("GetAllLocalAddress failed", e);
      return localIpSet;
    }
    while (networkInterfaces.hasMoreElements()) {
      Enumeration<InetAddress> inetAds = networkInterfaces.nextElement().getInetAddresses();
      while (inetAds.hasMoreElements()) {
        InetAddress inetAddress = inetAds.nextElement();
        String ipAddress = inetAddress.getHostAddress();
        int index = ipAddress.indexOf('%');
        if (index > 0) {
          ipAddress = ipAddress.substring(0, index);
        }
        localIpSet.add(ipAddress);
      }
    }
    return localIpSet;
  }

  private static boolean isReservedAddress(InetAddress inetAddress) {
    return inetAddress.isAnyLocalAddress() || inetAddress.isLinkLocalAddress()
        || inetAddress.isLoopbackAddress() || inetAddress.isMulticastAddress();
  }

  public static String getExternalIpV4() {
    long t1 = System.currentTimeMillis();
    String ipV4 = getIp(Constant.ipV4Urls, true);
    log.debug("GetExternalIpV4 cost {} ms", System.currentTimeMillis() - t1);
    return ipV4;
  }

  public static String getExternalIpV6() {
    long t1 = System.currentTimeMillis();
    String ipV6 = getIp(Constant.ipV6Urls, false);
    if (null == ipV6) {
      ipV6 = getOuterIPv6Address();
    }
    log.debug("GetExternalIpV6 cost {} ms", System.currentTimeMillis() - t1);
    return ipV6;
  }

  public static InetSocketAddress parseInetSocketAddress(String para) {
    int index = para.trim().lastIndexOf(":");
    if (index > 0) {
      String host = para.substring(0, index);
      if (host.startsWith("[") && host.endsWith("]")) {
        host = host.substring(1, host.length() - 1);
      } else {
        if (host.contains(":")) {
          throw new RuntimeException(String.format("Invalid inetSocketAddress: \"%s\", "
              + "use ipv4:port or [ipv6]:port", para));
        }
      }
      int port = Integer.parseInt(para.substring(index + 1));
      return new InetSocketAddress(host, port);
    } else {
      throw new RuntimeException(String.format("Invalid inetSocketAddress: \"%s\", "
          + "use ipv4:port or [ipv6]:port", para));
    }
  }

  private static String getIp(List<String> multiSrcUrls, boolean isAskIpv4) {
    int threadSize = multiSrcUrls.size();
    ExecutorService executor = Executors.newFixedThreadPool(threadSize,
        BasicThreadFactory.builder().namingPattern("getIp").build());
    CompletionService<String> completionService = new ExecutorCompletionService<>(executor);

    for (String url : multiSrcUrls) {
      completionService.submit(() -> getExternalIp(url, isAskIpv4));
    }

    String ip = null;
    for (int i = 0; i < threadSize; i++) {
      try {
        //block until any result return
        Future<String> f = completionService.take();
        String result = f.get();
        if (StringUtils.isNotEmpty(result)) {
          ip = result;
          break;
        }
      } catch (Exception ignored) {
        //ignore
      }
    }

    executor.shutdownNow();
    return ip;
  }

  public static String getLanIP() {
    String lanIP;
    try (Socket s = new Socket("www.baidu.com", 80)) {
      lanIP = s.getLocalAddress().getHostAddress();
    } catch (IOException e) {
      log.warn("Can't get lan IP. Fall back to 127.0.0.1: " + e);
      lanIP = "127.0.0.1";
    }
    return lanIP;
  }
}
