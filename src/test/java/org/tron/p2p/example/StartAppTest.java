package org.tron.p2p.example;

import java.net.InetAddress;
import java.util.Set;
import org.apache.commons.cli.CommandLine;
import org.junit.Assert;
import org.junit.Test;

public class StartAppTest {

  @Test
  public void parseBlockedIpsFromCli() throws Exception {
    StartApp app = new StartApp();
    CommandLine cli = app.parseCli(new String[]{"--blocked-ips",
        "192.0.2.1,2001:db8::1,192.0.2.1"});

    Set<InetAddress> blockedIps = app.parseInetAddressSet(cli.getOptionValue("b"));

    Assert.assertEquals(2, blockedIps.size());
    Assert.assertTrue(blockedIps.contains(InetAddress.getByName("192.0.2.1")));
    Assert.assertTrue(blockedIps.contains(InetAddress.getByName("2001:db8::1")));
  }

  @Test(expected = IllegalArgumentException.class)
  public void rejectHostNameAsBlockedIp() {
    new StartApp().parseInetAddressSet("malicious.example.com");
  }

  @Test(expected = IllegalArgumentException.class)
  public void rejectEmptyBlockedIpEntry() {
    new StartApp().parseInetAddressSet("192.0.2.1,,2001:db8::1");
  }

  @Test(expected = IllegalArgumentException.class)
  public void rejectTrailingEmptyBlockedIpEntry() {
    new StartApp().parseInetAddressSet("192.0.2.1,");
  }

  @Test(expected = IllegalArgumentException.class)
  public void rejectNullBlockedIps() {
    new StartApp().parseInetAddressSet(null);
  }
}
