package org.tron.p2p;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.tron.p2p.base.Parameter;
import org.tron.p2p.connection.ChannelManager;
import org.tron.p2p.connection.ConnectionPolicy;

public class P2pServicePeerManagementTest {

  private P2pService p2pService;

  @Before
  public void setUp() {
    Parameter.p2pConfig = new P2pConfig();
    p2pService = new P2pService();
    ConnectionPolicy.replaceBlockedIps(Collections.emptySet());
  }

  @After
  public void tearDown() {
    Parameter.p2pConfig.getActiveNodes().clear();
    ConnectionPolicy.replaceBlockedIps(Collections.emptySet());
  }

  @Test
  public void blockedActiveNodeIsRejected() {
    InetSocketAddress address = new InetSocketAddress("192.0.2.20", 18888);
    ConnectionPolicy.replaceBlockedIps(Collections.singleton(address.getAddress()));

    Assert.assertFalse(p2pService.addActiveNode(address));
    Assert.assertFalse(Parameter.p2pConfig.getActiveNodes().contains(address));
  }

  @Test
  public void removeAndDisconnectDoNotChangeEachOthersState() {
    InetSocketAddress address = new InetSocketAddress("192.0.2.21", 18888);
    Assert.assertTrue(p2pService.addActiveNode(address));
    Assert.assertFalse(p2pService.addActiveNode(address));

    Assert.assertEquals(0, p2pService.disconnect(address));
    Assert.assertTrue(Parameter.p2pConfig.getActiveNodes().contains(address));
    Assert.assertTrue(p2pService.removeActiveNode(address));
    Assert.assertFalse(p2pService.removeActiveNode(address));
  }

  @Test
  public void invalidAddressIsRejectedBeforeNetworkAccess() {
    try {
      p2pService.addActiveNode(InetSocketAddress.createUnresolved("peer.example", 18888));
      Assert.fail("Expected unresolved address to be rejected");
    } catch (IllegalArgumentException expected) {
      Assert.assertTrue(expected.getMessage().contains("must be resolved"));
    }
  }

  @Test
  public void activeNodeSetterKeepsCollectionSafeForRuntimeUpdates() {
    P2pConfig config = new P2pConfig();
    config.setActiveNodes(new ArrayList<InetSocketAddress>());

    java.util.Iterator<InetSocketAddress> iterator = config.getActiveNodes().iterator();
    config.getActiveNodes().add(new InetSocketAddress("192.0.2.22", 18888));

    Assert.assertFalse(iterator.hasNext());
    Assert.assertEquals(1, config.getActiveNodes().size());
  }
}
