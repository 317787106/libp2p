package org.tron.p2p.discover.protocol.kad;

import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.socket.DatagramPacket;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.tron.p2p.P2pConfig;
import org.tron.p2p.base.Parameter;
import org.tron.p2p.discover.Node;
import org.tron.p2p.discover.message.Message;
import org.tron.p2p.discover.message.MessageType;
import org.tron.p2p.discover.message.kad.FindNodeMessage;
import org.tron.p2p.discover.message.kad.NeighborsMessage;
import org.tron.p2p.discover.message.kad.PingMessage;
import org.tron.p2p.discover.message.kad.PongMessage;
import org.tron.p2p.discover.socket.MessageHandler;
import org.tron.p2p.discover.socket.P2pPacketDecoder;
import org.tron.p2p.discover.socket.UdpEvent;
import org.tron.p2p.protos.Discover;

public class DiscoveryEndpointTest {

  private static final int PORT = 28888;
  private static P2pConfig config;
  private P2pConfig previousConfig;
  private long previousTimeout;
  private KadService service;
  private EmbeddedChannel pipeline;
  private final List<UdpEvent> outbound = new ArrayList<>();

  @BeforeClass
  public static void createConfig() {
    config = new P2pConfig();
  }

  @Before
  public void setUp() {
    previousConfig = Parameter.p2pConfig;
    previousTimeout = KadService.getPingTimeout();
    Parameter.p2pConfig = config;
    config.setIp("127.0.0.1");
    config.setIpv6("::1");
    config.setNodeID(id(1));
    config.setNetworkId(1);
    config.setDiscoverEnable(false);
    KadService.setPingTimeout(60_000);
    service = new KadService();
    service.init();
    config.setDiscoverEnable(true);
    service.setMessageSender(outbound::add);
    pipeline = new EmbeddedChannel(new P2pPacketDecoder(), new MessageHandler(null, service));
  }

  @After
  public void tearDown() {
    try {
      if (pipeline != null) {
        pipeline.finishAndReleaseAll();
      }
    } finally {
      if (service != null) {
        service.close();
      }
      KadService.setPingTimeout(previousTimeout);
      Parameter.p2pConfig = previousConfig;
    }
  }

  @Test
  public void ipv4SenderCannotClaimExistingIpv6Record() throws Exception {
    NodeHandler honest = active(new Node(id(2), null, "::1", PORT));
    Node claimed = new Node(id(3), "127.0.0.2", "::1", PORT);

    receive(new PingMessage(claimed, service.getPublicHomeNode()), "127.0.0.2", PORT);

    assertHonestRecord(honest, id(2), null, "::1");
    Assert.assertEquals(2, service.getAllNodes().size());
    assertOutbound(MessageType.KAD_PING, "127.0.0.2", PORT);
    assertOutbound(MessageType.KAD_PONG, "127.0.0.2", PORT);
    assertOnlyDestination("127.0.0.2", PORT);

    outbound.clear();
    receive(new PingMessage(new Node(id(2), null, "::1", PORT),
        service.getPublicHomeNode()), "::1", PORT);

    assertOutbound(MessageType.KAD_PONG, "::1", PORT);
    assertOnlyDestination("::1", PORT);
  }

  @Test
  public void ipv6SenderCannotChangeExistingIpv4IdentityOrNetwork() throws Exception {
    NodeHandler honest = active(new Node(id(2), "127.0.0.2", null, PORT));
    PingMessage ping = new PingMessage(new Node(id(3), "127.0.0.2", "::1", PORT),
        service.getPublicHomeNode());
    Discover.PingMessage incompatible = Discover.PingMessage.parseFrom(ping.getData())
        .toBuilder().setVersion(config.getNetworkId() + 1).build();

    receive(new PingMessage(incompatible.toByteArray()), "::1", PORT);

    assertHonestRecord(honest, id(2), "127.0.0.2", null);
    Assert.assertEquals(2, service.getAllNodes().size());
    assertOnlyDestination("::1", PORT);
  }

  @Test
  public void newIpv6PingUsesSourceForInitialProbeAndPong() throws Exception {
    Node claimed = new Node(id(2), "127.0.0.2", "::1", PORT);

    receive(new PingMessage(claimed, service.getPublicHomeNode()), "::1", PORT);

    Assert.assertEquals(1, service.getAllNodes().size());
    Node stored = service.getAllNodes().get(0);
    Assert.assertNull(stored.getHostV4());
    Assert.assertEquals(address("::1", PORT), stored.getInetSocketAddressV6());
    Assert.assertEquals(2, outbound.size());
    assertOutbound(MessageType.KAD_PING, "::1", PORT);
    assertOutbound(MessageType.KAD_PONG, "::1", PORT);
    assertOnlyDestination("::1", PORT);
  }

  @Test
  public void findNodeResponseUsesActualSourceAddressAndPort() throws Exception {
    service.getNodeHandler(new Node(id(2), null, "::1", PORT));
    outbound.clear();
    Node claimed = new Node(id(2), "127.0.0.2", "::1", PORT + 1);

    receive(new FindNodeMessage(claimed, id(3)), "::1", PORT);

    assertOutbound(MessageType.KAD_NEIGHBORS, "::1", PORT);
    assertOnlyDestination("::1", PORT);
    receive(new PingMessage(claimed, service.getPublicHomeNode()), "::1", PORT);
    Assert.assertFalse(service.getAllNodes().get(0).isConnectible(config.getNetworkId()));
  }

  @Test
  public void unsupportedSourceFamilyCannotUseAdvertisedAlternative() throws Exception {
    config.setIpv6(null);
    Node claimed = new Node(id(2), "127.0.0.2", "::1", PORT);

    receive(new PingMessage(claimed, service.getPublicHomeNode()), "::1", PORT);
    receive(new FindNodeMessage(claimed, id(3)), "::1", PORT);

    Assert.assertTrue(service.getAllNodes().isEmpty());
    Assert.assertTrue(outbound.isEmpty());

    receive(new PingMessage(claimed, service.getPublicHomeNode()), "127.0.0.2", PORT);
    assertOutbound(MessageType.KAD_PONG, "127.0.0.2", PORT);
    assertOnlyDestination("127.0.0.2", PORT);
  }

  @Test
  public void neighborsCannotMergeAnAlternativeIntoAnActiveRecord() throws Exception {
    NodeHandler honest = active(new Node(id(2), null, "::1", PORT));
    NodeHandler sender = active(new Node(id(3), "127.0.0.3", null, PORT));
    sender.sendFindNode(id(4));
    outbound.clear();
    Node claimed = new Node(id(5), "127.0.0.2", "::1", PORT);

    receive(new NeighborsMessage(sender.getNode(), Collections.singletonList(claimed), 1L),
        "127.0.0.3", PORT);

    assertHonestRecord(honest, id(2), null, "::1");
    Assert.assertEquals(3, service.getAllNodes().size());
    Assert.assertNull(findNode("127.0.0.2", PORT).getHostV6());
    assertOutbound(MessageType.KAD_PING, "127.0.0.2", PORT);
    assertOnlyDestination("127.0.0.2", PORT);

    outbound.clear();
    receive(new PingMessage(new Node(id(2), null, "::1", PORT),
        service.getPublicHomeNode()), "::1", PORT);
    assertOnlyDestination("::1", PORT);
  }

  @Test
  public void dualStackNeighborsAreProbedAndLearnedIndependently() throws Exception {
    NodeHandler sender = active(new Node(id(2), "127.0.0.3", null, PORT));
    sender.sendFindNode(id(3));
    outbound.clear();
    Node neighbor = new Node(id(4), "127.0.0.2", "::1", PORT);

    receive(new NeighborsMessage(sender.getNode(), Collections.singletonList(neighbor), 1L),
        "127.0.0.3", PORT);

    Assert.assertEquals(3, service.getAllNodes().size());
    Node ipv4 = findNode("127.0.0.2", PORT);
    Node ipv6 = findNode("::1", PORT);
    Assert.assertNotSame(ipv4, ipv6);
    Assert.assertNull(ipv4.getHostV6());
    Assert.assertNull(ipv6.getHostV4());
    Assert.assertFalse(ipv4.isConnectible(config.getNetworkId()));
    Assert.assertFalse(ipv6.isConnectible(config.getNetworkId()));
    Assert.assertEquals(2, outbound.size());
    assertOutbound(MessageType.KAD_PING, "127.0.0.2", PORT);
    assertOutbound(MessageType.KAD_PING, "::1", PORT);

    receive(new PongMessage(neighbor), "127.0.0.2", PORT);
    Assert.assertTrue(ipv4.isConnectible(config.getNetworkId()));
    Assert.assertFalse(ipv6.isConnectible(config.getNetworkId()));
    receive(new PongMessage(neighbor), "::1", PORT);
    Assert.assertTrue(ipv6.isConnectible(config.getNetworkId()));
  }

  @Test
  public void sameIpWithDifferentSourcePortsHasSeparateRecords() throws Exception {
    receive(new PingMessage(new Node(id(2), "127.0.0.2", null, PORT),
        service.getPublicHomeNode()), "127.0.0.2", PORT);
    outbound.clear();

    receive(new PingMessage(new Node(id(3), "127.0.0.2", null, PORT),
        service.getPublicHomeNode()), "127.0.0.2", PORT + 1);

    Assert.assertEquals(2, service.getAllNodes().size());
    Assert.assertArrayEquals(id(2), findNode("127.0.0.2", PORT).getId());
    Assert.assertArrayEquals(id(3), findNode("127.0.0.2", PORT + 1).getId());
    Assert.assertFalse(findNode("127.0.0.2", PORT + 1).isConnectible(config.getNetworkId()));
    assertOnlyDestination("127.0.0.2", PORT + 1);
  }

  @Test
  public void mutableNodeMetadataCannotRedirectHandlerTraffic() throws Exception {
    NodeHandler handler = active(new Node(id(2), null, "::1", PORT));
    handler.getNode().updateHostV4("127.0.0.2");

    handler.sendPing();
    receive(new PingMessage(new Node(id(2), null, "::1", PORT),
        service.getPublicHomeNode()), "::1", PORT);

    assertOutbound(MessageType.KAD_PING, "::1", PORT);
    assertOutbound(MessageType.KAD_PONG, "::1", PORT);
    assertOnlyDestination("::1", PORT);
  }

  private NodeHandler active(Node node) throws Exception {
    NodeHandler handler = service.getNodeHandler(node);
    InetSocketAddress source = node.getPreferInetSocketAddress();
    receive(new PongMessage(node), source.getAddress().getHostAddress(), source.getPort());
    Assert.assertEquals(NodeHandler.State.ACTIVE, handler.getState());
    outbound.clear();
    return handler;
  }

  private void receive(Message message, String sender, int port) throws Exception {
    byte[] wire = message.getSendData();
    Message.parse(wire);
    pipeline.writeInbound(new DatagramPacket(Unpooled.wrappedBuffer(wire),
        address("127.0.0.1", config.getPort()), address(sender, port)));
    pipeline.checkException();
    Assert.assertTrue(pipeline.isOpen());
  }

  private void assertHonestRecord(NodeHandler handler, byte[] expectedId,
      String ipv4, String ipv6) {
    Node node = handler.getNode();
    Assert.assertArrayEquals(expectedId, node.getId());
    Assert.assertEquals(ipv4, node.getHostV4());
    Assert.assertEquals(ipv6 == null ? null : address(ipv6, PORT), node.getInetSocketAddressV6());
    Assert.assertEquals(NodeHandler.State.ACTIVE, handler.getState());
    Assert.assertTrue(node.isConnectible(config.getNetworkId()));
    Assert.assertTrue(service.getTable().contains(node));
  }

  private Node findNode(String host, int port) {
    return service.getAllNodes().stream().filter(node ->
        address(host, port).equals(node.getPreferInetSocketAddress())).findFirst().get();
  }

  private void assertOutbound(MessageType type, String host, int port) {
    Assert.assertTrue("Missing " + type + " to " + address(host, port), outbound.stream()
        .anyMatch(event -> event.getMessage().getType() == type
            && address(host, port).equals(event.getAddress())));
  }

  private void assertOnlyDestination(String host, int port) {
    Assert.assertFalse(outbound.isEmpty());
    outbound.forEach(event -> Assert.assertEquals(address(host, port), event.getAddress()));
  }

  private static InetSocketAddress address(String host, int port) {
    return new InetSocketAddress(host, port);
  }

  private static byte[] id(int value) {
    byte[] id = new byte[64];
    Arrays.fill(id, (byte) value);
    return id;
  }
}
