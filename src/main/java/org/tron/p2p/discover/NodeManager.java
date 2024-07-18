package org.tron.p2p.discover;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.tron.p2p.base.Parameter;
import org.tron.p2p.discover.protocol.kad.KadService;
import org.tron.p2p.discover.socket.DiscoverServer;

@Slf4j(topic = "net")
public class NodeManager {

  private static DiscoverService discoverService;
  private static DiscoverServer discoverServer;

  static ScheduledExecutorService testServer = Executors.newSingleThreadScheduledExecutor(
      new BasicThreadFactory.Builder().namingPattern("testServer").build());

  public static void init() {
    discoverService = new KadService();
    discoverService.init();
    if (Parameter.p2pConfig.isDiscoverEnable()) {
      discoverServer = new DiscoverServer();
      discoverServer.init(discoverService);

      testServer.scheduleWithFixedDelay(() -> {
        try {
          for (Node node : getConnectableNodes()) {
            log.info("ConnectableNode: {}:{}", node.hostV4, node.getPort());
          }
        } catch (Exception e) {
          log.error("DisconnectRandom node failed", e);
        }
      }, 30, 10, TimeUnit.SECONDS);
    }
  }

  public static void close() {
    if (discoverService != null) {
      discoverService.close();
    }
    if (discoverServer != null) {
      discoverServer.close();
    }
  }

  public static List<Node> getConnectableNodes() {
    return discoverService.getConnectableNodes();
  }

  public static Node getHomeNode() {
    return discoverService.getPublicHomeNode();
  }

  public static List<Node> getTableNodes() {
    return discoverService.getTableNodes();
  }

  public static List<Node> getAllNodes() {
    return discoverService.getAllNodes();
  }

}
