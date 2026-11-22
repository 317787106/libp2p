package org.tron.p2p.discover.socket;

import io.netty.channel.Channel;
import java.lang.reflect.Field;
import java.net.BindException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.Assert;
import org.junit.Test;
import org.tron.p2p.P2pConfig;
import org.tron.p2p.base.Parameter;
import org.tron.p2p.discover.Node;
import org.tron.p2p.discover.message.kad.PingMessage;

public class DiscoverServerTest {

  @Test(timeout = 15000)
  public void shutdownBeforeStartupCompletesInitialBindExceptionally() {
    P2pConfig previousConfig = Parameter.p2pConfig;
    Parameter.p2pConfig = new P2pConfig();
    Parameter.p2pConfig.setPort(0);
    DiscoverServer server = new DiscoverServer();
    try {
      server.close();
      IllegalStateException error = Assert.assertThrows(IllegalStateException.class,
          () -> server.init(new NoopEventHandler()));
      Assert.assertEquals("Discovery server startup was cancelled", error.getMessage());
    } finally {
      server.close();
      Parameter.p2pConfig = previousConfig;
    }
  }

  @Test(timeout = 15000)
  public void initialUdpBindFailureReachesCaller() throws Exception {
    P2pConfig previousConfig = Parameter.p2pConfig;
    try (DatagramSocket occupied = new DatagramSocket(0)) {
      Parameter.p2pConfig = new P2pConfig();
      Parameter.p2pConfig.setPort(occupied.getLocalPort());
      DiscoverServer server = new DiscoverServer();
      try {
        IllegalStateException error = Assert.assertThrows(IllegalStateException.class,
            () -> server.init(new NoopEventHandler()));
        Assert.assertTrue(error.getCause() instanceof BindException);
      } finally {
        server.close();
      }
    } finally {
      Parameter.p2pConfig = previousConfig;
    }
  }

  @Test(timeout = 15000)
  public void closeDuringBindReleasesChannelAndEventLoop() throws Exception {
    P2pConfig previousConfig = Parameter.p2pConfig;
    Parameter.p2pConfig = new P2pConfig();
    Parameter.p2pConfig.setPort(0);
    DiscoverServer server = new DiscoverServer();
    CountDownLatch initializing = new CountDownLatch(1);
    CountDownLatch continueBind = new CountDownLatch(1);
    AtomicReference<Channel> udpChannel = new AtomicReference<>();
    AtomicReference<Throwable> failure = new AtomicReference<>();
    try {
      EventHandler eventHandler = new EventHandler() {
        @Override
        public void channelActivated() {
        }

        @Override
        public void handleEvent(UdpEvent event) {
        }

        @Override
        public void setMessageSender(Consumer<UdpEvent> sender) {
          try {
            Field field = MessageHandler.class.getDeclaredField("channel");
            field.setAccessible(true);
            udpChannel.set((Channel) field.get(sender));
            initializing.countDown();
            Assert.assertTrue(continueBind.await(5, TimeUnit.SECONDS));
          } catch (Throwable error) {
            failure.set(error);
          }
        }
      };
      Thread startup = new Thread(() -> {
        try {
          server.init(eventHandler);
        } catch (Throwable error) {
          failure.set(error);
        }
      });
      startup.start();
      Assert.assertTrue(initializing.await(5, TimeUnit.SECONDS));
      // Pause before bind completes, when DiscoverServer.close() cannot yet see its channel.
      server.close();
      continueBind.countDown();
      startup.join(5000);
      Assert.assertFalse("Discovery startup thread is still running", startup.isAlive());
      Channel channel = udpChannel.get();
      Assert.assertTrue(channel.closeFuture().await(5, TimeUnit.SECONDS));
      Assert.assertTrue(channel.eventLoop().terminationFuture().await(5, TimeUnit.SECONDS));
      Assert.assertFalse(channel.isOpen());
      Assert.assertTrue(failure.get() instanceof IllegalStateException);
      Assert.assertEquals("Discovery server startup was cancelled", failure.get().getMessage());
    } finally {
      continueBind.countDown();
      server.close();
      Parameter.p2pConfig = previousConfig;
    }
  }

  @Test(timeout = 45000)
  public void repeatedRebindFailuresRecoverAfterPortIsReleased() throws Exception {
    P2pConfig previousConfig = Parameter.p2pConfig;
    RecordingEventHandler handler = new RecordingEventHandler();
    DiscoverServer server = newServer();
    BindAttempt initial = null;
    DatagramSocket occupied = null;
    try {
      server.init(handler);
      initial = nextAttempt(handler);
      int port = ((InetSocketAddress) initial.channel.localAddress()).getPort();
      assertUdpExchange(handler, port);
      initial.channel.close().sync();
      occupied = occupyReleasedPort(port);

      BindAttempt firstFailure = nextAttempt(handler);
      Assert.assertTrue(firstFailure.channel.closeFuture().await(3, TimeUnit.SECONDS));
      Assert.assertFalse(initial.channel.eventLoop().parent().isShuttingDown());
      BindAttempt secondFailure = nextAttempt(handler);
      Assert.assertTrue(secondFailure.channel.closeFuture().await(3, TimeUnit.SECONDS));
      Assert.assertTrue("Failed binds must retain a retry interval",
          secondFailure.startedAt - firstFailure.startedAt >= TimeUnit.SECONDS.toNanos(4));
      Assert.assertSame(initial.channel.eventLoop().parent(),
          secondFailure.channel.eventLoop().parent());
      Assert.assertFalse(initial.channel.eventLoop().parent().isShuttingDown());

      occupied.close();
      occupied = null;
      BindAttempt recovered = nextAttempt(handler);
      awaitActive(recovered.channel);
      Assert.assertSame(initial.channel.eventLoop().parent(), recovered.channel.eventLoop().parent());
      assertUdpExchange(handler, port);
      Assert.assertTrue(recovered.channel.isActive());
    } finally {
      if (occupied != null) {
        occupied.close();
      }
      closeAndAwait(server, initial, previousConfig);
    }
  }

  @Test(timeout = 25000)
  public void closeDuringFailedRebindWaitStopsFurtherAttempts() throws Exception {
    P2pConfig previousConfig = Parameter.p2pConfig;
    RecordingEventHandler handler = new RecordingEventHandler();
    DiscoverServer server = newServer();
    BindAttempt initial = null;
    DatagramSocket occupied = null;
    try {
      server.init(handler);
      initial = nextAttempt(handler);
      int port = ((InetSocketAddress) initial.channel.localAddress()).getPort();
      initial.channel.close().sync();
      occupied = occupyReleasedPort(port);
      BindAttempt failed = nextAttempt(handler);
      Assert.assertTrue(failed.channel.closeFuture().await(3, TimeUnit.SECONDS));
      Assert.assertFalse(initial.channel.eventLoop().parent().isShuttingDown());

      server.close();
      occupied.close();
      occupied = null;

      Assert.assertTrue(initial.channel.eventLoop().parent().terminationFuture()
          .await(10, TimeUnit.SECONDS));
      Assert.assertTrue(handler.attempts.isEmpty());
      try (DatagramSocket available = occupy(port)) {
        Assert.assertTrue(available.isBound());
      }
    } finally {
      if (occupied != null) {
        occupied.close();
      }
      closeAndAwait(server, initial, previousConfig);
    }
  }

  @Test(timeout = 25000)
  public void closeDuringRebindReleasesNewChannelAndEventLoop() throws Exception {
    P2pConfig previousConfig = Parameter.p2pConfig;
    CountDownLatch rebinding = new CountDownLatch(1);
    CountDownLatch continueBind = new CountDownLatch(1);
    AtomicInteger attempts = new AtomicInteger();
    AtomicReference<Throwable> failure = new AtomicReference<>();
    RecordingEventHandler handler = new RecordingEventHandler() {
      @Override
      public void setMessageSender(Consumer<UdpEvent> sender) {
        super.setMessageSender(sender);
        if (attempts.incrementAndGet() == 2) {
          rebinding.countDown();
          try {
            Assert.assertTrue(continueBind.await(10, TimeUnit.SECONDS));
          } catch (Throwable error) {
            failure.set(error);
          }
        }
      }
    };
    DiscoverServer server = newServer();
    BindAttempt initial = null;
    Thread closing = null;
    try {
      server.init(handler);
      initial = nextAttempt(handler);
      initial.channel.close().sync();
      Assert.assertTrue(rebinding.await(10, TimeUnit.SECONDS));
      BindAttempt rebound = nextAttempt(handler);

      // close() can wait for the event loop, which is paused in the initializer here.
      closing = new Thread(server::close);
      closing.start();
      awaitShutdown(server);
      continueBind.countDown();
      closing.join(5000);

      Assert.assertFalse("Discovery close is still waiting", closing.isAlive());
      Assert.assertTrue(rebound.channel.closeFuture().await(5, TimeUnit.SECONDS));
      Assert.assertTrue(initial.channel.eventLoop().parent().terminationFuture()
          .await(5, TimeUnit.SECONDS));
      Assert.assertFalse(rebound.channel.isOpen());
      Assert.assertTrue(handler.attempts.isEmpty());
      Assert.assertNull(failure.get());
    } finally {
      continueBind.countDown();
      if (closing != null) {
        closing.join(5000);
      }
      closeAndAwait(server, initial, previousConfig);
    }
  }

  private DiscoverServer newServer() throws Exception {
    Parameter.p2pConfig = new P2pConfig();
    try (DatagramSocket available = new DatagramSocket(0)) {
      Parameter.p2pConfig.setPort(available.getLocalPort());
    }
    return new DiscoverServer();
  }

  private DatagramSocket occupy(int port) throws Exception {
    DatagramSocket socket = new DatagramSocket(null);
    try {
      socket.setReuseAddress(false);
      socket.bind(new InetSocketAddress(port));
      return socket;
    } catch (Exception error) {
      socket.close();
      throw error;
    }
  }

  private DatagramSocket occupyReleasedPort(int port) throws Exception {
    // The JDK may retain the bound socket until the selector processes deregistration.
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
    while (true) {
      try {
        return occupy(port);
      } catch (BindException error) {
        if (System.nanoTime() >= deadline) {
          throw error;
        }
        Thread.sleep(10);
      }
    }
  }

  private BindAttempt nextAttempt(RecordingEventHandler handler) throws Exception {
    BindAttempt attempt = handler.attempts.poll(10, TimeUnit.SECONDS);
    Assert.assertNotNull("No discovery bind attempt observed", attempt);
    return attempt;
  }

  private void awaitActive(Channel channel) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
    while (!channel.isActive() && channel.isOpen() && System.nanoTime() < deadline) {
      Thread.sleep(10);
    }
    Assert.assertTrue("Discovery server did not bind the released port", channel.isActive());
  }

  private void awaitShutdown(DiscoverServer server) throws Exception {
    Field shutdown = DiscoverServer.class.getDeclaredField("shutdown");
    shutdown.setAccessible(true);
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
    while (!shutdown.getBoolean(server) && System.nanoTime() < deadline) {
      Thread.sleep(10);
    }
    Assert.assertTrue("Discovery shutdown was not requested", shutdown.getBoolean(server));
  }

  private void closeAndAwait(DiscoverServer server, BindAttempt initial, P2pConfig previousConfig)
      throws Exception {
    try {
      server.close();
      if (initial != null) {
        Assert.assertTrue(initial.channel.eventLoop().parent().terminationFuture()
            .await(10, TimeUnit.SECONDS));
      }
    } finally {
      Parameter.p2pConfig = previousConfig;
    }
  }

  private void assertUdpExchange(RecordingEventHandler handler, int serverPort) throws Exception {
    InetSocketAddress serverAddress = new InetSocketAddress("127.0.0.1", serverPort);
    try (DatagramSocket peer = new DatagramSocket(0)) {
      peer.setSoTimeout(3000);
      InetSocketAddress peerAddress = new InetSocketAddress("127.0.0.1", peer.getLocalPort());
      PingMessage outbound = new PingMessage(new Node(serverAddress), new Node(peerAddress));
      handler.sender.accept(new UdpEvent(outbound, peerAddress));
      DatagramPacket packet = new DatagramPacket(new byte[2048], 2048);
      peer.receive(packet);
      Assert.assertArrayEquals(outbound.getSendData(),
          Arrays.copyOf(packet.getData(), packet.getLength()));

      PingMessage inbound = new PingMessage(new Node(peerAddress), new Node(serverAddress));
      byte[] bytes = inbound.getSendData();
      peer.send(new DatagramPacket(bytes, bytes.length, serverAddress));
      UdpEvent received = handler.received.poll(3, TimeUnit.SECONDS);
      Assert.assertNotNull("Discovery server did not receive UDP packet", received);
      Assert.assertArrayEquals(bytes, received.getMessage().getSendData());
    }
  }

  private static class BindAttempt {
    private final Channel channel;
    private final long startedAt = System.nanoTime();

    private BindAttempt(Channel channel) {
      this.channel = channel;
    }
  }

  private static class RecordingEventHandler extends NoopEventHandler {
    private final BlockingQueue<BindAttempt> attempts = new LinkedBlockingQueue<>();
    private final BlockingQueue<UdpEvent> received = new LinkedBlockingQueue<>();
    private volatile Consumer<UdpEvent> sender;

    @Override
    public void handleEvent(UdpEvent event) {
      received.add(event);
    }

    @Override
    public void setMessageSender(Consumer<UdpEvent> sender) {
      this.sender = sender;
      try {
        Field field = MessageHandler.class.getDeclaredField("channel");
        field.setAccessible(true);
        attempts.add(new BindAttempt((Channel) field.get(sender)));
      } catch (ReflectiveOperationException error) {
        throw new IllegalStateException(error);
      }
    }
  }

  private static class NoopEventHandler implements EventHandler {
    @Override public void channelActivated() { }
    @Override public void handleEvent(UdpEvent event) { }
    @Override public void setMessageSender(Consumer<UdpEvent> sender) { }
  }
}
