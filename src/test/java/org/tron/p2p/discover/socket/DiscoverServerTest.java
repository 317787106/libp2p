package org.tron.p2p.discover.socket;

import io.netty.channel.Channel;
import java.lang.reflect.Field;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.Assert;
import org.junit.Test;
import org.tron.p2p.P2pConfig;
import org.tron.p2p.base.Parameter;

public class DiscoverServerTest {

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
      server.init(new EventHandler() {
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
      });
      Assert.assertTrue(initializing.await(5, TimeUnit.SECONDS));
      // Pause before bind completes, when DiscoverServer.close() cannot yet see its channel.
      server.close();
      continueBind.countDown();
      Channel channel = udpChannel.get();
      Assert.assertTrue(channel.closeFuture().await(5, TimeUnit.SECONDS));
      Assert.assertTrue(channel.eventLoop().terminationFuture().await(5, TimeUnit.SECONDS));
      Assert.assertFalse(channel.isOpen());
      Assert.assertNull(failure.get());
    } finally {
      continueBind.countDown();
      server.close();
      Parameter.p2pConfig = previousConfig;
    }
  }
}
