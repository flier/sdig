package sdig

import java.io.File
import java.net.InetSocketAddress
import java.time.Duration

import ch.qos.logback.classic.Level
import com.typesafe.scalalogging.LazyLogging
import io.netty.channel.ChannelOutboundHandler
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.nio.NioDatagramChannel
import io.netty.handler.codec.dns.DnsRecordType
import io.netty.handler.codec.dns.DnsRecordType.{A, valueOf}
import io.netty.handler.traffic.{AbstractTrafficShapingHandler, GlobalTrafficShapingHandler}
import io.netty.resolver.dns.{DnsNameResolver, DnsNameResolverBuilder, DnsServerAddresses}
import org.apache.commons.pool2.impl.{DefaultPooledObject, GenericObjectPool, GenericObjectPoolConfig}
import org.apache.commons.pool2.{BasePooledObjectFactory, PooledObject}

import scala.collection.JavaConverters._
import scala.io.Source

case class Config(loggingLevel: Level = Level.WARN,
                  inputFiles: Seq[File] = Seq(),
                  queryDomains: Seq[String] = Seq(),
                  dnsServers: Seq[String] = Seq(),
                  workerThreads: Int = Runtime.getRuntime.availableProcessors(),
                  maxTotalPooledResolver: Int = GenericObjectPoolConfig.DEFAULT_MAX_TOTAL,
                  maxIdlePooledResolver: Int = GenericObjectPoolConfig.DEFAULT_MAX_IDLE,
                  minIdlePooledResolver: Int = GenericObjectPoolConfig.DEFAULT_MIN_IDLE,
                  writeLimit: Long = 0,
                  readLimit: Long = 0,
                  checkInterval: Long = AbstractTrafficShapingHandler.DEFAULT_CHECK_INTERVAL,
                  maxWaitTime: Long = AbstractTrafficShapingHandler.DEFAULT_MAX_TIME,
                  maxRetryTimes: Int = 3,
                  decodeUnicode: Boolean = false,
                  queryTimeout: Long = Duration.ofSeconds(5).toMillis,
                  queryType: DnsRecordType = A,
                  recurseQuery: Boolean = true,
                  benchmarkIterations: Int = 1) extends LazyLogging
{
    lazy val eventLoopGroup: NioEventLoopGroup = new NioEventLoopGroup(workerThreads)

    lazy val dnsServerAddrs: DnsServerAddresses = if (dnsServers.isEmpty) {
        DnsServerAddresses.defaultAddresses()
    } else {
        DnsServerAddresses.shuffled(dnsServers.map(addr =>
            addr.split(':') match {
                case Array(host, port) => new InetSocketAddress(host, port.toInt)
                case Array(host) => new InetSocketAddress(host, Config.DEFAULT_DNS_PORT)
            }
        ).asJava)
    }

    lazy val trafficShaping: Option[ChannelOutboundHandler] = if (writeLimit > 0) {
        logger.info(s"using traffic shaping within write $writeLimit bytes/s, read $readLimit bytes/s")
        Some(new GlobalTrafficShapingHandler(eventLoopGroup.next(), writeLimit, readLimit, checkInterval, maxWaitTime))
    } else {
        None
    }

    lazy val dnsNameResolverPool: GenericObjectPool[DnsNameResolver] = {
        val poolConfig = new GenericObjectPoolConfig() {{
            setMaxTotal(maxTotalPooledResolver)
            setMaxIdle(maxIdlePooledResolver)
            setMinIdle(minIdlePooledResolver)
        }}

        logger.info(s"using DNS resolver pool, " +
            s"max_total=${poolConfig.getMaxTotal}, " +
            s"max_idle=${poolConfig.getMaxIdle}, " +
            s"min_idle=${poolConfig.getMinIdle}")

        new GenericObjectPool[DnsNameResolver](
            new BasePooledObjectFactory[DnsNameResolver]() {
                override def create(): DnsNameResolver = {
                    new DnsNameResolverBuilder(eventLoopGroup.next())
                        .nameServerAddresses(dnsServerAddrs)
                        .channelFactory(() => {
                            val ch = new NioDatagramChannel()

                            trafficShaping match {
                                case Some(handler) =>
                                    ch.pipeline().addLast("traffic-shaping", handler)
                                case _ =>
                            }

                            ch
                        })
                        .decodeIdn(decodeUnicode)
                        .queryTimeoutMillis(queryTimeout)
                        .recursionDesired(recurseQuery)
                        .optResourceEnabled(false)
                        .traceEnabled(true)
                        .build()
                }

                override def wrap(resolver: DnsNameResolver): PooledObject[DnsNameResolver] = {
                    new DefaultPooledObject[DnsNameResolver](resolver)
                }
            }, poolConfig)
    }

    lazy val domains: Seq[String] = queryDomains ++ inputFiles.flatMap(Source.fromFile(_).getLines())

    lazy val benchMode: Boolean = benchmarkIterations > 1
}

object Config extends LazyLogging {
    val APP_NAME = "sdig"
    val APP_VERSION = "1.0.0"

    val DEFAULT_DNS_PORT = 53

    def parse(args: Seq[String]): Option[Config] = {
        val parser = new scopt.OptionParser[Config](APP_NAME) {
            head(APP_NAME, APP_VERSION)

            opt[Seq[File]]('i', "input")
                .valueName("<file>[,<file>]")
                .action((x, c) => c.copy(inputFiles = x))
                .text("input files to lookup")
                .optional()

            opt[Seq[String]]('s', "server")
                .valueName("<addr>[,<addr>]")
                .action((x, c) => c.copy(dnsServers = x))
                .text("DNS servers")

            opt[Int]('c', "threads")
                .valueName("<num>")
                .action((x, c) => c.copy(workerThreads = x))
                .text("worker threads")

            opt[Int]("max-total")
                .valueName("<num>")
                .action((x, c) => c.copy(maxTotalPooledResolver = x))
                .text("the maximum number of DNS resolver that can be cached in the pool")

            opt[Int]("max-idle")
                .valueName("<num>")
                .action((x, c) => c.copy(maxIdlePooledResolver = x))
                .text("the maximum number of DNS resolver that can be idled in the pool")

            opt[Int]("min-total")
                .valueName("<num>")
                .action((x, c) => c.copy(minIdlePooledResolver = x))
                .text("the minimum number of DNS resolver that can be idled in the pool")

            opt[Long]("write-limit")
                .valueName("<bytes>")
                .action((x, c) => c.copy(writeLimit = x))
                .text("set 0 or a limit in bytes/s")

            opt[Int]("max-retry-times")
                .valueName("<num>")
                .action((x, c) => c.copy(maxRetryTimes = x))
                .text("maximum rety time when query timeout")

            opt[Boolean]("decode-unicode")
                .action( (x, c) => c.copy(decodeUnicode = x) )
                .text("names should be decoded to unicode when received.")

            opt[Long]("query-timeout")
                .valueName("<ms>")
                .action((x, c) => c.copy(queryTimeout = x))
                .text("the timeout of each DNS query performed by this resolver (in milliseconds).")

            opt[String]('t', "query-type")
                .valueName("<type>")
                .action((x, c) => c.copy(queryType = valueOf(x.toUpperCase)))
                .text("DNS record type.")

            opt[Boolean]('r', "recursion")
                .action((x, c) => c.copy(recurseQuery = x))
                .text("send a DNS query with recursive mode.")

            opt[Unit]('v', "verbose").action( (_, c) =>
                c.copy(loggingLevel = Level.INFO))
                .text("show verbose logs")

            opt[Unit]('d', "debug").action( (_, c) =>
                c.copy(loggingLevel = Level.DEBUG))
                .text("show debug logs")

            opt[Int]('b', "bench")
                .valueName("<num>")
                .action((x, c) => c.copy(benchmarkIterations = x))
                .text("the number of iterations for which the benchmark is run.")

            arg[String]("<domain>...")
                .unbounded()
                .optional()
                .action((x, c) => c.copy(queryDomains = c.queryDomains :+ x))
                .text("query domain")

            help("help").text("prints this usage text")
        }

        parser.parse(args, Config())
    }
}
