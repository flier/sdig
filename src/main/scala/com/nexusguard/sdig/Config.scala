package com.nexusguard.sdig

import java.io.File
import java.net.InetSocketAddress
import java.time.Duration

import ch.qos.logback.classic.Level
import com.typesafe.scalalogging.LazyLogging
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.nio.NioDatagramChannel
import io.netty.handler.codec.dns.DnsRecordType
import io.netty.handler.codec.dns.DnsRecordType.{A, valueOf}
import io.netty.resolver.dns.{DnsNameResolver, DnsNameResolverBuilder, DnsServerAddresses}
import org.apache.commons.pool2.{BasePooledObjectFactory, PooledObject}
import org.apache.commons.pool2.impl.{DefaultPooledObject, GenericObjectPool, GenericObjectPoolConfig}

import scala.io.Source
import scala.collection.JavaConverters._

case class Config(loggingLevel: Level = Level.WARN,
                  inputFiles: Seq[File] = Seq(),
                  queryDomains: Seq[String] = Seq(),
                  dnsServers: Seq[String] = Seq(),
                  workerThreads: Int = Runtime.getRuntime.availableProcessors(),
                  maxTotalPooledResolver: Int = GenericObjectPoolConfig.DEFAULT_MAX_TOTAL,
                  maxIdlePooledResolver: Int = GenericObjectPoolConfig.DEFAULT_MAX_IDLE,
                  minIdlePooledResolver: Int = GenericObjectPoolConfig.DEFAULT_MIN_IDLE,
                  decodeUnicode: Boolean = false,
                  queryTimeout: Long = Duration.ofSeconds(5).toMillis,
                  queryType: DnsRecordType = A,
                  recurseQuery: Boolean = true) extends LazyLogging
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

    lazy val dnsNameResolverPool: GenericObjectPool[DnsNameResolver] =
        new GenericObjectPool[DnsNameResolver](
            new BasePooledObjectFactory[DnsNameResolver]() {
                override def create(): DnsNameResolver = {
                    new DnsNameResolverBuilder(eventLoopGroup.next())
                        .nameServerAddresses(dnsServerAddrs)
                        .channelType(classOf[NioDatagramChannel])
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
            }, new GenericObjectPoolConfig() {{
                logger.debug(s"creating DNS resolver pool, " +
                    s"max_total=$maxTotalPooledResolver, " +
                    s"max_idle=$maxIdlePooledResolver, " +
                    s"min_idle=$minIdlePooledResolver")

                setMaxTotal(maxTotalPooledResolver)
                setMaxIdle(maxIdlePooledResolver)
                setMinIdle(minIdlePooledResolver)
            }})

    lazy val domains: Seq[String] = queryDomains ++ inputFiles.flatMap(Source.fromFile(_).getLines())
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
