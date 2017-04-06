package com.nexusguard.sdig

import java.io.File
import java.net.{Inet4Address, Inet6Address, InetAddress, InetSocketAddress}
import java.time.format.DateTimeFormatter
import java.time._
import java.util.concurrent.CountDownLatch

import ch.qos.logback.classic.Level
import com.google.common.base.{CharMatcher, Joiner}
import com.google.common.net.InetAddresses
import com.typesafe.scalalogging.LazyLogging
import io.netty.channel.AddressedEnvelope
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.nio.NioDatagramChannel
import io.netty.handler.codec.dns.DnsRecordType._
import io.netty.handler.codec.dns._
import io.netty.resolver.dns.{DnsNameResolver, DnsNameResolverBuilder, DnsServerAddresses}
import io.netty.util.concurrent.Future
import org.apache.commons.pool2.impl.{DefaultPooledObject, GenericObjectPool}
import org.apache.commons.pool2.{BasePooledObjectFactory, PooledObject}
import org.slf4j.{Logger, LoggerFactory}

import scala.io.Source
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer

case class Config(loggingLevel: Level = Level.WARN,
                  inputFiles: Seq[File] = Seq(),
                  queryDomains: Seq[String] = Seq(),
                  dnsServers: Seq[String] = Seq(),
                  workerThreads: Int = Runtime.getRuntime.availableProcessors(),
                  decodeUnicode: Boolean = false,
                  queryTimeout: Long = Duration.ofSeconds(5).toMillis,
                  queryType: DnsRecordType = A,
                  recurseQuery: Boolean = true)
{
    LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME)
        .asInstanceOf[ch.qos.logback.classic.Logger]
        .setLevel(loggingLevel)

    val eventLoopGroup: NioEventLoopGroup = new NioEventLoopGroup(workerThreads)

    val dnsServerAddrs: DnsServerAddresses = if (dnsServers.isEmpty) {
        DnsServerAddresses.defaultAddresses()
    } else {
        DnsServerAddresses.shuffled(dnsServers.map(addr =>
            addr.split(':') match {
                case Array(host, port) => new InetSocketAddress(host, port.toInt)
                case Array(host) => new InetSocketAddress(host, Config.DEFAULT_DNS_PORT)
            }
        ).asJava)
    }

    val dnsNameResolverPool: GenericObjectPool[DnsNameResolver] =
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
            })

    val domains: Seq[String] = queryDomains ++ inputFiles.flatMap(Source.fromFile(_).getLines())
}

object Config {
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

object Main extends LazyLogging {
    def dnsClassName(clazz: Int): String = {
        clazz & 0xFFFF match {
            case DnsRecord.CLASS_IN => "IN"
            case DnsRecord.CLASS_CSNET => "CSNET"
            case DnsRecord.CLASS_CHAOS => "CHAOS"
            case DnsRecord.CLASS_HESIOD => "HESIOD"
            case DnsRecord.CLASS_NONE => "NONE"
            case DnsRecord.CLASS_ANY => "ANY"
            case _ => s"UNKNOWN($clazz)"
        }
    }

    def main(args: Array[String]): Unit = {
        Config.parse(args) match {
            case Some(config) =>
                val questions = config.domains
                    .map(domain =>
                        CharMatcher.whitespace().trimTrailingFrom(
                            CharMatcher.whitespace().trimLeadingFrom(domain)))
                    .map(domain =>
                        if (config.queryType == PTR && !domain.endsWith(".arpa")) {
                            val addr = InetAddresses.forString(domain)

                            Joiner.on('.').join(addr.getAddress.reverse.map("%x".format(_)).toIterator.asJava) +
                            (addr match {
                                case _: Inet4Address => ".in-addr.arpa"
                                case _: Inet6Address => ".ip6.arpa"
                            })
                        } else {
                            domain
                        })
                    .map(new DefaultDnsQuestion(_, config.queryType))

                try {
                    val finished = new CountDownLatch(questions.size)

                    logger.info(s"sending ${finished.getCount} questions")

                    questions.foreach(question => {
                        val ts = Instant.now()

                        val queryClass = dnsClassName(question.dnsClass)
                        val queryType = question.`type`().name()

                        logger.debug(s"sending DNS query: ${question.name}\t$queryClass\t$queryType")

                        val resolver = config.dnsNameResolverPool.borrowObject()

                        resolver.query(question).addListener((future: Future[AddressedEnvelope[DnsResponse, InetSocketAddress]]) => {
                            try {
                                if (future.isSuccess) {
                                    val answer = future.get()

                                    println(dumpResponse(answer.content(), answer.sender(), ts))
                                } else {
                                    logger.warn(s"received error, ${future.cause()}")
                                }
                            } finally {
                                config.dnsNameResolverPool.returnObject(resolver)

                                finished.countDown()
                            }
                        })
                    })

                    finished.await()
                } finally {
                    config.eventLoopGroup.shutdownGracefully()
                }


            case None => logger.error(s"fail to parse arguments, $args")
        }
    }

    def dumpResponse(response: DnsResponse, server: InetSocketAddress, ts: Instant): String = {
        logger.debug(s"received DNS answer from $server")

        val lines = new ListBuffer[String]()

        lines ++= Seq("", s";; ->>HEADER<<- opcode: ${response.opCode}, status: ${response.code}, id: ${response.id}")

        val flags = List(
            if (response.count(DnsSection.QUESTION) > 0) Some("qr") else None,
            if (response.isAuthoritativeAnswer) Some("aa") else None,
            if (response.isTruncated) Some("tc") else None,
            if (response.isRecursionDesired) Some("rd") else None,
            if (response.isRecursionAvailable) Some("ra") else None
        ).flatten.mkString(" ")

        def getRecords(section: DnsSection): Seq[DnsRecord] =
            (0 until response.count(section)).map(response.recordAt(section, _).asInstanceOf[DnsRecord])

        val questions = getRecords(DnsSection.QUESTION)
        val answers = getRecords(DnsSection.ANSWER)
        val authorities = getRecords(DnsSection.AUTHORITY)
        val additionals = getRecords(DnsSection.ADDITIONAL)

        lines += s";; flags: $flags; QUERY: ${questions.size}, ANSWSER: ${answers.size}, " +
                 s"AUTHORITY: ${authorities.size}, ADDITIONAL: ${additionals.size}"

        if (questions.nonEmpty) {
            lines ++= Seq("", ";; QUESTION SECTION:")
            lines ++= questions.map(record => {
                val name = record.name()
                val dnsClass = dnsClassName(record.dnsClass)

                s";; $name\t$dnsClass\t${record.`type`.name}"
            })
        }

        if (answers.nonEmpty) {
            lines ++= Seq("", ";; ANSWER SECTION:")
            lines ++= answers.map(record => {
                val name = record.name()
                val ttl = record.timeToLive()
                val dnsClass = dnsClassName(record.dnsClass)
                val tp = record.`type`().name()

                record match {
                    case raw: DnsRawRecord if Array(A, AAAA) contains record.`type`() =>
                        val buf = new Array[Byte](raw.content().readableBytes)
                        val idx = raw.content().readerIndex()
                        raw.content().getBytes(idx, buf)
                        val ip = InetAddress.getByAddress(buf).getHostAddress

                        f"$name%-32s\t$ttl\t$dnsClass\t$tp\t$ip"

                    case raw: DnsRawRecord if record.`type`() == CNAME =>
                        val cname = DefaultDnsRecordDecoder.decodeName(raw.content())

                        f"$name%-32s\t$ttl\t$dnsClass\t$tp\t$cname"

                    case raw: DnsRawRecord if record.`type`() == MX =>
                        val buf = raw.content()
                        val preference = buf.readShort()
                        val mx = DefaultDnsRecordDecoder.decodeName(buf)

                        f"$name%-32s\t$ttl\t$dnsClass\t$tp\t$preference\t$mx"

                    case ptr: DnsPtrRecord =>
                        val hostname = ptr.hostname

                        f"$name%-32s\t$ttl\t$dnsClass\t$tp\t$hostname"

                    case _ =>
                        f"$name%-32s\t$ttl\t$dnsClass\t$tp"
                }
            })
        }

        if (authorities.nonEmpty) {
            lines ++= Seq("", ";; AUTHORITY SECTION:")
        }

        if (additionals.nonEmpty) {
            lines ++= Seq("", ";; ADDITIONAL SECTION:")
        }

        val now = Instant.now()
        val elapsed = Duration.between(ts, now).toMillis
        val when = ZonedDateTime.ofInstant(now, ZoneId.systemDefault()).format(DateTimeFormatter.RFC_1123_DATE_TIME)

        lines ++= Seq("",
                      s";; Query time: $elapsed msec",
                      s";; SERVER: ${server.getAddress.getHostAddress}#${server.getPort}",
                      s";; WHEN: $when")

        Joiner.on('\n').join(lines.toIterator.asJava)
    }
}
