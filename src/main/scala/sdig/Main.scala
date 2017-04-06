package sdig

import java.net.{Inet4Address, Inet6Address, InetAddress, InetSocketAddress}
import java.time._
import java.time.format.DateTimeFormatter
import java.util.concurrent.CountDownLatch

import com.google.common.base.{CharMatcher, Joiner}
import com.google.common.net.InetAddresses
import com.typesafe.scalalogging.LazyLogging
import io.netty.channel.AddressedEnvelope
import io.netty.handler.codec.dns.DnsRecordType._
import io.netty.handler.codec.dns._
import io.netty.util.concurrent.Future
import org.slf4j.{Logger, LoggerFactory}

import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer

import sdig.implicitConversions._

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
                LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME)
                    .asInstanceOf[ch.qos.logback.classic.Logger]
                    .setLevel(config.loggingLevel)

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
        val additions = getRecords(DnsSection.ADDITIONAL)

        lines += s";; flags: $flags; QUERY: ${questions.size}, ANSWSER: ${answers.size}, " +
                 s"AUTHORITY: ${authorities.size}, ADDITIONAL: ${additions.size}"

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
                    case raw: DnsRawRecord if record.`type`() == A =>
                        val a: DnsARecord = raw

                        f"$name%-32s\t$ttl\t$dnsClass\t$tp\t${a.address.getHostAddress}"

                    case raw: DnsRawRecord if record.`type`() == AAAA =>
                        val a: DnsAAAARecord = raw

                        f"$name%-32s\t$ttl\t$dnsClass\t$tp\t${a.address.getHostAddress}"

                    case raw: DnsRawRecord if record.`type`() == CNAME =>
                        val cname: DnsCNameRecord = raw

                        f"$name%-32s\t$ttl\t$dnsClass\t$tp\t${cname.hostname}"

                    case raw: DnsRawRecord if record.`type`() == MX =>
                        val mx: DnsMxRecord = raw

                        f"$name%-32s\t$ttl\t$dnsClass\t$tp\t${mx.preference}\t${mx.hostname}"

                    case raw: DnsRawRecord if record.`type`() == NS =>
                        val ns: DnsNsRecord = raw

                        f"$name%-32s\t$ttl\t$dnsClass\t$tp\t${ns.hostname}"

                    case raw: DnsRawRecord if record.`type`() == TXT =>
                        val txt: DnsTxtRecord = raw

                        f"$name%-32s\t$ttl\t$dnsClass\t$tp\t${txt.data}"

                    case ptr: DnsPtrRecord =>
                        f"$name%-32s\t$ttl\t$dnsClass\t$tp\t${ptr.hostname}"

                    case _ =>
                        f"$name%-32s\t$ttl\t$dnsClass\t$tp"
                }
            })
        }

        if (authorities.nonEmpty) {
            lines ++= Seq("", ";; AUTHORITY SECTION:")
            lines ++= authorities.map(record => {
                val name = record.name()
                val ttl = record.timeToLive()
                val dnsClass = dnsClassName(record.dnsClass)
                val tp = record.`type`().name()

                record match {
                    case raw: DnsRawRecord if record.`type`() == SOA =>
                        val soa: DnsSoaRecord = raw

                        f"$name%-32s\t$ttl\t$dnsClass\t$tp\t" +
                        f"${soa.primaryNameServer} ${soa.responsibleAuthorityMailbox} ${soa.serialNumber} " +
                        f"${soa.refreshInterval} ${soa.retryInterval} ${soa.expireLimit} ${soa.minimumTTL}"

                    case _ =>
                        f"$name%-32s\t$ttl\t$dnsClass\t$tp"
                }
            })
        }

        if (additions.nonEmpty) {
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
