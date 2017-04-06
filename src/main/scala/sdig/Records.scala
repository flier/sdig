package sdig

import java.net.{Inet4Address, Inet6Address, InetAddress}

import com.google.common.base.Charsets
import io.netty.handler.codec.dns.{DefaultDnsRecordDecoder, DnsRawRecord, DnsRecord, DnsRecordType}
import io.netty.util.internal.ObjectUtil.checkNotNull
import com.google.common.base.Preconditions.checkArgument

trait DnsARecord extends DnsRecord {
    /*
     * A 32 bit IPv4 Internet address.
     */
    val address: Inet4Address
}

trait DnsAAAARecord extends DnsRecord {
    /*
     * A 128 bit IPv4 Internet address.
     */
    val address: Inet6Address
}

trait DnsCNameRecord extends DnsRecord {
    /*
     * the canonical or primary name for the owner.
     *
     * The owner name is an alias.
     */
    val hostname: String
}

trait DnsMxRecord extends DnsRecord {
    /*
     * Returns the preference given to this RR among others at the same owner.
     *
     * Lower values are preferred.
     */
    val preference: Int

    /*
     * Returns a host willing to act as a mail exchange for the owner name.
     */
    val hostname: String
}

trait DnsNsRecord extends DnsRecord {
    /*
     * a host which should be authoritative for the specified class and domain.
     */
    val hostname: String
}

trait DnsSoaRecord extends DnsRecord {
    /*
     * the name server that was the original or primary source of data for this zone.
     */
    val primaryNameServer: String
    /*
     * the mailbox of the person responsible for this zone.
     */
    val responsibleAuthorityMailbox: String
    /*
     * The unsigned 32 bit version number of the original copy of the zone.
     *
     * Zone transfers preserve this value.
     * This value wraps and should be compared using sequence space arithmetic.
     */
    val serialNumber: Long
    /*
     * A 32 bit time interval before the zone should be refreshed.
     */
    val refreshInterval: Long
    /*
     * A 32 bit time interval that should elapse before a failed refresh should be retried.
     */
    val retryInterval: Long
    /*
     * A 32 bit time value that specifies the upper limit on the time interval
     * that can elapse before the zone is no longer authoritative.
     */
    val expireLimit: Long
    /*
     * The unsigned 32 bit minimum TTL field that should be exported with any RR from this zone.
     */
    val minimumTTL: Long
}

trait DnsTxtRecord extends DnsRecord {
    /*
     * One or more <character-string>s.
     *
     * TXT RRs are used to hold descriptive text.
     * The semantics of the text depends on the domain where it is found.
     */
    val data: String
}

case class DefaultDnsARecord(name: String,
                             dnsClass: Int,
                             timeToLive: Long,
                             address: Inet4Address) extends DnsARecord {
    override def `type`(): DnsRecordType = DnsRecordType.A
}

object DefaultDnsARecord {
    def parse(raw: DnsRawRecord): DnsARecord = {
        checkNotNull(raw, "raw")
        checkArgument(raw.`type`() == DnsRecordType.A)
        checkArgument(raw.content().readableBytes() == 4)

        val buf = new Array[Byte](raw.content().readableBytes)
        raw.content().readBytes(buf)
        val address = InetAddress.getByAddress(buf).asInstanceOf[Inet4Address]

        DefaultDnsARecord(raw.name(), raw.dnsClass(), raw.timeToLive(), address)
    }
}

case class DefaultDnsAAAARecord(name: String,
                                dnsClass: Int,
                                timeToLive: Long,
                                address: Inet6Address) extends DnsAAAARecord {
    override def `type`(): DnsRecordType = DnsRecordType.AAAA
}

object DefaultDnsAAAARecord {
    def parse(raw: DnsRawRecord): DnsAAAARecord = {
        checkNotNull(raw, "raw")
        checkArgument(raw.`type`() == DnsRecordType.AAAA)
        checkArgument(raw.content().readableBytes() == 16)

        val buf = new Array[Byte](raw.content().readableBytes)
        raw.content().readBytes(buf)
        val address = InetAddress.getByAddress(buf).asInstanceOf[Inet6Address]

        DefaultDnsAAAARecord(raw.name(), raw.dnsClass(), raw.timeToLive(), address)
    }
}

case class DefaultDnsCNameRecord(name: String,
                                 dnsClass: Int,
                                 timeToLive: Long,
                                 hostname: String) extends DnsCNameRecord {
    override def `type`(): DnsRecordType = DnsRecordType.CNAME
}

object DefaultDnsCNameRecord {
    def parse(raw: DnsRawRecord): DnsCNameRecord = {
        checkNotNull(raw, "raw")
        checkArgument(raw.`type`() == DnsRecordType.CNAME)

        val hostname = DefaultDnsRecordDecoder.decodeName(raw.content())

        DefaultDnsCNameRecord(raw.name(), raw.dnsClass(), raw.timeToLive(), hostname)
    }
}

case class DefaultDnsMxRecord(name: String,
                              dnsClass: Int,
                              timeToLive: Long,
                              preference: Int,
                              hostname: String) extends DnsMxRecord {
    override def `type`(): DnsRecordType = DnsRecordType.MX
}

object DefaultDnsMxRecord {
    def parse(raw: DnsRawRecord): DnsMxRecord = {
        checkNotNull(raw, "raw")
        checkArgument(raw.`type`() == DnsRecordType.MX)

        val buf = raw.content()
        val preference = buf.readShort()
        val hostname = DefaultDnsRecordDecoder.decodeName(buf)

        DefaultDnsMxRecord(raw.name(), raw.dnsClass(), raw.timeToLive(), preference, hostname)
    }
}

case class DefaultDnsNsRecord(name: String,
                              dnsClass: Int,
                              timeToLive: Long,
                              hostname: String) extends DnsNsRecord {
    override def `type`(): DnsRecordType = DnsRecordType.NS
}

object DefaultDnsNsRecord {
    def parse(raw: DnsRawRecord): DnsNsRecord = {
        checkNotNull(raw, "raw")
        checkArgument(raw.`type`() == DnsRecordType.NS)

        val hostname = DefaultDnsRecordDecoder.decodeName(raw.content())

        DefaultDnsNsRecord(raw.name(), raw.dnsClass(), raw.timeToLive(), hostname)
    }
}

case class DefaultDnsSoaRecord(name: String,
                               dnsClass: Int,
                               timeToLive: Long,
                               primaryNameServer: String,
                               responsibleAuthorityMailbox: String,
                               serialNumber: Long,
                               refreshInterval: Long,
                               retryInterval: Long,
                               expireLimit: Long,
                               minimumTTL: Long) extends DnsSoaRecord {
    override def `type`(): DnsRecordType = DnsRecordType.SOA
}

object DefaultDnsSoaRecord {
    def parse(raw: DnsRawRecord): DnsSoaRecord = {
        checkNotNull(raw, "raw")
        checkArgument(raw.`type`() == DnsRecordType.SOA)

        val buf = raw.content()

        val primaryNameServer = DefaultDnsRecordDecoder.decodeName(buf)
        val responsibleAuthorityMailbox = DefaultDnsRecordDecoder.decodeName(buf)
        val serialNumber = buf.readUnsignedInt()
        val refreshInterval = buf.readUnsignedInt()
        val retryInterval = buf.readUnsignedInt()
        val expireLimit = buf.readUnsignedInt()
        val minimumTTL = buf.readUnsignedInt()

        DefaultDnsSoaRecord(raw.name(), raw.dnsClass(), raw.timeToLive(),
            primaryNameServer, responsibleAuthorityMailbox, serialNumber,
            refreshInterval, retryInterval, expireLimit, minimumTTL)
    }
}

case class DefaultDnsTxtRecord(name: String,
                               dnsClass: Int,
                               timeToLive: Long,
                               data: String) extends DnsTxtRecord {
    override def `type`(): DnsRecordType = DnsRecordType.TXT
}

object DefaultDnsTxtRecord {
    def parse(raw: DnsRawRecord): DnsTxtRecord = {
        checkNotNull(raw, "raw")
        checkArgument(raw.`type`() == DnsRecordType.TXT)

        val data = raw.content().toString(Charsets.UTF_8)

        DefaultDnsTxtRecord(raw.name(), raw.dnsClass(), raw.timeToLive(), data)
    }
}

object implicitConversions {
    implicit def parseDnsARecord(raw: DnsRawRecord): DnsARecord = DefaultDnsARecord.parse(raw)

    implicit def parseDnsAAAARecord(raw: DnsRawRecord): DnsAAAARecord = DefaultDnsAAAARecord.parse(raw)

    implicit def parseDnsCNameRecord(raw: DnsRawRecord): DnsCNameRecord = DefaultDnsCNameRecord.parse(raw)

    implicit def parseDnsMxRecord(raw: DnsRawRecord): DnsMxRecord = DefaultDnsMxRecord.parse(raw)

    implicit def parseDnsNsRecord(raw: DnsRawRecord): DnsNsRecord = DefaultDnsNsRecord.parse(raw)

    implicit def parseDnsSoaRecord(raw: DnsRawRecord): DnsSoaRecord = DefaultDnsSoaRecord.parse(raw)

    implicit def parseDnsTxtRecord(raw: DnsRawRecord): DnsTxtRecord = DefaultDnsTxtRecord.parse(raw)
}
