---
title: "Large Record Sizes for TLS and DTLS"
category: std

docname: draft-mattsson-tls-super-jumbo-record-limit-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Transport Layer Security"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: "Transport Layer Security"
  type: "Working Group"
  mail: "tls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tls/"
  github: "emanjon/tls-super-jumbo-record-limit"
  latest: "https://emanjon.github.io/tls-super-jumbo-record-limit/draft-mattsson-tls-super-jumbo-record-limit.html"

author:
- initials: J.
  surname: Preuß Mattsson
  name: John Preuß Mattsson
  org: Ericsson
  email: john.mattsson@ericsson.com
- initials: H.
  surname: Tschofenig
  name: Hannes Tschofenig
  org: Siemens
  email: hannes.tschofenig@gmx.net
- initials: M.
  surname: Tüxen
  name: Michael Tüxen
  org: Münster Univ. of Applied Sciences
  email: tuexen@fh-muenster.de

normative:

  RFC2119:
  RFC8174:
  RFC8446:
  RFC8449:
  I-D.ietf-tls-tlsflags:

informative:

  RFC5246:
  RFC6083:
  RFC6347:
  RFC8201:
  RFC9147:

--- abstract

RFC 8449 defines a record size limit Extension for TLS and DTLS allowing endpoints to negotiate a record size limit smaller than the protocol-defined maximum record size, which is around 2<sup>14</sup> bytes. This document specifies a TLS flags extension to be used in combination with the record size limit extension allowing endpoints to use a record size limit larger than the protocol-defined maximum record size, but not more than about 2<sup>16</sup> bytes.

--- middle

# Introduction

The records in all version of TLS records has an uint16 length field that could theoretically allow records 65535 octets in size. TLS does however have a lower protocol-defined limit for maximum plaintext record size. For TLS 1.2 {{RFC5246}}, that limit is 2<sup>14</sup> = 16384 octets. TLS 1.3 {{RFC8446}} uses a limit of 2<sup>14</sup> + 1 = 16385 octets. In addition, TLS 1.2 allow expansion from compression and protection up to 2048 octets (though typically this expansion is only 16 octets). TLS 1.3 reduces the allowance for expansion to 256 octets.

The "record_size_limit" extension {{RFC8449}} enables endpoints to negotiate a lower limit for the maximum plaintext record size, but does not allow endpoints to increase the limits enforced by TLS 1.3 {{RFC8446}}, TLS 1.2 {{RFC5246}}, DTLS 1.3 {{RFC9147}}, and DTLS 1.2 {{RFC6347}}.

In some use cases such as DTLS over SCTP {{RFC6083}} the 2<sup>14</sup> bytes limit is a severe limitation.

This document defines a "super_jumbo_record_size_limit" flags extension ({{ex}}). The Record Size Limit Extension for TLS as specified in {{RFC8449}} used in combination with the flags extension defined in this document allows endpoints to negotiate a record size limit larger than the protocol-defined maximum record size. This can be used to bump up the maximum size of protected records to 2<sup>16</sup>-1 bytes, which is larger than the default limit of 2<sup>14</sup> bytes. This extension is defined for version 1.3 of TLS and DTLS.

# Terminology

{::boilerplate bcp14-tagged}

# The "super_jumbo_record_size_limit" Flags Extension {#ex}

The "super_jumbo_record_size_limit" extension does not have any ExtensionData. When the "super_jumbo_record_size_limit" extension is negotiated, an endpoint MUST be prepared to accept protected records with ciphertexts of length 2<sup>16</sup> bytes and protected record with plaintext of length 2<sup>16</sup> - the allowed expansion. The maximum length of a protected record plaintext is therefore 2<sup>16</sup> - 2<sup>11</sup> = 63488 octets in TLS 1.2 and 2<sup>16</sup> - 2<sup>8</sup> = 65280 octets in TLS 1.3. Unprotected messages are still subject to the lower default limits in TLS/DTLS 1.3.

The "super_jumbo_record_size_limit" extension MUST NOT be negotiated together with the "record_size_limit" extension or the "max_fragment_length" extension. A client MUST treat receipt
of "super_jumbo_record_size_limit" together with "record_size_limit" or "max_fragment_length" as a fatal error, and it SHOULD generate an "illegal_parameter" alert.

In TLS 1.3, the server sends the "super_jumbo_record_size_limit" extension in the EncryptedExtensions message.

During renegotiation or resumption, the record size limit is renegotiated.  Records are subject to the limits that were set in the handshake that produces the keys that are used to protect those records.  This admits the possibility that the extension might not be negotiated when a connection is renegotiated or resumed.

For DTLS 1.3 {{RFC9147}} over UDP or DCCP, the Path Maximum Transmission Unit (PMTU) also limits the size of records.  The record size limit does not affect PMTU discovery and SHOULD be set independently. The record size limit is fixed during the handshake and so should be set based on constraints at the endpoint and not based on the current network environment. In comparison, the PMTU is determined by the network path and can change dynamically over time. See PMTU {{RFC8201}} and Section 4.1 of DTLS 1.3 {{RFC9147}} for more detail on PMTU discovery. For DTLS over TCP or SCTP, which automatically fragments and reassembles datagrams, there is no PMTU limitation.

# AEAD Limits

The maximum record size limit is an input to the AEAD limits calculations in TLS 1.3 {{RFC8446}} and DTLS 1.3 {{RFC9147}}. Increasing the maximum record size to 2<sup>16</sup> bytes while keeping the same confidentiality and integrity advantage therefore requires lower AEAD limits. When the "super_jumbo_record_size_limit" has been negotiated, existing AEAD limits shall be decreased by a factor of 4. For example, when AES-CGM is used in TLS 1.3 {{RFC8446}} with a 64 kB record limit, only 2<sup>22.5</sup> records (about 6 million) may be encrypted on a given connection.

# Security Considerations

Large record sizes might require more memory allocation for senders and receivers. Large record sizes also means that more processing is done before verification of non-authentic records fails.

# IANA Considerations

This document registers the following entry to the "TLS Flags" registry defined in {{I-D.ietf-tls-tlsflags}}:

   *  Value: TBD1
   *  Flag Name: large_record_size
   *  Messages: CH, EE
   *  Recommended: Y
   *  Reference: [This document]

--- back

# Acknowledgments
{:numbered="false"}

Add your name here.
