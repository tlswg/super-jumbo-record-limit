---
title: "Large Record Sizes for TLS and DTLS with Reduced Overhead"
abbrev: "Large Record Sizes for TLS"
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
  RFC8447:
  RFC8449:
  RFC9147:

informative:

  RFC6083:

--- abstract

TLS 1.3 records limit the inner plaintext (TLSInnerPlaintext) size to 2<sup>14</sup> + 1 bytes, which includes one byte for the content type, and have a 3-byte overhead due to the fixed fields opaque_type and legacy_record_version. This document defines a TLS extension that allows endpoints to negotiate a larger maximum inner plaintext size, up to 2<sup>32</sup> - 256 bytes, while reducing overhead.

--- middle

# Introduction

TLS 1.3 records limit the inner plaintext (TLSInnerPlaintext) size to 2<sup>14</sup> + 1 bytes, which includes one byte for the content type, and have a 3-byte overhead due to the fixed fields opaque_type and legacy_record_version. TLS-based protocols are increasingly used to secure long-lived interfaces in critical infrastructure, such as telecommunication networks. In some infrastructure use cases, the upper layer of DTLS expects a message oriented service and uses message sizes much larger than 2<sup>14</sup>-bytes. In these cases, the 2<sup>14</sup>-byte limit in TLS necessitates an additional protocol layer for fragmentation, resulting in increased CPU and memory consumption and additional complexity. Allowing 2<sup>32</sup>-byte records would eliminate additional fragmentation in almost all use cases. In {{RFC6083}} (DTLS over SCTP), the 2<sup>14</sup>-byte limit is a severe restriction.

This document defines a "large_record_size_limit" extension that allows endpoints to negotiate a larger maximum inner plaintext (TLSInnerPlaintext) size. This extension is valid in TLS 1.3 and DTLS 1.3. The extension works similarly to the "record_size_limit" extension defined in {{RFC8449}}. Additionally, this document defines new TLS 1.3 TLSLargeCiphertext and DTLS 1.3 unified_hdr structures to enable inner plaintexts up to 2<sup>32</sup> - 256 bytes with reduced overhead. For example, inner plaintexts up to 2<sup>16</sup> - 256 bytes can be supported with 3 bytes less overhead, which is useful in constrained IoT environments. The "large_record_size_limit" extension is incompatible with middleboxes expecting TLS 1.2 records.

# Terminology

{::boilerplate bcp14-tagged}

# The "large_record_size_limit" Extension

The ExtensionData of the "large_record_size_limit" extension is LargeRecordSizeLimit:

~~~~~~~~
   uint32 LargeRecordSizeLimit;
~~~~~~~~

LargeRecordSizeLimit denotes the maximum size, in bytes, of inner plaintexts that the endpoint is willing to receive. It includes the content type and padding (i.e., the complete length of TLSInnerPlaintext). AEAD expansion is not included.

The large record size limit only applies to records sent toward the endpoint that advertises the limit. An endpoint can send records that are larger than the limit it advertises as its own limit. A TLS endpoint that receives a record larger than its advertised limit MUST generate a fatal "record_overflow" alert; a DTLS endpoint that receives a record larger than its advertised limit MAY either generate a fatal "record_overflow" alert or discard the record. An endpoint MUST NOT add padding to records that would cause the length of TLSInnerPlaintext to exceed the limit advertised by the other endpoint.

Endpoints MUST NOT send a "large_record_size_limit" extension with a value smaller than 64 or larger than 2<sup>32</sup> - 256. An endpoint MUST treat receipt of a smaller or larger value as a fatal error and generate an "illegal_parameter" alert.

The server sends the "large_record_size_limit" extension in the EncryptedExtensions message. During resumption, the limit is renegotiated. Records are subject to the limits that were set in the handshake that produces the keys that are used to protect those records. This admits the possibility that the extension might not be negotiated during resumption.

Unprotected messages and records protected with early_traffic_secret or handshake_traffic_secret are not subject to the large record size limit.

When the "large_record_size_limit" extension is negotiated:

* All TLS 1.3 records protected with application_traffic_secret MUST use the TLSLargeCiphertext structure instead of the TLSCiphertext structure. The size of the length field depends on the limit advertised by the receiver. If the limit is less than 2<sup>16</sup> - 255 an uint16 is used, if the limit is larger than 2<sup>24</sup> - 256 an uint32 is used, and otherwise an uint24 is used. The length is fixed for the connection. Different lengths might be used in different directions.

~~~~~~~~
   enum { u16(0), u24(1), u32(2) } Length;
~~~~~~~~
~~~~~~~~
   struct {
       select (Length.type) {
           case u16: uint16;
           case u24: uint24;
           case u32: uint32;
       };
    } VarLength;
~~~~~~~~
~~~~~~~~
   struct {
       VarLength length;
       opaque encrypted_record[TLSLargeCiphertext.length];
   } TLSLargeCiphertext;
~~~~~~~~

* All DTLS 1.3 records protected with application_traffic_secret and with length present MUST use a unified_hdr structure with a length equal to the TLS 1.3 length field defined above.

~~~~~~~~
    0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+
   |0|0|1|C|S|L|E E|
   +-+-+-+-+-+-+-+-+
   | Connection ID |   Legend:
   | (if any,      |
   /  length as    /   C   - Connection ID (CID) present
   |  negotiated)  |   S   - Sequence number length
   +-+-+-+-+-+-+-+-+   L   - Length present
   |  8 or 16 bit  |   E   - Epoch
   |Sequence Number|
   +-+-+-+-+-+-+-+-+
   | 16, 24, or 32 |
   |  bit Length   |
   | (if present)  |
   +-+-+-+-+-+-+-+-+
~~~~~~~~

* An endpoint MAY generate records protected with application_traffic_secret with inner plaintext that is equal to or smaller than the LargeRecordSizeLimit value it receives from its peer. An endpoint MUST NOT generate a protected record with inner plaintext that is larger than the LargeRecordSizeLimit value it receives from its peer.

The "large_record_size_limit" extension is not compatible with middleboxes expecting TLS 1.2 records and SHOULD NOT be negotiated where such middleboxes are expected. A server MUST NOT send extension responses to more than one of "large_record_size_limit", "record_size_limit", and "max_fragment_length". A client MUST treat receipt of more than one of "large_record_size_limit", "record_size_limit", and "max_fragment_length" as a fatal error, and it SHOULD generate an "illegal_parameter" alert.

The Path Maximum Transmission Unit (PMTU) in DTLS also limits the size of records. The record size limit does not affect PMTU discovery and SHOULD be set independently. The record size limit is fixed during the handshake and so should be set based on constraints at the endpoint and not based on the current network environment. In comparison, the PMTU is determined by the network path and can change dynamically over time.

# Limits on Key Usage

The maximum record size limit is an input to the AEAD limits calculations in TLS 1.3 {{RFC8446}} and DTLS 1.3 {{RFC9147}}. Increasing the maximum record size to more than 2<sup>14</sup> + 256 bytes while keeping the same confidentiality and integrity advantage per write key therefore requires lower AEAD limits. When the "large_record_size" has been negotiated record size limit larger than 2<sup>14</sup> + 1 bytes, existing AEAD limits SHALL be decreased by a factor of (LargeRecordSizeLimit) / (2^14-256). For example, when AES-CGM is used in TLS 1.3 {{RFC8446}} with a 64 kB record limit, only arounf 2<sup>22.5</sup> records (about 6 million) may be encrypted on a given connection.

# Security Considerations

Large record sizes might require more memory allocation for senders and receivers. Additionally, larger record sizes also means that more processing is done before verification of non-authentic records fails.

The use of larger record sizes can either simplify or complicate traffic analysis, depending on the application. The LargeRecordSizeLimit is just an upper limit and it is still the sender that decides the size of the inner plaintexts up to that limit.

# IANA Considerations

IANA is requested to assign a new value in the TLS ExtensionType Values registry defined by {{RFC8447}}:

   *  The Extension Name should be large_record_size_limit

   *  The TLS 1.3 value should be CH, EE

   *  The DTLS-Only value should be N

   *  The Recommended value should be Y

   *  The Reference should be this document

--- back

# Acknowledgments
{:numbered="false"}

The authors would like to thank {{{Stephen Farrell}}}, {{{Benjamin Kaduk}}}, and {{{Martin Thomson}}} for their valuable comments and feedback. Some of the text were inspired by and borrowed from {{RFC8449}}.
