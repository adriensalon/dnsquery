# dnsquery

Perform DNS queries over UDP (plaintext) and HTTPS (DNS-over-HTTPS, DoH), using C++17 and CMake. Supports querying common DNS record types such as `A` (IPv4), `AAAA` (IPv6), and `CNAME` records, and provides parsing of DNS response packets.

## Usage

```cpp
const std::string _domain = "youtube.com";
const std::string _provider_ipv4 = "8.8.8.8"; // cloudflare
const std::string _provider_ipv6 = "2001:4860:4860::8888"; // cloudflare ipv6

using namespace dnsquery;
```

### Perform a DNS query over UDP (plaintext)

```cpp
// query ipv4
query_result ipv4_udp_from_ipv4 = query_udp(record_type::DNS_A, _domain, _provider_ipv4);
query_result ipv4_udp_from_ipv6 = query_udp(record_type::DNS_A, _domain, _provider_ipv6);

// query ipv6
query_result ipv6_udp_from_ipv4 = query_udp(record_type::DNS_AAAA, _domain, _provider_ipv4);
query_result ipv6_udp_from_ipv6 = query_udp(record_type::DNS_AAAA, _domain, _provider_ipv6);

// etc
```

### Perform a DNS query over HTTPS (DoH)

```cpp
// query ipv4
query_result ipv4_https_from_ipv4 = query_https(record_type::DNS_A, _domain, _provider_ipv4);
query_result ipv4_https_from_ipv6 = query_https(record_type::DNS_A, _domain, _provider_ipv6);

// query ipv6
query_result ipv6_https_from_ipv4 = query_https(record_type::DNS_AAAA, _domain, _provider_ipv4);
query_result ipv6_https_from_ipv6 = query_https(record_type::DNS_AAAA, _domain, _provider_ipv6);

// etc
```