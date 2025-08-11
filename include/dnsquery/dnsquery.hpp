#pragma once

#include <chrono>
#include <string>
#include <vector>

namespace dnsquery {

/// See https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
/// @brief Supported DNS record types
enum struct record_type : std::uint16_t {
    DNS_A = 1, // ipv4
    DNS_AAAA = 28, // ipv6
    DNS_CNAME = 5,
};

/// See https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
/// @brief DNS response codes relevant for detection
enum struct response_code : std::uint16_t {
    DNS_NOERROR = 0,
    DNS_NXDOMAIN = 3,
};

/// @brief Represents a single DNS resource record
struct query_record {
    record_type type;
    std::chrono::seconds ttl;
    std::string data;
};

/// @brief Represents the result of a DNS query
struct query_result {
    response_code status;
    std::vector<query_record> answers;
};

namespace binary {

    /// @brief Creates a binary DNS query packet ready to be sent to a DNS server
    /// @param type The DNS record type to request (for example A, AAAA, TXT)
    /// @param domain The domain name to query (for example "example.com")
    /// @return A vector of bytes representing the DNS query packet formatted according to the DNS protocol
    /// @note This function only prepares the query data and does not send the request
    [[nodiscard]] std::vector<std::uint8_t> create_dns_query_packet(const record_type& type, const std::string& domain) noexcept;

    /// @brief Parses a raw binary DNS response packet
    /// @param data A vector of bytes containing the raw DNS response from the server
    /// @return A query_result object holding the parsed DNS records and metadata
    /// @throws std::runtime_error if the response is malformed or parsing fails
    [[nodiscard]] query_result parse_dns_response(const std::vector<std::uint8_t>& data);

}

/// @brief Sends a DNS query over UDP (plaintext) to the specified DNS server
/// @param type The DNS record type to request
/// @param domain The domain name to query
/// @param provider The DNS server address (ipv4 without port, ipv6 without port or hostname)
/// @param port The DNS server port (default UDP port is 53)
/// @return A query_result containing DNS records returned by the server
/// @throws std::invalid_argument on invalid provider
/// @throws std::runtime_error on network errors or parsing errors
[[nodiscard]] query_result query_udp(const record_type& type, const std::string& domain, const std::string& provider, const std::uint16_t port = 53);

/// @brief Sends a DNS query over HTTPS (DoH) to the specified DNS server
/// @param type The DNS record type to request
/// @param domain The domain name to query
/// @param provider The DNS-over-HTTPS server address (ipv4 without port, ipv6 without port or hostname)
/// @param port The DNS server port (default HTTPS port is 443)
/// @return A query_result containing DNS records returned by the server
/// @throws std::invalid_argument on invalid provider
/// @throws std::runtime_error on HTTP errors, network errors or parsing errors
[[nodiscard]] query_result query_https(const record_type& type, const std::string& domain, const std::string& provider, const std::uint16_t port = 443);

}