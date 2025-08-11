#include <curl/curl.h>

#include <random>
#include <stdexcept>

#include <dnsquery/dnsquery.hpp>

#if _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace dnsquery {
namespace {

    static std::size_t curl_write_callback(const void* contents, const std::size_t size, const std::size_t count, void* user_data)
    {
        const std::size_t _total_size = size * count;
        static_cast<std::string*>(user_data)->append(static_cast<const char*>(contents), _total_size);

        return _total_size;
    }

    bool is_ipv6(const std::string& provider)
    {
        bool _is_ipv6 = provider.find(':') != std::string::npos && provider.find('.') == std::string::npos;

        if (_is_ipv6 && (provider.find('[') != std::string::npos || provider.find(']') != std::string::npos)) {
            throw std::invalid_argument("DNS provider address should not contain brackets");
        }

        // std::size_t last_colon = provider.rfind(':');
        // if (last_colon != std::string::npos && last_colon != provider.size() - 1) {
        //     std::string port_part = provider.substr(last_colon + 1);
        //     if (!port_part.empty() && std::all_of(port_part.begin(), port_part.end(), ::isdigit)) {
        //         throw std::invalid_argument("DNS provider address should not contain port, please provide it as argument");
        //     }
        // }

        return _is_ipv6;
    }

}

namespace binary {

    std::vector<std::uint8_t> create_dns_query_packet(const record_type& type, const std::string& domain) noexcept
    {
        std::vector<std::uint8_t> _query_packet;

        // transaction id (random)
        std::uint16_t _transaction_id = std::random_device {}();
        _query_packet.push_back(_transaction_id >> 8);
        _query_packet.push_back(_transaction_id & 0xFF);

        // flags (standard query 0x0100)
        _query_packet.push_back(0x01);
        _query_packet.push_back(0x00);

        // qdcount (1)
        _query_packet.push_back(0x00);
        _query_packet.push_back(0x01);

        // ancount, nscount, arcount (0)
        _query_packet.insert(_query_packet.end(), { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });

        // question (domain name in label format)
        std::size_t _start_pos = 0, _end_pos;
        while ((_end_pos = domain.find('.', _start_pos)) != std::string::npos) {
            std::uint8_t _label_length = static_cast<std::uint8_t>(_end_pos - _start_pos);
            _query_packet.push_back(_label_length);
            _query_packet.insert(_query_packet.end(), domain.begin() + _start_pos, domain.begin() + _end_pos);
            _start_pos = _end_pos + 1;
        }
        std::uint8_t _last_length = static_cast<std::uint8_t>(domain.size() - _start_pos);
        _query_packet.push_back(_last_length);
        _query_packet.insert(_query_packet.end(), domain.begin() + _start_pos, domain.end());
        _query_packet.push_back(0x00); // null terminator

        // qtype
        std::uint16_t _type = static_cast<std::uint16_t>(type);
        _query_packet.push_back(_type >> 8);
        _query_packet.push_back(_type & 0xFF);

        // qclas (in 0x0001)
        _query_packet.push_back(0x00);
        _query_packet.push_back(0x01);

        return _query_packet;
    }

    query_result parse_dns_response(const std::vector<std::uint8_t>& data)
    {
        query_result _result {};
        if (data.size() < 12) {
            throw std::runtime_error("Error on DNS response too short");
        }

        std::uint16_t _flags = (data[2] << 8) | data[3];
        std::uint8_t _rcode = _flags & 0x0F;
        _result.status = static_cast<response_code>(_rcode);

        std::uint16_t _qdcount = (data[4] << 8) | data[5];
        std::uint16_t _ancount = (data[6] << 8) | data[7];

        std::size_t _offset = 12;

        // skip questions
        for (int _q = 0; _q < _qdcount; ++_q) {
            while (_offset < data.size() && data[_offset] != 0) {
                _offset += data[_offset] + 1;
            }
            _offset += 1; // null byte
            _offset += 4; // qtype + qclass
        }

        // parse answers
        for (int _a = 0; _a < _ancount; ++_a) {
            if ((data[_offset] & 0xC0) == 0xC0) { // skip name (can be pointer or labels)
                _offset += 2;
            } else {
                while (_offset < data.size() && data[_offset] != 0) {
                    _offset += data[_offset] + 1;
                }
                _offset += 1;
            }

            const std::uint16_t _type = (data[_offset] << 8) | data[_offset + 1];
            const std::uint16_t _class = (data[_offset + 2] << 8) | data[_offset + 3];
            const std::uint32_t _ttl = (data[_offset + 4] << 24) | (data[_offset + 5] << 16) | (data[_offset + 6] << 8) | data[_offset + 7];
            const std::uint16_t _rdlength = (data[_offset + 8] << 8) | data[_offset + 9];
            _offset += 10;

            query_record _record;
            _record.type = static_cast<record_type>(_type);
            _record.ttl = std::chrono::seconds(_ttl);

            if (_type == static_cast<uint16_t>(record_type::DNS_A) && _rdlength == 4) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &data[_offset], ip, sizeof(ip));
                _record.data = ip;
            } else if (_type == static_cast<uint16_t>(record_type::DNS_AAAA) && _rdlength == 16) {
                char ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &data[_offset], ip, sizeof(ip));
                _record.data = ip;
            } else if (_type == static_cast<uint16_t>(record_type::DNS_CNAME)) {
                // TODO!!
                _record.data = "<CNAME record>";
            }

            _offset += _rdlength;
            _result.answers.push_back(std::move(_record));
        }

        return _result;
    }

}

query_result query_udp(const record_type& type, const std::string& domain, const std::string& provider, const std::uint16_t port)
{
    const bool _is_ipv6 = is_ipv6(provider);
    const std::vector<uint8_t> _query_data = binary::create_dns_query_packet(type, domain);

#ifdef _WIN32
    WSADATA _win32_wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &_win32_wsa_data) != 0) {
        throw std::runtime_error("Error on WSAStartup");
    }
#endif

    // create socket
    SOCKET _socket = socket(_is_ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (_socket == INVALID_SOCKET) {
#ifdef _WIN32
        WSACleanup();
#endif
        throw std::runtime_error("Error on socket creation");
    }
    int _inet_result;

    // inet pton
    sockaddr_storage _destination;
    int _destination_length;
    if (_is_ipv6) {
        sockaddr_in6 _to6 {};
        _inet_result = inet_pton(AF_INET6, provider.c_str(), &_to6.sin6_addr);
        if (_inet_result == 1) {
            _to6.sin6_family = AF_INET6;
            _to6.sin6_port = htons(port);
            std::memcpy(&_destination, &_to6, sizeof(_to6));
            _destination_length = sizeof(_to6);
        }
    } else {
        sockaddr_in _to4 {};
        _inet_result = inet_pton(AF_INET, provider.c_str(), &_to4.sin_addr);
        if (_inet_result == 1) {
            _to4.sin_family = AF_INET;
            _to4.sin_port = htons(port);
            std::memcpy(&_destination, &_to4, sizeof(_to4));
            _destination_length = sizeof(_to4);
        }
    }
    if (_inet_result != 1) {
#ifdef _WIN32
        closesocket(_socket);
        WSACleanup();
#else
        close(_socket);
#endif
        throw std::runtime_error("Error on invalid DNS server address");
    }

    // send to
    const int _sendto_len = static_cast<int>(_query_data.size());
    const char* _sendto_buf = reinterpret_cast<const char*>(_query_data.data());
    const sockaddr* _sendto_to = reinterpret_cast<const sockaddr*>(&_destination);
    _inet_result = sendto(_socket, _sendto_buf, _sendto_len, 0, _sendto_to, _destination_length);
    if (_inet_result < 0) {
#ifdef _WIN32
        closesocket(_socket);
        WSACleanup();
#else
        close(_socket);
#endif
        throw std::runtime_error("Error on sendto");
    }

    // recv from
    int _received_length;
    std::vector<uint8_t> _response(512); // standard DNS max size over UDP
    const int _recvfrom_len = static_cast<int>(_response.size());
    char* _recvfrom_buf = reinterpret_cast<char*>(_response.data());
#ifdef _WIN32
    int _recvfrom_fromlen = _is_ipv6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
#else
    socklen_t _recvfrom_fromlen = _is_ipv6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
#endif
    sockaddr* _recvfrom_from;
    if (_is_ipv6) {
        sockaddr_in6 _from6 {};
        _recvfrom_from = reinterpret_cast<sockaddr*>(&_from6);
        _received_length = recvfrom(_socket, _recvfrom_buf, _recvfrom_len, 0, _recvfrom_from, &_recvfrom_fromlen);
    } else {
        sockaddr_in _from4 {};
        _recvfrom_from = reinterpret_cast<sockaddr*>(&_from4);
        _received_length = recvfrom(_socket, _recvfrom_buf, _recvfrom_len, 0, _recvfrom_from, &_recvfrom_fromlen);
    }
    _response.resize(static_cast<std::size_t>(_received_length));
    if (_received_length < 0) {
#ifdef _WIN32
        closesocket(_socket);
        WSACleanup();
#else
        close(_socket);
#endif
        throw std::runtime_error("Error on recvfrom");
    }

    // close socket
#ifdef _WIN32
    closesocket(_socket);
    WSACleanup();
#else
    close(_socket);
#endif

    return binary::parse_dns_response(_response);
}

query_result query_https(const record_type& type, const std::string& domain, const std::string& provider, const std::uint16_t port)
{
    const bool _is_ipv6 = is_ipv6(provider);
    const std::vector<uint8_t> _query_data = binary::create_dns_query_packet(type, domain);
    const std::string _doh_url = std::string("https://") + (_is_ipv6 ? "[" : "") + provider + (_is_ipv6 ? "]" : "") + ":" + std::to_string(port) + "/dns-query";

    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Error on CURL initialization");
    }

    std::string _response;
    curl_easy_setopt(curl, CURLOPT_URL, _doh_url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, _query_data.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, _query_data.size());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &_response);

    struct curl_slist* _headers = nullptr;
    _headers = curl_slist_append(_headers, "Content-Type: application/dns-message");
    _headers = curl_slist_append(_headers, "Accept: application/dns-message");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, _headers);

    CURLcode _curl_result = curl_easy_perform(curl);
    curl_slist_free_all(_headers);
    curl_easy_cleanup(curl);

    if (_curl_result != CURLE_OK) {
        throw std::runtime_error(std::string("Error on CURL request with :") + curl_easy_strerror(_curl_result));
    }

    return binary::parse_dns_response(std::vector<std::uint8_t>(_response.begin(), _response.end()));
}

}
