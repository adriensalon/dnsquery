#include <iostream>

#include <dnsquery/dnsquery.hpp>

void print_query(const std::string& domain, const std::string& provider, const dnsquery::query_result& result)
{
    std::cout << "Domain: " << domain << "\n";
    std::cout << "Provider: " << provider << "\n";
    std::cout << "Response code: " << (int)result.status << "\n";

    int _index = 0;
    for (const auto& _answer : result.answers) {
        std::cout << "Answers[" << _index++ << "]:" << std::endl;
        std::cout << "      Type: " << (int)_answer.type << std::endl;
        std::cout << "      TTL: " << _answer.ttl.count() << std::endl;
        std::cout << "      Data: " << _answer.data << std::endl;
    }

    std::cout << std::endl;
}

int main()
{
    const std::string _domain = "youtube.com";
    const std::string _provider_ipv4 = "8.8.8.8"; // cloudflare
    const std::string _provider_ipv6 = "2001:4860:4860::8888"; // cloudflare ipv6
    const dnsquery::record_type _type_ipv4 = dnsquery::record_type::DNS_A;
    const dnsquery::record_type _type_ipv6 = dnsquery::record_type::DNS_AAAA;

    dnsquery::query_result _result;

    try {
        _result = dnsquery::query_udp(_type_ipv4, _domain, _provider_ipv4);
        print_query(_domain, _provider_ipv4, _result);
        _result = dnsquery::query_udp(_type_ipv4, _domain, _provider_ipv6);
        print_query(_domain, _provider_ipv6, _result);
        _result = dnsquery::query_udp(_type_ipv6, _domain, _provider_ipv4);
        print_query(_domain, _provider_ipv4, _result);
        _result = dnsquery::query_udp(_type_ipv6, _domain, _provider_ipv6);
        print_query(_domain, _provider_ipv6, _result);

        _result = dnsquery::query_https(_type_ipv4, _domain, _provider_ipv4);
        print_query(_domain, _provider_ipv4, _result);
        _result = dnsquery::query_https(_type_ipv4, _domain, _provider_ipv6);
        print_query(_domain, _provider_ipv6, _result);
        _result = dnsquery::query_https(_type_ipv6, _domain, _provider_ipv4);
        print_query(_domain, _provider_ipv4, _result);
        _result = dnsquery::query_https(_type_ipv6, _domain, _provider_ipv6);
        print_query(_domain, _provider_ipv6, _result);

    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
    }

    return 0;
}
