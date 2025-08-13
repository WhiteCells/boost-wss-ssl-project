#include <boost/beast.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;

int main() {
    try {
        net::io_context ioc;
        ssl::context ctx{ssl::context::tlsv12_client};

        // 信任自签证书（测试用）
        ctx.set_verify_mode(ssl::verify_none);
        // 如果是正式 CA 证书，改成：
        // ctx.set_default_verify_paths();
        // ctx.set_verify_mode(ssl::verify_peer);

        tcp::resolver resolver{ioc};
        auto const results = resolver.resolve("127.0.0.1", "8081");

        websocket::stream<ssl::stream<tcp::socket>> ws(ioc, ctx);

        // 设置 SNI 主机名（必要，否则有些服务器会拒绝）
        if(!SSL_set_tlsext_host_name(ws.next_layer().native_handle(), "127.0.0.1")) {
            beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
            throw beast::system_error{ec};
        }

        net::connect(ws.next_layer().next_layer(), results.begin(), results.end());

        // SSL 握手
        ws.next_layer().handshake(ssl::stream_base::client);

        // WebSocket 握手
        ws.handshake("127.0.0.1", "/");

        // 发送消息
        std::string text = "Hello over WSS!";
        ws.write(net::buffer(text));

        // 接收回显
        beast::flat_buffer buffer;
        ws.read(buffer);
        std::cout << "Received: " << beast::make_printable(buffer.data()) << "\n";

        // 关闭连接
        ws.close(websocket::close_code::normal);
    }
    catch (std::exception const& e) {
        std::cerr << "Client error: " << e.what() << "\n";
        return 1;
    }
}
