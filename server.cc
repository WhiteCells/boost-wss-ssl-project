#include <boost/beast.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>
#include <thread>

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;

void do_session(tcp::socket socket, ssl::context& ctx) {
    try {
        // 先构造 SSL 流
        ssl::stream<beast::tcp_stream> ssl_stream(std::move(socket), ctx);

        // SSL 握手（服务器模式）
        ssl_stream.handshake(ssl::stream_base::server);

        // 再构造 WebSocket 流
        websocket::stream<ssl::stream<beast::tcp_stream>> ws(std::move(ssl_stream));

        // WebSocket 握手
        ws.accept();

        for (;;) {
            beast::flat_buffer buffer;
            ws.read(buffer);
            ws.text(ws.got_text());
            ws.write(buffer.data()); // 回显
        }
    }
    catch (std::exception const& e) {
        std::cerr << "Session error: " << e.what() << "\n";
    }
}

int main() {
    try {
        net::io_context ioc{1};

        ssl::context ctx{ssl::context::tlsv12_server};
        ctx.set_options(
            ssl::context::default_workarounds
            | ssl::context::no_sslv2
            | ssl::context::single_dh_use);
        ctx.use_certificate_chain_file("cert.pem");
        ctx.use_private_key_file("key.pem", ssl::context::pem);

        tcp::acceptor acceptor{ioc, {tcp::v4(), 8081}};
        for (;;) {
            tcp::socket socket{ioc};
            acceptor.accept(socket);
            std::thread{&do_session, std::move(socket), std::ref(ctx)}.detach();
        }
    }
    catch (std::exception const& e) {
        std::cerr << "Server error: " << e.what() << "\n";
        return 1;
    }
}
