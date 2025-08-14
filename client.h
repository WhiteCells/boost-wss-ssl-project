#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>
#include <string>
#include <memory>
#include <chrono>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;

class WssClient : public std::enable_shared_from_this<WssClient>
{
public:
    WssClient(net::io_context &ioc, ssl::context &ctx,
              std::string host, std::string port, std::string target) :
        resolver_(net::make_strand(ioc)),
        ws_(net::make_strand(ioc), ctx),
        host_(std::move(host)),
        port_(std::move(port)),
        target_(std::move(target)) {}

    void run()
    {
        // 可选：SNI
        if (!SSL_set_tlsext_host_name(ws_.next_layer().native_handle(), host_.c_str())) {
            beast::error_code ec(static_cast<int>(::ERR_get_error()), net::error::get_ssl_category());
            std::cerr << "[Client] SNI set error: " << ec.message() << "\n";
        }

        resolver_.async_resolve(
            host_, port_,
            beast::bind_front_handler(&WssClient::on_resolve, shared_from_this()));
    }

private:
    void on_resolve(beast::error_code ec, tcp::resolver::results_type results)
    {
        if (ec) {
            std::cerr << "[Client] resolve error: " << ec.message() << "\n";
            return;
        }
        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));
        beast::get_lowest_layer(ws_).async_connect(results,
                                                   beast::bind_front_handler(&WssClient::on_connect, shared_from_this()));
    }

    void on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type ep)
    {
        if (ec) {
            std::cerr << "[Client] connect error: " << ec.message() << "\n";
            return;
        }
        // TCP OK -> TLS 握手（客户端）
        host_ += ":" + std::to_string(ep.port());
        ws_.next_layer().async_handshake(ssl::stream_base::client,
                                         beast::bind_front_handler(&WssClient::on_tls_handshake, shared_from_this()));
    }

    void on_tls_handshake(beast::error_code ec)
    {
        if (ec) {
            std::cerr << "[Client] TLS handshake error: " << ec.message() << "\n";
            return;
        }
        // TLS OK -> WebSocket 握手
        ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
        ws_.set_option(websocket::stream_base::decorator([](websocket::request_type &req) {
            req.set(http::field::user_agent, "wss-demo-client");
        }));
        ws_.async_handshake(host_, target_,
                            beast::bind_front_handler(&WssClient::on_ws_handshake, shared_from_this()));
    }

    void on_ws_handshake(beast::error_code ec)
    {
        if (ec) {
            std::cerr << "[Client] WS handshake error: " << ec.message() << "\n";
            return;
        }
        // 发送一条消息
        std::string text = "hello from client";
        ws_.text(true);
        ws_.async_write(net::buffer(text),
                        beast::bind_front_handler(&WssClient::on_write, shared_from_this()));
    }

    void on_write(beast::error_code ec, std::size_t)
    {
        if (ec) {
            std::cerr << "[Client] write error: " << ec.message() << "\n";
            return;
        }
        // 读回显
        ws_.async_read(buffer_,
                       beast::bind_front_handler(&WssClient::on_read, shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t bytes)
    {
        if (ec) {
            std::cerr << "[Client] read error: " << ec.message() << "\n";
            return;
        }
        std::string msg = beast::buffers_to_string(buffer_.data());
        buffer_.consume(bytes);
        std::cout << "[Client] recv: " << msg << "\n";

        // 关闭
        ws_.async_close(websocket::close_code::normal,
                        beast::bind_front_handler(&WssClient::on_close, shared_from_this()));
    }

    void on_close(beast::error_code ec)
    {
        if (ec) {
            std::cerr << "[Client] close error: " << ec.message() << "\n";
            return;
        }
        std::cout << "[Client] closed.\n";
    }

private:
    tcp::resolver resolver_;
    websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws_;
    beast::flat_buffer buffer_;
    std::string host_, port_, target_;
};

#endif // _CLIENT_H_
