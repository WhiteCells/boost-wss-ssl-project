#ifndef _SERVER_H_
#define _SERVER_H_

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>
#include <string>
#include <thread>
#include <memory>
#include <chrono>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;

// 加载服务端证书/私钥
static void load_server_certificate(ssl::context &ctx)
{
    // 一些常见的安全选项
    ctx.set_options(ssl::context::default_workarounds |
                    ssl::context::no_sslv2 |
                    ssl::context::no_sslv3 |
                    ssl::context::no_tlsv1 |
                    ssl::context::no_tlsv1_1 |
                    ssl::context::single_dh_use);

    // 可改为 use_certificate_chain() / use_private_key() 从内存加载
    ctx.use_certificate_chain_file("server.crt");
    ctx.use_private_key_file("server.key", ssl::context::pem);
}

class WssServerSession : public std::enable_shared_from_this<WssServerSession>
{
public:
    explicit WssServerSession(tcp::socket socket, ssl::context &ssl_ctx) :
        ws_(std::move(socket), ssl_ctx) {}

    void run()
    {
        // TLS 握手
        ws_.next_layer().async_handshake(
            ssl::stream_base::server,
            beast::bind_front_handler(&WssServerSession::on_tls_handshake, shared_from_this()));
    }

private:
    void on_tls_handshake(beast::error_code ec)
    {
        if (ec) {
            std::cerr << "[Server] TLS handshake error: " << ec.message() << "\n";
            return;
        }
        // WebSocket 接受握手
        ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        ws_.async_accept(
            beast::bind_front_handler(&WssServerSession::on_ws_accept, shared_from_this()));
    }

    void on_ws_accept(beast::error_code ec)
    {
        if (ec) {
            std::cerr << "[Server] WS accept error: " << ec.message() << "\n";
            return;
        }
        do_read();
    }

    void do_read()
    {
        ws_.async_read(
            buffer_,
            beast::bind_front_handler(&WssServerSession::on_read, shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t bytes)
    {
        if (ec == websocket::error::closed)
            return;
        if (ec) {
            std::cerr << "[Server] read error: " << ec.message() << "\n";
            return;
        }
        std::string msg = beast::buffers_to_string(buffer_.data());
        buffer_.consume(bytes);
        std::cout << "[Server] recv: " << msg << "\n";

        // 回显
        ws_.text(true);
        ws_.async_write(
            net::buffer(msg),
            beast::bind_front_handler(&WssServerSession::on_write, shared_from_this()));
    }

    void on_write(beast::error_code ec, std::size_t)
    {
        if (ec) {
            std::cerr << "[Server] write error: " << ec.message() << "\n";
            return;
        }
        do_read(); // 继续读
    }

private:
    websocket::stream<beast::ssl_stream<tcp::socket>> ws_;
    beast::flat_buffer buffer_;
};

class WssServer
{
public:
    WssServer(const net::ip::address &addr, unsigned short port) :
        ioc_(1),
        acceptor_(ioc_, tcp::endpoint {addr, port}),
        ssl_ctx_(ssl::context::tls_server)
    {
        load_server_certificate(ssl_ctx_);
    }

    void run_async()
    {
        do_accept();
        th_ = std::thread([this] {
            ioc_.run();
        });
    }

    void stop()
    {
        ioc_.stop();
        if (th_.joinable())
            th_.join();
    }

private:
    void do_accept()
    {
        acceptor_.async_accept(
            [this](beast::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<WssServerSession>(std::move(socket), ssl_ctx_)->run();
                }
                else {
                    std::cerr << "[Server] accept error: " << ec.message() << "\n";
                }
                do_accept();
            });
    }

private:
    net::io_context ioc_;
    tcp::acceptor acceptor_;
    ssl::context ssl_ctx_;
    std::thread th_;
};

#endif // _SERVER_H_
