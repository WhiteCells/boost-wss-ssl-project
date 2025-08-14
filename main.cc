#include "server.h"
#include "client.h"

int main()
{
    try {
        // 启动 WSS Server
        const auto address = net::ip::make_address("127.0.0.1");
        const unsigned short port = 8443;
        WssServer server(address, port);
        server.run_async();
        std::cout << "[Main] WSS server listening on wss://127.0.0.1:" << port << "/ws\n";

        // 稍等服务器起来
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        // 启动 WSS Client
        net::io_context ioc;
        ssl::context sslctx(ssl::context::tls_client);

        // 不校验证书
        // sslctx.set_verify_mode(ssl::verify_none);

        // 校验证书
        sslctx.set_verify_mode(ssl::verify_peer);
        sslctx.load_verify_file("server.crt"); // CA 证书

        auto client = std::make_shared<WssClient>(ioc, sslctx, "127.0.0.1", std::to_string(port), "/ws");
        client->run();

        ioc.run();

        server.stop();
    }
    catch (const std::exception &e) {
        std::cerr << "Fatal: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
