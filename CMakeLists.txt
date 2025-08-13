cmake_minimum_required(VERSION 3.10)

project(boost-wss-ssl-project VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CLIENT_SRC
    client.cc
)

set(SERVER_SRC
    server.cc
)

include_directories(${Boost_INCLUDE_DIRS})

link_libraries(${Boost_LIBRARIES})

add_executable(server ${SERVER_SRC})

add_executable(client ${CLIENT_SRC})
