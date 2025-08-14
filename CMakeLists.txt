cmake_minimum_required(VERSION 3.10)

project(boost-wss-ssl-project VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SRC
    main.cc
)

find_package(OpenSSL REQUIRED)

include_directories(${Boost_INCLUDE_DIRS})

link_libraries(${Boost_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)

add_executable(${PROJECT_NAME} ${SRC})
