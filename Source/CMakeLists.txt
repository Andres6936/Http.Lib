ADD_LIBRARY(Httplib STATIC
        SSL/Client.cpp
        SSL/Server.cpp
        SSL/SocketStream.cpp
        BufferStream.cpp
        Client.cpp
        ClientImpl.cpp
        Request.cpp
        Response.cpp
        Result.cpp
        Server.cpp
        SocketStream.cpp
        Stream.cpp
        )
TARGET_INCLUDE_DIRECTORIES(Httplib PUBLIC $<BUILD_INTERFACE:${HTTPLIB_ROOT_DIR}/Include>)
SET_TARGET_PROPERTIES(Httplib PROPERTIES CXX_STANDARD 17)


FIND_PACKAGE(Threads REQUIRED)
TARGET_LINK_LIBRARIES(Httplib PUBLIC Threads::Threads)