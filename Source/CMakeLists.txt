ADD_LIBRARY(Httplib STATIC
        BufferStream.cpp
        Client.cpp
        ClientImpl.cpp
        Request.cpp
        Response.cpp
        Result.cpp
        Server.cpp
        SocketStream.cpp
        SSLClient.cpp
        SSLServer.cpp
        Stream.cpp
        )
TARGET_INCLUDE_DIRECTORIES(Httplib PUBLIC $<BUILD_INTERFACE:${HTTPLIB_ROOT_DIR}/Include>)
SET_TARGET_PROPERTIES(Httplib PROPERTIES CXX_STANDARD 17)