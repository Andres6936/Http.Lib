ADD_EXECUTABLE(Example.Client client.cc)
TARGET_LINK_LIBRARIES(Example.Client PRIVATE Httplib)

ADD_EXECUTABLE(Example.Server server.cc)
TARGET_LINK_LIBRARIES(Example.Server PRIVATE Httplib)