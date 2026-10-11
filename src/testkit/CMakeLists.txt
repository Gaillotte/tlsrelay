add_executable(tlsrelay-testkit main.cpp traffic.cpp proxy.cpp pki.cpp)
target_link_libraries(tlsrelay-testkit PRIVATE tlsrelay::core tlsrelay::options CLI11::CLI11)
install(TARGETS tlsrelay-testkit RUNTIME DESTINATION bin)
