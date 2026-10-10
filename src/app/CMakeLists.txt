add_executable(tlsrelay main.cpp)
target_link_libraries(tlsrelay PRIVATE tlsrelay::core tlsrelay::options CLI11::CLI11)

install(TARGETS tlsrelay RUNTIME DESTINATION bin)
