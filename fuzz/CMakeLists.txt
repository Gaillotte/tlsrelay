# Cibles de fuzzing libFuzzer (PLAN §5) : clang uniquement, avec
# TLSRELAY_SANITIZERS contenant fuzzer-no-link (préréglage linux-fuzz).
set(TLSRELAY_FUZZ_TARGETS frame config whitelist csr dn admin)
foreach(name IN LISTS TLSRELAY_FUZZ_TARGETS)
    add_executable(fuzz_${name} fuzz_${name}.cpp)
    target_link_libraries(fuzz_${name} PRIVATE tlsrelay::core tlsrelay::options)
    target_compile_options(fuzz_${name} PRIVATE -fsanitize=fuzzer)
    target_link_options(fuzz_${name} PRIVATE -fsanitize=fuzzer)
endforeach()
