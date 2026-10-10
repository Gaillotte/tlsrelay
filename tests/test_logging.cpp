#include "tlsrelay/logging.hpp"

#include <spdlog/sinks/ostream_sink.h>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>

using namespace tlsrelay;

TEST(JsonEscape, EscapesSpecialCharacters) {
    EXPECT_EQ(logging::json_escape("simple"), "simple");
    EXPECT_EQ(logging::json_escape("a\"b\\c"), "a\\\"b\\\\c");
    EXPECT_EQ(logging::json_escape("l1\nl2\r\t"), "l1\\nl2\\r\\t");
    EXPECT_EQ(logging::json_escape(std::string("\x01", 1)), "\\u0001");
    EXPECT_EQ(logging::json_escape("é"), "é");  // UTF-8 conservé tel quel
}

TEST(JsonFormatter, WritesOneObjectPerLine) {
    std::ostringstream out;
    auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(out);
    sink->set_formatter(logging::make_json_formatter());
    spdlog::logger logger("activity", sink);
    logger.info("canal={} \"ouvert\"", 7);

    const auto line = out.str();
    EXPECT_EQ(line.back(), '\n');
    EXPECT_EQ(line.find('\n'), line.size() - 1);
    EXPECT_NE(line.find("\"level\":\"info\""), std::string::npos) << line;
    EXPECT_NE(line.find("\"cat\":\"activity\""), std::string::npos) << line;
    EXPECT_NE(line.find("\"msg\":\"canal=7 \\\"ouvert\\\"\""), std::string::npos) << line;
    EXPECT_NE(line.find("Z\""), std::string::npos) << line;  // horodatage UTC
}

TEST(Logging, CliLevelOverridesCategories) {
    LogConfig cfg;
    cfg.level = LogLevel::info;
    cfg.activity = LogLevel::error;
    logging::init(cfg, LogLevel::trace);
    EXPECT_EQ(logging::activity().level(), spdlog::level::trace);
    EXPECT_EQ(logging::config().level(), spdlog::level::trace);

    logging::init(cfg);
    EXPECT_EQ(logging::activity().level(), spdlog::level::err);
    EXPECT_EQ(logging::config().level(), spdlog::level::info);

    logging::set_level(logging::Category::config, LogLevel::debug);
    EXPECT_EQ(logging::config().level(), spdlog::level::debug);
    logging::init_default();
}

TEST(Logging, UnwritableFileIsReported) {
    // Le « répertoire » parent est un fichier : l'ouverture échoue sur tout OS.
    const auto blocker = std::filesystem::temp_directory_path() / "tlsrelay-test-blocker";
    { std::ofstream(blocker) << "x"; }
    LogConfig cfg;
    cfg.output = (blocker / "sub" / "tlsrelay.log").string();
    EXPECT_THROW(logging::init(cfg), std::runtime_error);
    logging::init_default();
    std::filesystem::remove(blocker);
}

TEST(Logging, WritesToFile) {
    const auto path = std::filesystem::temp_directory_path() / "tlsrelay-test.log";
    std::filesystem::remove(path);
    LogConfig cfg;
    cfg.output = path.string();
    logging::init(cfg);
    logging::config().info("message de test");
    logging::init_default();  // libère le fichier

    std::ifstream in(path);
    std::stringstream content;
    content << in.rdbuf();
    EXPECT_NE(content.str().find("[config] message de test"), std::string::npos) << content.str();
    in.close();
    std::filesystem::remove(path);
}
