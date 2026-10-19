#pragma once

// Preview of the changes before saving: line-by-line diff
// of each file (removed lines in red, added lines in green).

#include "document.hpp"

#include <QDialog>

#include <vector>

namespace tlsrelay::admin {

class DiffDialog : public QDialog {
    Q_OBJECT

public:
    DiffDialog(const std::vector<FileChange>& changes, QWidget* parent = nullptr);

    // HTML text of the preview (tests).
    static QString render(const std::vector<FileChange>& changes);
};

}  // namespace tlsrelay::admin
