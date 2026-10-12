#pragma once

// Aperçu des modifications avant enregistrement : différences ligne à ligne
// de chaque fichier (lignes retirées en rouge, ajoutées en vert).

#include "document.hpp"

#include <QDialog>

#include <vector>

namespace tlsrelay::admin {

class DiffDialog : public QDialog {
    Q_OBJECT

public:
    DiffDialog(const std::vector<FileChange>& changes, QWidget* parent = nullptr);

    // Texte HTML de l'aperçu (tests).
    static QString render(const std::vector<FileChange>& changes);
};

}  // namespace tlsrelay::admin
