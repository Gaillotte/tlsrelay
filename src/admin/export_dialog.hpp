#pragma once

// Choix des éléments d'un paquet de déploiement (deployment.hpp).

#include "deployment.hpp"

#include <QDialog>

class QComboBox;
class QLabel;
class QLineEdit;

namespace tlsrelay::admin {

class ExportDialog : public QDialog {
    Q_OBJECT

public:
    // request : configuration et textes à exporter ; le dialogue complète
    // le répertoire de sortie, la plateforme, le kit et les CRL.
    ExportDialog(ExportRequest request, QWidget* parent = nullptr);

    const ExportRequest& request() const { return request_; }

private:
    void refresh();

    ExportRequest request_;
    QLineEdit* out_;
    QComboBox* platform_;
    QLineEdit* kit_;
    QLineEdit* crl_;
    QLabel* warnings_;
};

}  // namespace tlsrelay::admin
