#pragma once

// Choice of the contents of a deployment package (deployment.hpp).

#include "deployment.hpp"

#include <QDialog>

class QComboBox;
class QLabel;
class QLineEdit;

namespace tlsrelay::admin {

class ExportDialog : public QDialog {
    Q_OBJECT

public:
    // request: configuration and texts to export; the dialog fills in
    // the output directory, the platform, the kit and the CRLs.
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
