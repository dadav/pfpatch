import sys
import yaml
import pefile
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGroupBox,
    QPushButton,
    QComboBox,
    QScrollArea,
    QFileDialog,
    QLineEdit,
    QLabel,
    QSizePolicy,
    QMessageBox,
)
from pathlib import Path


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.binary_files = dict()
        self.patches = dict()

        self.setWindowTitle("Private Files Patcher")
        self.setMinimumSize(800, 600)

        self.init_ui()
        self.load_defaults()

    def load_defaults(self):
        self.select_config_dir("patches")

    def apply_patches(self):
        for patch in self.patches.values():
            binary_path, binary = self.binary_files[patch["file"]]
            if patch["editable"]:
                new_value = int(patch["widget"].text()).to_bytes()
                addr = patch["changes"][0]["offset"] - binary.OPTIONAL_HEADER.ImageBase
                binary.set_bytes_at_rva(addr, new_value)
            else:
                if patch["widget"].isChecked():
                    for change in patch["changes"]:
                        addr = change["offset"] - binary.OPTIONAL_HEADER.ImageBase
                        binary.set_bytes_at_rva(addr, bytes.fromhex(change["value"]))

            binary.write(binary_path)
            QMessageBox.information(self, "Success", "Patches applied to binary!")

    def select_binary(self, name, result_object: QLineEdit, default=None):
        selected_file, _ = QFileDialog.getOpenFileName(
            self, f"Select {name} binary", initialFilter=default
        )

        if selected_file:
            self.binary_files[name] = (
                selected_file,
                pefile.PE(selected_file, fast_load=True),
            )
            result_object.setText(selected_file)
            self.update_patches_ui(self.config_data["patches"])
            self.select_first_warning_widget.setVisible(False)

    def select_config_dir(self, value=None):
        selected_path = value or QFileDialog.getExistingDirectory(
            self, "Select config directory"
        )

        if selected_path:
            self.config_files_cbox.clear()
            self.clear_ui()
            for config in list(Path(selected_path).glob("*.y?ml")):
                self.config_files_cbox.addItem(config.stem, str(config))

    def clear_ui(self):
        self.patch_btn.setEnabled(False)
        self.clear_layout(self.patches_layout)
        self.patches.clear()
        self.clear_layout(self.files_layout)
        self.binary_files.clear()
        self.select_first_warning_widget = QLabel("Select a binary first...")
        self.patches_layout.addWidget(self.select_first_warning_widget)

    def config_changed(self, index):
        if index == -1:
            return

        config_path = Path(self.config_files_cbox.currentData())

        with open(config_path, "r") as f:
            self.config_data = yaml.load(f, Loader=yaml.SafeLoader)

        self.clear_ui()
        self.update_binary_ui(self.config_data["files"])

    def clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)

            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                self.clear_layout(item.layout())

    def update_patches_ui(self, patches):
        self.clear_layout(self.patches_layout)
        self.patches.clear()
        for patch in patches:
            patch_group = QGroupBox(patch.get("name", "Unnamed Patch"))

            patch_layout = QVBoxLayout()
            if "description" in patch:
                desc_label = QLabel(patch["description"])
                desc_label.setWordWrap(True)
                desc_label.setStyleSheet("color: gray;")
                patch_layout.addWidget(desc_label)

            _, binary = self.binary_files[patch["file"]]
            if patch["editable"]:
                value_widget = QLineEdit()
                patch_layout.addWidget(value_widget)
                assert len(patch["changes"]) == 1

                change = patch["changes"][0]
                addr = change["offset"] - binary.OPTIONAL_HEADER.ImageBase
                current = int.from_bytes(binary.get_data(addr, int(change["size"])))
                value_widget.setText(str(current))
                patch["widget"] = value_widget
            else:
                value_widget = QCheckBox("Enable")
                patch_layout.addWidget(value_widget)
                for change in patch["changes"]:
                    addr = change["offset"] - binary.OPTIONAL_HEADER.ImageBase
                    desired = bytes.fromhex(change["value"])
                    current = binary.get_data(addr, len(desired))
                    if current != desired:
                        break
                else:
                    value_widget.setChecked(True)
                patch["widget"] = value_widget

            patch_group.setLayout(patch_layout)
            self.patches_layout.addWidget(patch_group)
            self.patches[patch.get("name", f"patch_{len(self.patches)}")] = patch
        self.patches_layout.addStretch()
        if len(self.patches) > 0:
            self.patch_btn.setEnabled(True)

    def update_binary_ui(self, data):
        self.clear_layout(self.files_layout)
        self.binary_files.clear()

        for binary_name, binary_data in data.items():
            patch_group = QGroupBox(binary_name)
            patch_layout = QHBoxLayout()

            file_txt = QLineEdit()
            file_txt.setText("<empty>")
            file_txt.setEnabled(False)
            file_btn = QPushButton("Select")
            file_btn.clicked.connect(
                lambda _,
                nn=binary_name,
                ff=file_txt,
                dd=binary_data.get("default", None): self.select_binary(nn, ff, dd)
            )

            patch_layout.addWidget(file_txt)
            patch_layout.addWidget(file_btn)

            patch_group.setLayout(patch_layout)
            self.files_layout.addWidget(patch_group)

        self.files_layout.addStretch()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        self.setWindowTitle("pfpatch")

        main_layout = QVBoxLayout(central_widget)

        # -----------------------------------------
        config_group = QGroupBox("Config")
        config_layout = QVBoxLayout()

        self.config_files_cbox = QComboBox()
        self.config_files_cbox.currentIndexChanged.connect(self.config_changed)

        select_config_dir_btn = QPushButton("Change directory")
        select_config_dir_btn.clicked.connect(self.select_config_dir)

        config_layout.addWidget(self.config_files_cbox)
        config_layout.addWidget(select_config_dir_btn)
        config_group.setLayout(config_layout)
        # -----------------------------------------
        files_group = QGroupBox("Files")
        files_layout = QVBoxLayout()
        files_scroll = QScrollArea()
        files_scroll.setWidgetResizable(True)
        files_scroll.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum
        )
        self.files_widget = QWidget()
        self.files_layout = QVBoxLayout(self.files_widget)
        files_scroll.setWidget(self.files_widget)
        files_layout.addWidget(files_scroll)
        files_group.setLayout(files_layout)
        # -----------------------------------------
        patches_group = QGroupBox("Patches")
        patches_layout = QVBoxLayout()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self.patches_widget = QWidget()
        self.patches_layout = QVBoxLayout(self.patches_widget)
        self.select_first_warning_widget = QLabel("Select a binary first...")
        self.patches_layout.addWidget(self.select_first_warning_widget)
        scroll.setWidget(self.patches_widget)
        patches_layout.addWidget(scroll)
        patches_group.setLayout(patches_layout)
        # -----------------------------------------
        #
        self.patch_btn = QPushButton("Patch")
        self.patch_btn.clicked.connect(self.apply_patches)
        self.patch_btn.setEnabled(False)

        main_layout.addWidget(config_group)
        main_layout.addWidget(files_group)
        main_layout.addWidget(patches_group)
        main_layout.addWidget(self.patch_btn)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
