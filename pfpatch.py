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
        self.backup_dir = Path("backups")
        self.backup_dir.mkdir(exist_ok=True)
        self.settings_file = Path("settings.yml")
        self.binary_paths = dict()

        self.setWindowTitle("Private Files Patcher")
        self.setMinimumSize(800, 600)

        self.init_ui()
        self.load_settings()
        self.load_defaults()

    def load_settings(self):
        """Load saved binary paths and config directory from settings file"""
        if self.settings_file.exists():
            try:
                with open(self.settings_file, "r") as f:
                    data = yaml.load(f, Loader=yaml.SafeLoader)
                    if data:
                        if "binary_paths" in data:
                            self.binary_paths = data["binary_paths"]
                        if "config_dir" in data:
                            self.config_dir = data["config_dir"]
                        else:
                            self.config_dir = None
            except Exception as e:
                print(f"Failed to load settings: {e}")
        else:
            self.config_dir = None

    def save_settings(self):
        """Save binary paths and config directory to settings file"""
        try:
            settings_data = {
                "binary_paths": self.binary_paths,
            }
            if hasattr(self, 'config_dir') and self.config_dir:
                settings_data["config_dir"] = self.config_dir
            
            with open(self.settings_file, "w") as f:
                yaml.dump(settings_data, f)
        except Exception as e:
            print(f"Failed to save settings: {e}")

    def load_defaults(self):
        # Load saved config directory or default to "patches"
        if hasattr(self, 'config_dir') and self.config_dir and Path(self.config_dir).exists():
            self.select_config_dir(self.config_dir)
        else:
            self.select_config_dir("patches")

    def get_backup_path(self, binary_name):
        """Generate backup file path for a binary"""
        return self.backup_dir / f"{binary_name}_backup.bin"

    def is_binary_patched(self, binary_name):
        """Check if binary has been patched (backup exists)"""
        backup_path = self.get_backup_path(binary_name)
        return backup_path.exists()

    def save_original_bytes(self, binary_name, patch):
        """Save original bytes before first patch"""
        # Only save if binary hasn't been patched before
        if self.is_binary_patched(binary_name):
            return
        
        backup_path = self.get_backup_path(binary_name)
        binary_path, binary = self.binary_files[binary_name]
        
        # Store original bytes for all changes in this patch
        original_data = []
        for change in patch["changes"]:
            addr = change["offset"] - binary.OPTIONAL_HEADER.ImageBase
            size = len(bytes.fromhex(change["value"]))
            original_bytes = binary.get_data(addr, size)
            original_data.append({
                "offset": change["offset"],
                "value": original_bytes.hex()
            })
        
        # Save to file
        with open(backup_path, "w") as f:
            yaml.dump(original_data, f)

    def restore_original_bytes(self, binary_name, patch):
        """Restore original bytes from backup"""
        backup_path = self.get_backup_path(binary_name)
        
        if not backup_path.exists():
            QMessageBox.warning(self, "Warning", "No backup found for restoration!")
            return False
        
        binary_path, binary = self.binary_files[binary_name]
        
        # Load original bytes
        with open(backup_path, "r") as f:
            original_data = yaml.load(f, Loader=yaml.SafeLoader)
        
        # Restore original bytes
        for change in original_data:
            addr = change["offset"] - binary.OPTIONAL_HEADER.ImageBase
            binary.set_bytes_at_rva(addr, bytes.fromhex(change["value"]))
        
        return True

    def apply_patches(self):
        try:
            modified_binaries = set()
            
            for patch_name, patch in self.patches.items():
                binary_name = patch["file"]
                
                # Check if binary is loaded
                if binary_name not in self.binary_files:
                    continue
                
                # Skip if patch widget is disabled
                if not patch["widget"].isEnabled():
                    continue
                
                binary_path, binary = self.binary_files[binary_name]
                
                if patch["editable"]:
                    try:
                        new_value_text = patch["widget"].text().strip()
                        if not new_value_text:
                            continue
                        
                        new_value_int = int(new_value_text)
                        change = patch["changes"][0]
                        size = int(change["size"])
                        new_value = new_value_int.to_bytes(size, byteorder='little')
                        
                        addr = change["offset"] - binary.OPTIONAL_HEADER.ImageBase
                        binary.set_bytes_at_rva(addr, new_value)
                        modified_binaries.add(binary_name)
                    except ValueError as e:
                        QMessageBox.warning(self, "Error", f"Invalid value in {patch_name}: {str(e)}")
                        continue
                else:
                    if patch["widget"].isChecked():
                        # Save original bytes before patching (only if not already patched)
                        self.save_original_bytes(binary_name, patch)
                        
                        # Apply patches
                        for change in patch["changes"]:
                            addr = change["offset"] - binary.OPTIONAL_HEADER.ImageBase
                            binary.set_bytes_at_rva(addr, bytes.fromhex(change["value"]))
                        modified_binaries.add(binary_name)
                    else:
                        # Restore original bytes
                        if self.restore_original_bytes(binary_name, patch):
                            modified_binaries.add(binary_name)
            
            # Write all modified binaries
            for binary_name in modified_binaries:
                binary_path, binary = self.binary_files[binary_name]
                binary.write(binary_path)
            
            if modified_binaries:
                QMessageBox.information(self, "Success", f"Patches applied to {len(modified_binaries)} binary(ies) successfully!")
            else:
                QMessageBox.information(self, "Info", "No changes to apply.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to apply patches: {str(e)}")

    def select_binary(self, name, result_object: QLineEdit, default=None):
        selected_file, _ = QFileDialog.getOpenFileName(
            self, f"Select {name} binary", filter=default or "All Files (*)"
        )

        if selected_file:
            try:
                self.binary_files[name] = (
                    selected_file,
                    pefile.PE(selected_file, fast_load=True),
                )
                result_object.setText(selected_file)
                
                # Save binary path to settings
                self.binary_paths[name] = selected_file
                self.save_settings()
                
                # Update patches UI if config is loaded
                if hasattr(self, 'config_data') and 'patches' in self.config_data:
                    self.update_patches_ui(self.config_data["patches"])
                
                # Enable patch button if at least one patch is available
                self.update_patch_button_state()
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load binary: {str(e)}")
                result_object.setText("<empty>")

    def update_patch_button_state(self):
        """Enable patch button if at least one patch has its binary loaded"""
        has_enabled_patch = False
        for patch in self.patches.values():
            if patch["widget"].isEnabled():
                has_enabled_patch = True
                break
        
        self.patch_btn.setEnabled(has_enabled_patch)

    def select_config_dir(self, value=None):
        selected_path = value or QFileDialog.getExistingDirectory(
            self, "Select config directory"
        )

        if selected_path:
            config_path = Path(selected_path)
            if not config_path.exists():
                return
            
            # Save the config directory to settings
            self.config_dir = str(config_path)
            self.save_settings()
            
            self.config_files_cbox.clear()
            self.clear_ui()
            
            config_files = list(config_path.glob("*.y?ml"))
            if not config_files:
                QMessageBox.warning(self, "Warning", "No config files found in directory!")
                return
            
            for config in config_files:
                self.config_files_cbox.addItem(config.stem, str(config))

    def clear_ui(self):
        self.patch_btn.setEnabled(False)
        self.clear_layout(self.patches_layout)
        self.patches.clear()
        self.clear_layout(self.files_layout)
        self.binary_files.clear()

    def config_changed(self, index):
        if index == -1:
            return

        config_path = Path(self.config_files_cbox.currentData())

        try:
            with open(config_path, "r") as f:
                self.config_data = yaml.load(f, Loader=yaml.SafeLoader)

            self.clear_ui()
            self.update_binary_ui(self.config_data["files"])
            
            # Show patches (disabled initially)
            self.update_patches_ui(self.config_data["patches"])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load config: {str(e)}")

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
            try:
                binary_name = patch["file"]
                
                patch_group = QGroupBox(patch.get("name", "Unnamed Patch"))

                patch_layout = QVBoxLayout()
                if "description" in patch:
                    desc_label = QLabel(patch["description"])
                    desc_label.setWordWrap(True)
                    desc_label.setStyleSheet("color: gray;")
                    patch_layout.addWidget(desc_label)

                # Check if the required binary is loaded
                binary_loaded = binary_name in self.binary_files
                
                if patch.get("editable", False):
                    value_widget = QLineEdit()
                    value_widget.setEnabled(binary_loaded)
                    
                    if binary_loaded:
                        _, binary = self.binary_files[binary_name]
                        if len(patch["changes"]) > 0:
                            change = patch["changes"][0]
                            addr = change["offset"] - binary.OPTIONAL_HEADER.ImageBase
                            size = int(change.get("size", 4))
                            current = int.from_bytes(
                                binary.get_data(addr, size),
                                byteorder='little'
                            )
                            value_widget.setText(str(current))
                    else:
                        value_widget.setPlaceholderText(f"Load {binary_name} first")
                    
                    patch_layout.addWidget(value_widget)
                    patch["widget"] = value_widget
                else:
                    value_widget = QCheckBox("Enable")
                    value_widget.setEnabled(binary_loaded)
                    
                    if binary_loaded:
                        _, binary = self.binary_files[binary_name]
                        # Check current state
                        all_match = True
                        for change in patch["changes"]:
                            addr = change["offset"] - binary.OPTIONAL_HEADER.ImageBase
                            desired = bytes.fromhex(change["value"])
                            current = binary.get_data(addr, len(desired))
                            if current != desired:
                                all_match = False
                                break
                        
                        if all_match:
                            value_widget.setChecked(True)
                    
                    patch_layout.addWidget(value_widget)
                    patch["widget"] = value_widget
                
                # Add status label showing if binary is loaded
                if not binary_loaded:
                    status_label = QLabel(f"⚠ Requires binary: {binary_name}")
                    status_label.setStyleSheet("color: orange;")
                    patch_layout.addWidget(status_label)

                patch_group.setLayout(patch_layout)
                self.patches_layout.addWidget(patch_group)
                self.patches[patch.get("name", f"patch_{len(self.patches)}")] = patch
            except Exception as e:
                print(f"Error processing patch: {str(e)}")
                continue
        
        self.patches_layout.addStretch()
        self.update_patch_button_state()

    def update_binary_ui(self, data):
        self.clear_layout(self.files_layout)
        self.binary_files.clear()

        for binary_name, binary_data in data.items():
            patch_group = QGroupBox(binary_name)
            patch_layout = QHBoxLayout()

            file_txt = QLineEdit()
            file_txt.setEnabled(False)
            
            # Try to load saved path
            if binary_name in self.binary_paths:
                saved_path = self.binary_paths[binary_name]
                if Path(saved_path).exists():
                    try:
                        self.binary_files[binary_name] = (
                            saved_path,
                            pefile.PE(saved_path, fast_load=True),
                        )
                        file_txt.setText(saved_path)
                    except Exception as e:
                        print(f"Failed to load saved binary: {e}")
                        file_txt.setText("<empty>")
                else:
                    file_txt.setText("<empty>")
            else:
                file_txt.setText("<empty>")
            
            file_btn = QPushButton("Select")
            
            # Fix lambda capture issue
            def make_select_handler(name, txt, default_filter):
                return lambda: self.select_binary(name, txt, default_filter)
            
            file_btn.clicked.connect(
                make_select_handler(
                    binary_name,
                    file_txt,
                    binary_data.get("default", None)
                )
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