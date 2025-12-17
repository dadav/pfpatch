import sys
import yaml
import pefile
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from pydantic import BaseModel, Field, field_validator

__version__ = "0.1.0"

from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
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


class PatchChange(BaseModel):
    """Represents a single byte change in a patch"""

    file: Optional[str] = None
    offset: int
    value: Optional[str] = None
    size: Optional[int] = None
    formula: Optional[str] = (
        None  # Formula/expression for editable patches (e.g., "value * 0x10", "value + 5")
    )

    @field_validator("value")
    @classmethod
    def validate_hex_value(cls, v: Optional[str]) -> Optional[str]:
        """Ensure value is valid hex"""
        if v is None:
            return v
        try:
            bytes.fromhex(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid hex value: {v}")

    @field_validator("formula")
    @classmethod
    def validate_formula(cls, v: Optional[str]) -> Optional[str]:
        """Validate formula syntax (basic check)"""
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        # Basic syntax check - must contain 'value' variable
        if "value" not in v:
            raise ValueError("Formula must contain 'value' variable")
        return v


class Patch(BaseModel):
    """Represents a patch configuration"""

    name: str
    file: Optional[str] = None
    description: Optional[str] = None
    editable: bool = False
    changes: List[PatchChange]
    widget: Optional[Any] = None

    @field_validator("changes")
    @classmethod
    def validate_changes(cls, v: List[PatchChange], info) -> List[PatchChange]:
        """Validate changes based on patch type"""
        if not v:
            raise ValueError("Patch must have at least one change")

        default_binary = info.data.get("file")

        # Ensure each change has a binary target (either own file or default)
        for i, change in enumerate(v):
            target_binary = change.file or default_binary
            if target_binary is None:
                raise ValueError(
                    f"Change {i} must specify a file when patch has no default file"
                )

        # If editable, all changes must have size specified
        if info.data.get("editable", False):
            sizes = []
            for i, change in enumerate(v):
                if change.size is None:
                    raise ValueError(f"Editable patch change {i} must specify size")
                sizes.append(change.size)

            # All changes should have the same size for consistency
            if len(set(sizes)) > 1:
                raise ValueError(
                    "All changes in an editable patch must have the same size"
                )
        else:
            for i, change in enumerate(v):
                if change.value is None:
                    raise ValueError(
                        f"Change {i} must have a value for non-editable patches"
                    )

        return v


class BinaryFile(BaseModel):
    """Represents a binary file configuration"""

    default: Optional[str] = None


class Config(BaseModel):
    """Represents the complete configuration"""

    files: Dict[str, BinaryFile]
    patches: List[Patch]

    @field_validator("patches")
    @classmethod
    def validate_patch_files(cls, v: List[Patch], info) -> List[Patch]:
        """Ensure all patches reference valid files"""
        if "files" not in info.data:
            return v

        file_names = set(info.data["files"].keys())
        for patch in v:
            if patch.file and patch.file not in file_names:
                raise ValueError(
                    f"Patch '{patch.name}' references unknown file '{patch.file}'"
                )
            for change in patch.changes:
                target_file = change.file or patch.file
                if target_file is None:
                    raise ValueError(
                        f"Patch '{patch.name}' has change without a file target"
                    )
                if target_file not in file_names:
                    raise ValueError(
                        f"Patch '{patch.name}' references unknown file '{target_file}'"
                    )

        return v


class Settings(BaseModel):
    """Represents saved settings"""

    binary_paths: Dict[str, str] = Field(default_factory=dict)
    config_dir: Optional[str] = None


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()

        self.binary_files: Dict[str, Tuple[str, pefile.PE]] = {}
        self.saved_binary_paths: Dict[str, str] = {}
        self.patches: Dict[str, Patch] = {}
        self.config_dir: Optional[str] = None

        # Set backup directory - use executable directory for onefile, or current dir for script
        if getattr(sys, "frozen", False):
            # Running as compiled executable - use directory where exe is located
            self.backup_dir = Path(sys.executable).parent / "backups"
        else:
            # Running as script - use current directory
            self.backup_dir = Path("backups")
        self.backup_dir.mkdir(exist_ok=True)

        # Set settings file location - same logic as backup dir
        if getattr(sys, "frozen", False):
            self.settings_file = Path(sys.executable).parent / "settings.yml"
        else:
            self.settings_file = Path("settings.yml")

        self.current_config: Optional[Config] = None

        self.setWindowTitle(f"Private Files Patcher v{__version__}")
        self.setMinimumSize(800, 600)

        self.init_ui()
        self.load_settings()
        self.load_defaults()

    def _get_resource_path(self, relative_path: str) -> Path:
        """Get resource path that works with PyInstaller onefile mode"""
        if getattr(sys, "frozen", False):
            # Running as compiled executable (PyInstaller)
            base_path = Path(sys._MEIPASS)
        else:
            # Running as script
            base_path = Path(__file__).parent

        return base_path / relative_path

    def _offset_to_rva(self, offset: int, binary: pefile.PE) -> int:
        """Convert virtual address offset to RVA (Relative Virtual Address)"""
        return offset - binary.OPTIONAL_HEADER.ImageBase

    def _evaluate_formula(self, formula: Optional[str], value: int) -> int:
        """Safely evaluate a formula expression with the given value

        Supports standard Python math operations: +, -, *, /, //, %, **
        Supports bitwise operations: &, |, ^, <<, >>
        Supports functions: abs, min, max, pow, round
        Supports hex literals: 0x10, 0xFF, etc.
        """
        if formula is None or not formula.strip():
            return value

        # Create a safe evaluation context
        # Only allow specific builtins and math operations
        safe_builtins = {
            "abs": abs,
            "min": min,
            "max": max,
            "pow": pow,
            "round": round,
            "int": int,
            "float": float,
        }

        safe_dict = {
            "value": value,
            "__builtins__": safe_builtins,
        }

        try:
            # Compile and evaluate the expression
            # This allows standard Python operators (+, -, *, /, etc.)
            code = compile(formula, "<formula>", "eval")
            result = eval(code, safe_dict, {})

            if not isinstance(result, (int, float)):
                raise ValueError(
                    f"Formula must evaluate to a number, got {type(result)}"
                )
            return int(result)
        except NameError as e:
            raise ValueError(f"Invalid variable in formula: {e}")
        except SyntaxError as e:
            raise ValueError(f"Invalid formula syntax: {e}")
        except ZeroDivisionError as e:
            raise ValueError(f"Division by zero in formula: {e}")
        except Exception as e:
            raise ValueError(f"Error evaluating formula '{formula}': {e}")

    def _get_change_binary(
        self, change: PatchChange, default_binary: Optional[str]
    ) -> str:
        """Resolve which binary a change targets"""
        binary_name = change.file or default_binary
        if binary_name is None:
            raise ValueError("Change does not specify a target binary")
        return binary_name

    def _group_changes_by_binary(self, patch: Patch) -> Dict[str, List[PatchChange]]:
        """Group patch changes by their target binary"""
        grouped: Dict[str, List[PatchChange]] = {}
        for change in patch.changes:
            binary_name = self._get_change_binary(change, patch.file)
            grouped.setdefault(binary_name, []).append(change)
        return grouped

    def _get_patch_required_binaries(self, patch: Patch) -> List[str]:
        """Return list of binaries a patch touches"""
        return sorted(self._group_changes_by_binary(patch).keys())

    def _close_binary(self, binary_name: str) -> None:
        """Close and remove a binary file from memory"""
        if binary_name in self.binary_files:
            _, binary = self.binary_files[binary_name]
            try:
                binary.close()
            except Exception:
                pass  # Ignore errors when closing
            del self.binary_files[binary_name]

    def load_settings(self) -> None:
        """Load saved binary paths and config directory from settings file"""
        if self.settings_file.exists():
            try:
                with open(self.settings_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data:
                        settings = Settings(**data)
                        self.saved_binary_paths = settings.binary_paths or {}
                        self.config_dir = settings.config_dir
                    else:
                        self.config_dir = None
            except (yaml.YAMLError, ValueError, KeyError) as e:
                QMessageBox.warning(self, "Warning", f"Failed to load settings: {e}")
                self.config_dir = None
            except Exception as e:
                QMessageBox.warning(
                    self, "Warning", f"Unexpected error loading settings: {e}"
                )
                self.config_dir = None
        else:
            self.config_dir = None

    def save_settings(self) -> None:
        """Save binary paths and config directory to settings file"""
        try:
            # Extract paths from binary_files
            binary_paths = {name: path for name, (path, _) in self.binary_files.items()}
            # Merge with saved_binary_paths to preserve paths that aren't currently loaded
            binary_paths = {**self.saved_binary_paths, **binary_paths}

            settings = Settings(
                binary_paths=binary_paths,
                config_dir=self.config_dir,
            )

            with open(self.settings_file, "w", encoding="utf-8") as f:
                yaml.dump(
                    settings.model_dump(exclude_none=True), f, default_flow_style=False
                )

            # Update saved_binary_paths to match what we just saved
            self.saved_binary_paths = binary_paths
        except (IOError, OSError, yaml.YAMLError) as e:
            QMessageBox.warning(self, "Warning", f"Failed to save settings: {e}")
        except Exception as e:
            QMessageBox.warning(
                self, "Warning", f"Unexpected error saving settings: {e}"
            )

    def load_defaults(self) -> None:
        """Load default configuration directory"""
        if self.config_dir and Path(self.config_dir).exists():
            self.select_config_dir(self.config_dir)
        else:
            # Try resource path first (for PyInstaller), then current directory
            default_path = self._get_resource_path("patches")
            if not default_path.exists():
                # Fallback to current directory
                default_path = Path("patches")

            if default_path.exists():
                self.select_config_dir(str(default_path))

    def get_backup_path(self, binary_name: str) -> Path:
        """Generate backup file path for a binary"""
        return self.backup_dir / f"{binary_name}_backup.yaml"

    def is_binary_patched(self, binary_name: str) -> bool:
        """Check if binary has been patched (backup exists)"""
        backup_path = self.get_backup_path(binary_name)
        return backup_path.exists()

    def save_original_bytes(
        self, binary_name: str, changes: List[PatchChange]
    ) -> None:
        """Save original bytes before first patch"""
        # Only save if binary hasn't been patched before
        if self.is_binary_patched(binary_name):
            return

        backup_path = self.get_backup_path(binary_name)
        _, binary = self.binary_files[binary_name]

        original_data = []
        for change in changes:
            addr = self._offset_to_rva(change.offset, binary)
            size = (
                len(bytes.fromhex(change.value))
                if change.value is not None
                else change.size
            )
            if size is None:
                continue
            try:
                original_bytes = binary.get_data(addr, size)
                original_data.append(
                    {"offset": change.offset, "value": original_bytes.hex()}
                )
            except Exception as e:
                QMessageBox.warning(
                    self,
                    "Warning",
                    f"Failed to read original bytes at offset {change.offset:#x}: {e}",
                )
                return

        try:
            with open(backup_path, "w", encoding="utf-8") as f:
                yaml.dump(original_data, f, default_flow_style=False)
        except (IOError, OSError, yaml.YAMLError) as e:
            QMessageBox.warning(self, "Warning", f"Failed to save backup: {e}")

    def restore_original_bytes(self, binary_name: str) -> bool:
        """Restore original bytes from backup"""
        backup_path = self.get_backup_path(binary_name)

        if not backup_path.exists():
            QMessageBox.warning(
                self, "Warning", "No backup found for reversing the patch!"
            )
            return False

        _, binary = self.binary_files[binary_name]

        try:
            # Load original bytes
            with open(backup_path, "r", encoding="utf-8") as f:
                original_data = yaml.safe_load(f)

            if not original_data:
                QMessageBox.warning(self, "Warning", "Backup file is empty!")
                return False

            # Restore original bytes
            for change in original_data:
                addr = self._offset_to_rva(change["offset"], binary)
                binary.set_bytes_at_rva(addr, bytes.fromhex(change["value"]))

            return True
        except (IOError, OSError, yaml.YAMLError, KeyError, ValueError) as e:
            QMessageBox.warning(self, "Warning", f"Failed to restore backup: {e}")
            return False

    def apply_patches(self) -> None:
        """Apply all enabled patches to their respective binaries"""
        try:
            modified_binaries = set()

            for patch_name, patch in self.patches.items():
                try:
                    changes_by_binary = self._group_changes_by_binary(patch)
                except ValueError as e:
                    QMessageBox.warning(self, "Error", f"Invalid patch '{patch_name}': {e}")
                    continue

                required_binaries = set(changes_by_binary.keys())

                # Check if all binaries are loaded
                if any(b not in self.binary_files for b in required_binaries):
                    continue

                # Skip if patch widget is disabled
                if not patch.widget.isEnabled():
                    continue

                if patch.editable:
                    try:
                        new_value_text = patch.widget.text().strip()
                        if not new_value_text:
                            # If empty, try to restore original if backup exists
                            for binary_name in required_binaries:
                                if self.is_binary_patched(binary_name):
                                    if self.restore_original_bytes(binary_name):
                                        modified_binaries.add(binary_name)
                            continue

                        new_value_int = int(new_value_text)
                        # Get size from first change (all should have same size per validation)
                        if not patch.changes or patch.changes[0].size is None:
                            QMessageBox.warning(
                                self,
                                "Error",
                                f"Patch {patch_name} has no size specified",
                            )
                            continue
                        size = patch.changes[0].size

                        # Apply value to all changes (with formulas if specified)
                        success = True
                        for binary_name, changes in changes_by_binary.items():
                            _, binary = self.binary_files[binary_name]
                            for change in changes:
                                if change.size != size:
                                    QMessageBox.warning(
                                        self,
                                        "Error",
                                        f"Patch {patch_name} has inconsistent sizes",
                                    )
                                    success = False
                                    break

                                # Calculate final value using formula if specified, otherwise use value as-is
                                try:
                                    final_value_int = self._evaluate_formula(
                                        change.formula, new_value_int
                                    )
                                except ValueError as e:
                                    QMessageBox.warning(
                                        self,
                                        "Error",
                                        f"Invalid formula at offset {change.offset:#x}: {e}",
                                    )
                                    success = False
                                    break

                                # Check for overflow based on size
                                max_value = (1 << (size * 8)) - 1
                                if final_value_int > max_value:
                                    QMessageBox.warning(
                                        self,
                                        "Error",
                                        f"Value {final_value_int} exceeds maximum for {size} byte(s) at offset {change.offset:#x}",
                                    )
                                    success = False
                                    break
                                if final_value_int < 0:
                                    QMessageBox.warning(
                                        self,
                                        "Error",
                                        f"Value {final_value_int} is negative at offset {change.offset:#x}",
                                    )
                                    success = False
                                    break

                                try:
                                    final_value = final_value_int.to_bytes(
                                        size, byteorder="little"
                                    )
                                    addr = self._offset_to_rva(change.offset, binary)
                                    binary.set_bytes_at_rva(addr, final_value)
                                except Exception as e:
                                    QMessageBox.warning(
                                        self,
                                        "Error",
                                        f"Failed to apply patch at offset {change.offset:#x}: {e}",
                                    )
                                    success = False
                                    break
                            if not success:
                                break

                        if success:
                            modified_binaries.update(required_binaries)
                    except ValueError as e:
                        QMessageBox.warning(
                            self, "Error", f"Invalid value in {patch_name}: {str(e)}"
                        )
                        continue
                    except Exception as e:
                        QMessageBox.warning(
                            self,
                            "Error",
                            f"Failed to apply patch {patch_name}: {str(e)}",
                        )
                        continue
                else:
                    if patch.widget.isChecked():
                        for binary_name, changes in changes_by_binary.items():
                            self.save_original_bytes(binary_name, changes)

                            _, binary = self.binary_files[binary_name]
                            for change in changes:
                                if change.value is None:
                                    continue
                                addr = self._offset_to_rva(change.offset, binary)
                                binary.set_bytes_at_rva(addr, bytes.fromhex(change.value))
                            modified_binaries.add(binary_name)
                    else:
                        for binary_name in required_binaries:
                            if self.restore_original_bytes(binary_name):
                                modified_binaries.add(binary_name)

            # Write all modified binaries
            for binary_name in modified_binaries:
                binary_path, binary = self.binary_files[binary_name]
                try:
                    binary.write(binary_path)
                except (IOError, OSError, pefile.PEFormatError) as e:
                    QMessageBox.critical(
                        self, "Error", f"Failed to write binary {binary_name}: {e}"
                    )
                    return

            if modified_binaries:
                QMessageBox.information(
                    self,
                    "Success",
                    f"Patches applied to {len(modified_binaries)} binary(ies) successfully!",
                )
            else:
                QMessageBox.information(self, "Info", "No changes to apply.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to apply patches: {e}")

    def select_binary(
        self, name: str, result_object: QLineEdit, default: Optional[str] = None
    ) -> None:
        """Select and load a binary file"""
        selected_file, _ = QFileDialog.getOpenFileName(
            self,
            f"Select {name} binary",
            filter=f"Default ({default if default else name});;All Files (*)",
        )

        if selected_file:
            # Close existing binary if any
            self._close_binary(name)

            try:
                binary = pefile.PE(selected_file, fast_load=True)
                self.binary_files[name] = (selected_file, binary)
                result_object.setText(selected_file)

                self.save_settings()
                if self.current_config:
                    self.update_patches_ui(self.current_config.patches)
                self.update_patch_button_state()

            except pefile.PEFormatError as e:
                QMessageBox.critical(self, "Error", f"Invalid PE file format: {str(e)}")
                result_object.setText("<empty>")
            except (IOError, OSError) as e:
                QMessageBox.critical(self, "Error", f"Failed to open file: {str(e)}")
                result_object.setText("<empty>")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load binary: {str(e)}")
                result_object.setText("<empty>")

    def update_patch_button_state(self) -> None:
        """Enable patch button if at least one patch has its binary loaded"""
        has_enabled_patch = any(
            patch.widget.isEnabled() for patch in self.patches.values()
        )
        self.patch_btn.setEnabled(has_enabled_patch)

    def select_config_dir(self, value: Optional[str] = None) -> None:
        """Select configuration directory"""
        if value:
            selected_path = value
        else:
            selected_path = QFileDialog.getExistingDirectory(
                self, "Select config directory"
            )

        if not selected_path:
            return

        config_path = Path(selected_path)
        if not config_path.exists():
            if value:  # Only show error if called programmatically
                QMessageBox.warning(
                    self, "Warning", f"Directory does not exist: {selected_path}"
                )
            return

        if not config_path.is_dir():
            QMessageBox.warning(
                self, "Warning", f"Path is not a directory: {selected_path}"
            )
            return

        self.config_dir = str(config_path)
        self.save_settings()

        self.config_files_cbox.clear()
        self.clear_ui()

        config_files = list(config_path.glob("*.y?ml"))
        if not config_files:
            QMessageBox.warning(self, "Warning", "No config files found in directory!")
            return

        for config in sorted(config_files):
            self.config_files_cbox.addItem(config.stem, str(config))

    def clear_ui(self) -> None:
        """Clear all UI elements and close loaded binaries"""
        self.patch_btn.setEnabled(False)
        self.clear_layout(self.patches_layout)
        self.patches.clear()
        self.clear_layout(self.files_layout)

        # Close all binary files before clearing
        for binary_name in list(self.binary_files.keys()):
            self._close_binary(binary_name)

    def config_changed(self, index: int) -> None:
        """Handle configuration file selection change"""
        if index == -1:
            return

        config_data = self.config_files_cbox.currentData()
        if not config_data:
            QMessageBox.warning(self, "Warning", "No config file selected")
            return

        config_path = Path(config_data)
        if not config_path.exists():
            QMessageBox.critical(
                self, "Error", f"Config file does not exist: {config_path}"
            )
            return

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if not data:
                    QMessageBox.critical(self, "Error", "Config file is empty")
                    return
                self.current_config = Config(**data)

            self.clear_ui()
            self.update_binary_ui(self.current_config.files)

            # Show patches (disabled initially)
            self.update_patches_ui(self.current_config.patches)
        except (IOError, OSError) as e:
            QMessageBox.critical(self, "Error", f"Failed to read config file: {str(e)}")
        except yaml.YAMLError as e:
            QMessageBox.critical(
                self, "Error", f"Invalid YAML in config file: {str(e)}"
            )
        except (ValueError, KeyError) as e:
            QMessageBox.critical(self, "Error", f"Invalid config format: {str(e)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load config: {str(e)}")

    def clear_layout(
        self, layout: Union[QVBoxLayout, QHBoxLayout, QGridLayout]
    ) -> None:
        """Recursively clear all widgets from a layout"""
        while layout.count():
            item = layout.takeAt(0)

            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                self.clear_layout(item.layout())

    def update_patches_ui(self, patches: List[Patch]):
        self.clear_layout(self.patches_layout)
        self.patches.clear()

        for idx, patch in enumerate(patches):
            try:
                required_binaries = self._get_patch_required_binaries(patch)

                patch_group = QGroupBox(patch.name)

                # Set description as tooltip if available
                if patch.description:
                    patch_group.setToolTip(patch.description)

                patch_layout = QVBoxLayout()

                # Check if the required binaries are loaded
                binaries_loaded = all(
                    name in self.binary_files for name in required_binaries
                )

                if patch.editable:
                    value_widget = QLineEdit()
                    value_widget.setEnabled(binaries_loaded)

                    if binaries_loaded and len(patch.changes) > 0:
                        first_change = patch.changes[0]
                        first_binary_name = self._get_change_binary(
                            first_change, patch.file
                        )
                        _, binary = self.binary_files[first_binary_name]
                        if len(patch.changes) > 0:
                            # Check if all changes have the same value
                            if first_change.size is not None:
                                try:
                                    addr = self._offset_to_rva(
                                        first_change.offset, binary
                                    )
                                    current = int.from_bytes(
                                        binary.get_data(addr, first_change.size),
                                        byteorder="little",
                                    )

                                    # Verify all changes have the same value
                                    all_same = True
                                    for change in patch.changes[1:]:
                                        if change.size != first_change.size:
                                            all_same = False
                                            break
                                        change_binary_name = self._get_change_binary(
                                            change, patch.file
                                        )
                                        _, change_binary = self.binary_files[
                                            change_binary_name
                                        ]
                                        change_addr = self._offset_to_rva(
                                            change.offset, change_binary
                                        )
                                        change_value = int.from_bytes(
                                            change_binary.get_data(
                                                change_addr, change.size
                                            ),
                                            byteorder="little",
                                        )
                                        if change_value != current:
                                            all_same = False
                                            break

                                    if all_same:
                                        value_widget.setText(str(current))
                                    else:
                                        # Values differ, show first one with a note
                                        value_widget.setText(str(current))
                                        value_widget.setToolTip(
                                            f"Note: Current values differ across {len(patch.changes)} locations. "
                                            f"Entering a value will apply it to all locations."
                                        )
                                except Exception as e:
                                    QMessageBox.warning(
                                        self,
                                        "Warning",
                                        f"Failed to read current value: {e}",
                                    )
                    else:
                        if len(patch.changes) > 1:
                            value_widget.setPlaceholderText(
                                f"Load required binaries first (will apply to {len(patch.changes)} locations)"
                            )
                        else:
                            value_widget.setPlaceholderText("Load required binaries first")

                    patch_layout.addWidget(value_widget)

                    # Show number of locations and formulas if multiple changes or formulas exist
                    has_formulas = any(c.formula for c in patch.changes)
                    if len(patch.changes) > 1 or has_formulas:
                        location_parts = []
                        for i, c in enumerate(patch.changes):
                            part = f"{c.offset:#x}"
                            if c.formula:
                                part += f" ({c.formula})"
                            location_parts.append(part)

                        if len(patch.changes) > 1:
                            locations_text = (
                                f"Applies to {len(patch.changes)} location(s): "
                                + ", ".join(location_parts)
                            )
                        else:
                            locations_text = f"Offset {location_parts[0]}"

                        locations_label = QLabel(locations_text)
                        locations_label.setStyleSheet("color: gray; font-size: 9pt;")
                        locations_label.setWordWrap(True)
                        patch_layout.addWidget(locations_label)

                    patch.widget = value_widget
                else:
                    value_widget = QCheckBox("Enable")
                    value_widget.setEnabled(binaries_loaded)

                    if binaries_loaded:
                        # Check current state
                        all_match = True
                        try:
                            for change in patch.changes:
                                if change.value is None:
                                    all_match = False
                                    break
                                change_binary_name = self._get_change_binary(
                                    change, patch.file
                                )
                                _, change_binary = self.binary_files[change_binary_name]
                                addr = self._offset_to_rva(change.offset, change_binary)
                                desired = bytes.fromhex(change.value)
                                current = change_binary.get_data(addr, len(desired))
                                if current != desired:
                                    all_match = False
                                    break

                            if all_match:
                                value_widget.setChecked(True)
                        except Exception:
                            # If we can't read the bytes, assume not patched
                            pass

                    patch_layout.addWidget(value_widget)
                    patch.widget = value_widget

                if not binaries_loaded:
                    missing = [
                        name for name in required_binaries if name not in self.binary_files
                    ]
                    status_label = QLabel(
                        f"Requires binaries: {', '.join(required_binaries)}\nMissing: {', '.join(missing)}"
                    )
                    status_label.setStyleSheet("color: orange;")
                    patch_layout.addWidget(status_label)

                patch_group.setLayout(patch_layout)
                # Add to grid: row = idx // 2, column = idx % 2
                row = idx // 2
                col = idx % 2
                self.patches_layout.addWidget(patch_group, row, col)
                self.patches[patch.name] = patch
            except Exception as e:
                QMessageBox.warning(
                    self, "Error", f"Error processing patch {patch.name}: {e}"
                )
                continue

        self.update_patch_button_state()

    def update_binary_ui(self, files: Dict[str, BinaryFile]):
        self.clear_layout(self.files_layout)
        self.binary_files.clear()

        for binary_name, binary_data in files.items():
            binary_layout = QHBoxLayout()

            label = QLabel(f"{binary_name}:")
            label.setMinimumWidth(100)

            file_txt = QLineEdit()
            file_txt.setEnabled(False)

            # Try to load saved path
            if binary_name in self.saved_binary_paths:
                saved_path = self.saved_binary_paths[binary_name]
                if Path(saved_path).exists():
                    try:
                        binary = pefile.PE(saved_path, fast_load=True)
                        self.binary_files[binary_name] = (saved_path, binary)
                        file_txt.setText(saved_path)
                    except pefile.PEFormatError:
                        # File exists but is not a valid PE file - silently fail
                        file_txt.setText("<empty>")
                    except (IOError, OSError):
                        # File access error - show warning but not critical
                        file_txt.setText("<empty>")
                    except Exception as e:
                        # Other errors - show warning
                        QMessageBox.warning(
                            self, "Warning", f"Failed to load binary {binary_name}: {e}"
                        )
                        file_txt.setText("<empty>")
                else:
                    file_txt.setText("<empty>")
            else:
                file_txt.setText("<empty>")

            file_btn = QPushButton("Select")

            def make_select_handler(name, txt, default_filter):
                return lambda: self.select_binary(name, txt, default_filter)

            file_btn.clicked.connect(
                make_select_handler(binary_name, file_txt, binary_data.default)
            )

            binary_layout.addWidget(label)
            binary_layout.addWidget(file_txt)
            binary_layout.addWidget(file_btn)

            self.files_layout.addLayout(binary_layout)

        self.files_layout.addStretch()

    def init_ui(self) -> None:
        """Initialize the user interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

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
        files_scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
        """)
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
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
        """)
        self.patches_widget = QWidget()
        self.patches_layout = QGridLayout(self.patches_widget)
        self.patches_layout.setColumnStretch(0, 1)
        self.patches_layout.setColumnStretch(1, 1)
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


def main() -> None:
    """Main entry point for the application"""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
