import sys
import yaml
import pefile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from pydantic import BaseModel, Field, field_validator, model_validator

__version__ = "0.3.0"

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

from PyQt6.QtCore import Qt


class PatchChange(BaseModel):
    """Represents a single byte change in a patch"""

    file: Optional[str] = None
    offset: Optional[Union[int, str]] = (
        None  # Either offset or pattern must be provided. Can be int or expression like "0x12345 + 4"
    )
    pattern: Optional[str] = (
        None  # Hex pattern to search for (e.g., "48 8B 05 ?? ?? ?? ??")
    )
    pattern_offset: Optional[int] = (
        None  # Offset within matched pattern (default: 0, patches at start of match)
    )
    value: Optional[str] = None
    size: Optional[int] = None
    formula: Optional[str] = (
        None  # Formula/expression for editable patches (e.g., "value * 0x10", "value + 5")
    )
    display_formula: Optional[str] = (
        None  # Formula to convert stored value to display value (e.g., "value / 86400" for seconds to days)
    )
    input_formula: Optional[str] = (
        None  # Formula to convert display value to stored value (e.g., "value * 86400" for days to seconds)
    )

    @field_validator("offset")
    @classmethod
    def validate_offset(cls, v: Optional[Union[int, str]]) -> Optional[int]:
        """Parse offset - can be int or expression like '0x12345 + 4'"""
        if v is None:
            return v
        if isinstance(v, int):
            return v
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return None
            # Try to parse as expression (e.g., "0x12345 + 4" or "0x12345 + 2")
            # First check if it contains arithmetic operators
            if "+" in v or "-" in v or "*" in v or "/" in v:
                try:
                    # Evaluate the expression safely with restricted globals
                    # Only allow basic arithmetic operations
                    result = eval(v, {"__builtins__": {}}, {})
                    if not isinstance(result, (int, float)):
                        raise ValueError(
                            f"Offset expression must evaluate to a number: {v}"
                        )
                    return int(result)
                except Exception:
                    raise ValueError(
                        f"Invalid offset expression: {v}. Must be valid arithmetic like '0x12345 + 4'"
                    )
            else:
                # No operators, try parsing as simple hex/decimal int
                try:
                    return int(v, 0)  # 0 allows auto-detection of hex (0x) or decimal
                except ValueError:
                    raise ValueError(
                        f"Invalid offset format: {v}. Must be int or expression like '0x12345 + 4'"
                    )
        return v

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

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, v: Optional[str]) -> Optional[str]:
        """Validate pattern format (hex bytes, supports ?? as wildcard)"""
        if v is None:
            return v
        v = v.strip()
        if not v:
            return None
        # Remove spaces and validate hex format
        parts = v.split()
        for part in parts:
            if part.upper() == "??":
                continue  # Wildcard byte
            try:
                int(part, 16)
                if len(part) > 2:
                    raise ValueError(f"Invalid hex byte in pattern: {part}")
            except ValueError:
                raise ValueError(f"Invalid pattern format: {v}")
        return v

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

    @field_validator("display_formula", "input_formula")
    @classmethod
    def validate_display_input_formula(cls, v: Optional[str]) -> Optional[str]:
        """Validate display/input formula syntax (basic check)"""
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        # Basic syntax check - must contain 'value' variable
        if "value" not in v:
            raise ValueError("Display/input formula must contain 'value' variable")
        return v

    @model_validator(mode="after")
    def validate_offset_or_pattern(self) -> "PatchChange":
        """Validate that either offset or pattern is provided"""
        if self.offset is None and self.pattern is None:
            raise ValueError("Either 'offset' or 'pattern' must be provided")
        if self.offset is not None and self.pattern is not None:
            raise ValueError("Cannot specify both 'offset' and 'pattern'")
        return self


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

        # If editable, changes can have either size (editable) or value (fixed)
        if info.data.get("editable", False):
            editable_sizes = []
            for i, change in enumerate(v):
                if change.size is not None and change.value is not None:
                    raise ValueError(
                        f"Editable patch change {i} cannot have both size and value"
                    )
                if change.size is None and change.value is None:
                    raise ValueError(
                        f"Editable patch change {i} must specify either size (for editable) or value (for fixed)"
                    )
                if change.size is not None:
                    editable_sizes.append(change.size)

            # All editable changes (with size) should have the same size for consistency
            if len(set(editable_sizes)) > 1:
                raise ValueError(
                    "All editable changes (with size) in an editable patch must have the same size"
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
    selected_config: Optional[str] = None


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        """Initialize the main window and set up directories, settings, and UI.

        Sets up backup and patches directories based on whether running as
        compiled executable or script. Initializes UI components and loads
        saved settings and default configurations.
        """
        super().__init__()

        self.binary_files: Dict[str, Tuple[str, pefile.PE]] = {}
        self.saved_binary_paths: Dict[str, str] = {}
        self.patches: Dict[str, Patch] = {}
        self.config_dir: Optional[str] = None
        self.saved_selected_config: Optional[str] = None

        # Set backup directory - use executable directory for onefile, or current dir for script
        if getattr(sys, "frozen", False):
            # Running as compiled executable - use directory where exe is located
            self.backup_dir = Path(sys.executable).parent / "backups"
            self.patches_dir = Path(sys.executable).parent / "patches"
        else:
            # Running as script - use current directory
            self.backup_dir = Path("backups")
            self.patches_dir = Path("patches")
        self.backup_dir.mkdir(exist_ok=True)
        self.patches_dir.mkdir(exist_ok=True)

        # Set settings file location - same logic as backup dir
        if getattr(sys, "frozen", False):
            self.settings_file = Path(sys.executable).parent / "settings.yml"
        else:
            self.settings_file = Path("settings.yml")

        # Copy bundled patches to persistent location on first run (PyInstaller only)
        if getattr(sys, "frozen", False):
            self._ensure_patches_copied()

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

    def _ensure_patches_copied(self) -> None:
        """Copy bundled patches to persistent location if not already present

        This allows users to modify and add new patch files even when running
        from a PyInstaller onefile executable.
        """
        bundled_patches = self._get_resource_path("patches")

        # Only copy if bundled patches exist and persistent directory is empty or missing files
        if not bundled_patches.exists():
            return

        try:
            # Get list of bundled patch files
            bundled_files = {
                f.name for f in bundled_patches.glob("*.y?ml") if f.is_file()
            }

            if not bundled_files:
                return

            # Check which files are missing in persistent location
            existing_files = {
                f.name for f in self.patches_dir.glob("*.y?ml") if f.is_file()
            }
            missing_files = bundled_files - existing_files

            # Copy missing files from bundled location
            if missing_files:
                for filename in missing_files:
                    src = bundled_patches / filename
                    dst = self.patches_dir / filename
                    if src.exists() and src.is_file():
                        shutil.copy2(src, dst)
        except (IOError, OSError, shutil.Error):
            # Silently fail - user can still select patches directory manually
            # or use bundled patches if persistent copy fails
            pass

    def _offset_to_rva(self, offset: int, binary: pefile.PE) -> int:
        """Convert virtual address offset to RVA (Relative Virtual Address).

        Args:
            offset: Virtual address offset to convert
            binary: PE file object containing the binary

        Returns:
            RVA (Relative Virtual Address) calculated by subtracting ImageBase
        """
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

    def _search_pattern(self, pattern: str, binary: pefile.PE) -> Optional[int]:
        """Search for a pattern in the binary and return the offset (virtual address) of the first match

        Pattern format: hex bytes separated by spaces, "??" for wildcard bytes
        Example: "48 8B 05 ?? ?? ?? ??" matches "48 8B 05" followed by 4 wildcard bytes

        Returns the virtual address offset of the match, or None if not found
        """
        # Parse pattern into bytes and wildcards
        pattern_parts = pattern.strip().split()
        if not pattern_parts:
            return None

        # Build search pattern: list of (byte_value, is_wildcard) tuples
        search_pattern = []
        for part in pattern_parts:
            if part.upper() == "??":
                search_pattern.append((None, True))
            else:
                try:
                    byte_val = int(part, 16)
                    if byte_val < 0 or byte_val > 255:
                        return None
                    search_pattern.append((byte_val, False))
                except ValueError:
                    return None

        if not search_pattern:
            return None

        # Get binary data - search in memory-mapped image
        try:
            # Get the memory-mapped image (virtual address space)
            binary_data = binary.get_memory_mapped_image()

            if len(binary_data) < len(search_pattern):
                return None

            # Search for pattern
            pattern_len = len(search_pattern)
            for i in range(len(binary_data) - pattern_len + 1):
                match = True
                for j, (expected_byte, is_wildcard) in enumerate(search_pattern):
                    if not is_wildcard and binary_data[i + j] != expected_byte:
                        match = False
                        break

                if match:
                    # Found match at RVA i, convert to virtual address
                    # The memory-mapped image is already in RVA space
                    return binary.OPTIONAL_HEADER.ImageBase + i

            return None
        except Exception:
            return None

    def _resolve_change_offset(
        self, change: PatchChange, binary: pefile.PE
    ) -> Optional[int]:
        """Resolve the actual offset (virtual address) for a change

        If change has an offset, returns it directly.
        If change has a pattern, searches for it and returns the match location.

        Returns the virtual address offset, or None if pattern not found
        """
        if change.offset is not None:
            return change.offset

        if change.pattern is None:
            return None

        # Search for pattern
        match_offset = self._search_pattern(change.pattern, binary)
        if match_offset is None:
            return None

        # Apply pattern_offset if specified (defaults to 0)
        pattern_offset = change.pattern_offset or 0
        return match_offset + pattern_offset

    def _get_change_binary(
        self, change: PatchChange, default_binary: Optional[str]
    ) -> str:
        """Resolve which binary a change targets.

        Args:
            change: The patch change to resolve the target binary for
            default_binary: Default binary name if change doesn't specify one

        Returns:
            The name of the target binary

        Raises:
            ValueError: If neither change.file nor default_binary is specified
        """
        binary_name = change.file or default_binary
        if binary_name is None:
            raise ValueError("Change does not specify a target binary")
        return binary_name

    def _group_changes_by_binary(self, patch: Patch) -> Dict[str, List[PatchChange]]:
        """Group patch changes by their target binary.

        Args:
            patch: The patch containing changes to group

        Returns:
            Dictionary mapping binary names to lists of changes targeting that binary
        """
        grouped: Dict[str, List[PatchChange]] = {}
        for change in patch.changes:
            binary_name = self._get_change_binary(change, patch.file)
            grouped.setdefault(binary_name, []).append(change)
        return grouped

    def _get_patch_required_binaries(self, patch: Patch) -> List[str]:
        """Return list of binaries a patch touches.

        Args:
            patch: The patch to analyze

        Returns:
            Sorted list of binary names that this patch requires
        """
        return sorted(self._group_changes_by_binary(patch).keys())

    def _close_binary(self, binary_name: str) -> None:
        """Close and remove a binary file from memory.

        Args:
            binary_name: Name of the binary to close
        """
        if binary_name in self.binary_files:
            _, binary = self.binary_files[binary_name]
            try:
                binary.close()
            except Exception:
                pass  # Ignore errors when closing
            del self.binary_files[binary_name]

    def load_settings(self) -> None:
        """Load saved binary paths and config directory from settings file.

        Reads the settings YAML file and restores saved binary paths and
        configuration directory. Shows warnings if loading fails but continues
        execution with default values.
        """
        if self.settings_file.exists():
            try:
                with open(self.settings_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data:
                        settings = Settings(**data)
                        self.saved_binary_paths = settings.binary_paths or {}
                        self.config_dir = settings.config_dir
                        self.saved_selected_config = settings.selected_config
                    else:
                        self.config_dir = None
                        self.saved_selected_config = None
            except (yaml.YAMLError, ValueError, KeyError) as e:
                QMessageBox.warning(self, "Warning", f"Failed to load settings: {e}")
                self.config_dir = None
                self.saved_selected_config = None
            except Exception as e:
                QMessageBox.warning(
                    self, "Warning", f"Unexpected error loading settings: {e}"
                )
                self.config_dir = None
                self.saved_selected_config = None
        else:
            self.config_dir = None
            self.saved_selected_config = None

    def save_settings(self) -> None:
        """Save binary paths and config directory to settings file.

        Merges currently loaded binary paths with previously saved paths,
        then writes all settings to the settings YAML file. Shows warnings
        if saving fails but does not interrupt execution.
        """
        try:
            # Extract paths from binary_files
            binary_paths = {name: path for name, (path, _) in self.binary_files.items()}
            # Merge with saved_binary_paths to preserve paths that aren't currently loaded
            binary_paths = {**self.saved_binary_paths, **binary_paths}

            settings = Settings(
                binary_paths=binary_paths,
                config_dir=self.config_dir,
                selected_config=self.saved_selected_config,
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
        """Load default configuration directory.

        Attempts to load the configuration directory in this order:
        1. Saved config directory from settings (if exists)
        2. Persistent patches directory (for PyInstaller or script mode)
        3. Resource path patches directory (for PyInstaller bundled patches)
        4. Current directory patches folder

        Selects the first available directory and populates the config file list.
        """
        if self.config_dir and Path(self.config_dir).exists():
            self.select_config_dir(self.config_dir)
        else:
            # Use persistent patches directory (works for both PyInstaller and script mode)
            # This allows users to modify and add new patch files
            if self.patches_dir.exists():
                self.select_config_dir(str(self.patches_dir))
            else:
                # Fallback: try resource path (for PyInstaller bundled patches)
                default_path = self._get_resource_path("patches")
                if not default_path.exists():
                    # Final fallback: current directory
                    default_path = Path("patches")

                if default_path.exists():
                    self.select_config_dir(str(default_path))

    def get_backup_path(self, binary_name: str) -> Path:
        """Generate backup file path for a binary.

        Args:
            binary_name: Name of the binary to get backup path for

        Returns:
            Path object pointing to the backup YAML file for this binary
        """
        return self.backup_dir / f"{binary_name}_backup.yaml"

    def is_binary_patched(self, binary_name: str) -> bool:
        """Check if binary has been patched (backup exists).

        Args:
            binary_name: Name of the binary to check

        Returns:
            True if backup file exists, False otherwise
        """
        backup_path = self.get_backup_path(binary_name)
        return backup_path.exists()

    def save_original_bytes(self, binary_name: str, changes: List[PatchChange]) -> None:
        """Save original bytes before first patch.

        Reads the original bytes from the binary at each change location
        and saves them to a backup YAML file. Merges with existing backup
        data to avoid duplicating offsets that are already saved.

        Args:
            binary_name: Name of the binary to backup
            changes: List of patch changes to save original bytes for

        Note:
            Skips offsets that are already in the backup file. Shows warnings
            if reading bytes fails but does not interrupt execution.
        """
        backup_path = self.get_backup_path(binary_name)
        _, binary = self.binary_files[binary_name]

        # Load existing backup data if it exists
        existing_data = []
        existing_offsets = set()
        if backup_path.exists():
            try:
                with open(backup_path, "r", encoding="utf-8") as f:
                    existing_data = yaml.safe_load(f) or []
                    existing_offsets = {
                        item["offset"] for item in existing_data if "offset" in item
                    }
            except (IOError, OSError, yaml.YAMLError, KeyError) as e:
                QMessageBox.warning(
                    self,
                    "Warning",
                    f"Failed to load existing backup: {e}. Creating new backup.",
                )
                existing_data = []
                existing_offsets = set()

        # Collect new offsets that aren't already saved
        new_data = []
        for change in changes:
            # Resolve offset (from direct offset or pattern match)
            resolved_offset = self._resolve_change_offset(change, binary)
            if resolved_offset is None:
                QMessageBox.warning(
                    self,
                    "Warning",
                    "Failed to resolve offset for change: pattern not found or invalid",
                )
                return

            # Skip if this offset is already saved
            if resolved_offset in existing_offsets:
                continue

            addr = self._offset_to_rva(resolved_offset, binary)
            size = (
                len(bytes.fromhex(change.value))
                if change.value is not None
                else change.size
            )
            if size is None:
                continue
            try:
                original_bytes = binary.get_data(addr, size)
                new_data.append(
                    {"offset": resolved_offset, "value": original_bytes.hex()}
                )
                existing_offsets.add(resolved_offset)
            except Exception as e:
                QMessageBox.warning(
                    self,
                    "Warning",
                    f"Failed to read original bytes at offset {resolved_offset:#x}: {e}",
                )
                return

        # Merge existing and new data
        merged_data = existing_data + new_data

        try:
            with open(backup_path, "w", encoding="utf-8") as f:
                yaml.dump(merged_data, f, default_flow_style=False)
        except (IOError, OSError, yaml.YAMLError) as e:
            QMessageBox.warning(self, "Warning", f"Failed to save backup: {e}")

    def restore_original_bytes(self, binary_name: str) -> bool:
        """Restore original bytes from backup.

        Reads the backup YAML file and restores all original byte values
        to their original locations in the binary.

        Args:
            binary_name: Name of the binary to restore

        Returns:
            True if restoration was successful, False otherwise

        Note:
            Shows warnings if backup file doesn't exist or restoration fails.
        """
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
        """Apply all enabled patches to their respective binaries.

        Processes all patches in the current configuration:
        - For editable patches: Reads value from input widget, applies formulas,
          and writes to all change locations
        - For checkbox patches: Applies or restores based on checkbox state

        Saves original bytes before first patch application. Writes all modified
        binaries to disk after processing. Shows success/error messages.

        Note:
            Only processes patches where required binaries are loaded and
            patch widgets are enabled. Skips patches with validation errors.
        """
        try:
            modified_binaries = set()

            for patch_name, patch in self.patches.items():
                try:
                    changes_by_binary = self._group_changes_by_binary(patch)
                except ValueError as e:
                    QMessageBox.warning(
                        self, "Error", f"Invalid patch '{patch_name}': {e}"
                    )
                    continue

                required_binaries = set(changes_by_binary.keys())

                # Check if all binaries are loaded
                if any(b not in self.binary_files for b in required_binaries):
                    continue

                # Skip if patch widget is disabled (only for editable patches with editable changes)
                if (
                    patch.editable
                    and patch.widget is not None
                    and not patch.widget.isEnabled()
                ):
                    continue

                if patch.editable:
                    try:
                        # Separate changes into editable (with size) and fixed (with value)
                        editable_changes = [
                            c for c in patch.changes if c.size is not None
                        ]
                        fixed_changes = [
                            c for c in patch.changes if c.value is not None
                        ]

                        # Handle editable changes (if any)
                        stored_value_int = None
                        if editable_changes:
                            if patch.widget is None:
                                QMessageBox.warning(
                                    self,
                                    "Error",
                                    f"Patch {patch_name} has editable changes but no input widget",
                                )
                                continue

                            new_value_text = patch.widget.text().strip()
                            if not new_value_text:
                                # If empty, try to restore original if backup exists
                                for binary_name in required_binaries:
                                    if self.is_binary_patched(binary_name):
                                        if self.restore_original_bytes(binary_name):
                                            modified_binaries.add(binary_name)
                                continue

                            display_value_int = int(new_value_text)

                            # Get size from first editable change (all should have same size per validation)
                            size = editable_changes[0].size
                            first_editable_change = editable_changes[0]

                            # Convert display value to stored value using input_formula if specified
                            stored_value_int = display_value_int
                            if first_editable_change.input_formula:
                                try:
                                    stored_value_int = self._evaluate_formula(
                                        first_editable_change.input_formula,
                                        display_value_int,
                                    )
                                except ValueError as e:
                                    QMessageBox.warning(
                                        self,
                                        "Error",
                                        f"Invalid input formula in patch {patch_name}: {e}",
                                    )
                                    continue

                        # Apply value to all changes (with formulas if specified)
                        success = True
                        for binary_name, changes in changes_by_binary.items():
                            _, binary = self.binary_files[binary_name]
                            for change in changes:
                                # Resolve offset (from direct offset or pattern match)
                                resolved_offset = self._resolve_change_offset(
                                    change, binary
                                )
                                if resolved_offset is None:
                                    QMessageBox.warning(
                                        self,
                                        "Error",
                                        f"Failed to resolve offset for change in patch {patch_name}: pattern not found or invalid",
                                    )
                                    success = False
                                    break

                                # Handle editable change (with size)
                                if change.size is not None:
                                    if stored_value_int is None:
                                        QMessageBox.warning(
                                            self,
                                            "Error",
                                            f"Patch {patch_name} has editable change but no input value provided",
                                        )
                                        success = False
                                        break

                                    if (
                                        not editable_changes
                                        or change.size != editable_changes[0].size
                                    ):
                                        QMessageBox.warning(
                                            self,
                                            "Error",
                                            f"Patch {patch_name} has inconsistent sizes",
                                        )
                                        success = False
                                        break

                                    # Calculate final value using formula if specified, otherwise use stored value as-is
                                    try:
                                        final_value_int = self._evaluate_formula(
                                            change.formula, stored_value_int
                                        )
                                    except ValueError as e:
                                        QMessageBox.warning(
                                            self,
                                            "Error",
                                            f"Invalid formula at offset {resolved_offset:#x}: {e}",
                                        )
                                        success = False
                                        break

                                    # Check for overflow based on size
                                    max_value = (1 << (change.size * 8)) - 1
                                    if final_value_int > max_value:
                                        QMessageBox.warning(
                                            self,
                                            "Error",
                                            f"Value {final_value_int} exceeds maximum for {change.size} byte(s) at offset {resolved_offset:#x}",
                                        )
                                        success = False
                                        break
                                    if final_value_int < 0:
                                        QMessageBox.warning(
                                            self,
                                            "Error",
                                            f"Value {final_value_int} is negative at offset {resolved_offset:#x}",
                                        )
                                        success = False
                                        break

                                    try:
                                        final_value = final_value_int.to_bytes(
                                            change.size, byteorder="little"
                                        )
                                        addr = self._offset_to_rva(
                                            resolved_offset, binary
                                        )
                                        binary.set_bytes_at_rva(addr, final_value)
                                    except Exception as e:
                                        QMessageBox.warning(
                                            self,
                                            "Error",
                                            f"Failed to apply patch at offset {resolved_offset:#x}: {e}",
                                        )
                                        success = False
                                        break

                                # Handle fixed change (with value)
                                elif change.value is not None:
                                    try:
                                        final_value = bytes.fromhex(change.value)
                                        addr = self._offset_to_rva(
                                            resolved_offset, binary
                                        )
                                        binary.set_bytes_at_rva(addr, final_value)
                                    except Exception as e:
                                        QMessageBox.warning(
                                            self,
                                            "Error",
                                            f"Failed to apply fixed value at offset {resolved_offset:#x}: {e}",
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
                                # Resolve offset (from direct offset or pattern match)
                                resolved_offset = self._resolve_change_offset(
                                    change, binary
                                )
                                if resolved_offset is None:
                                    QMessageBox.warning(
                                        self,
                                        "Error",
                                        f"Failed to resolve offset for change in patch {patch_name}: pattern not found or invalid",
                                    )
                                    continue
                                addr = self._offset_to_rva(resolved_offset, binary)
                                binary.set_bytes_at_rva(
                                    addr, bytes.fromhex(change.value)
                                )
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
        """Select and load a binary file.

        Opens a file dialog to select a PE binary file, loads it using pefile,
        and updates the UI. Closes any previously loaded binary with the same name.
        Updates patch UI and button state after loading.

        Args:
            name: Name identifier for the binary
            result_object: QLineEdit widget to display the selected file path
            default: Optional default filter name for the file dialog

        Note:
            Shows error messages if file is invalid PE format or cannot be opened.
            Saves settings after successful load.
        """
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
        """Enable patch button if at least one patch has its binary loaded.

        Checks all patches to see if any have their required binaries loaded
        and are enabled. Enables the patch button if at least one such patch exists.
        """
        has_enabled_patch = any(
            patch.widget.isEnabled() for patch in self.patches.values()
        )
        self.patch_btn.setEnabled(has_enabled_patch)

    def select_config_dir(self, value: Optional[str] = None) -> None:
        """Select configuration directory.

        Sets the configuration directory and populates the config file combo box
        with all YAML/YML files found in that directory. Clears current UI state.

        Args:
            value: Optional directory path to use directly. If None, opens file dialog.

        Note:
            Validates that the path exists and is a directory. Shows warnings
            if no config files are found. Saves the directory to settings.
        """
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

        # Block signals while clearing and populating to avoid triggering config_changed
        self.config_files_cbox.blockSignals(True)
        self.config_files_cbox.clear()
        self.config_files_cbox.blockSignals(False)

        self.clear_ui()

        config_files = list(config_path.glob("*.y?ml"))
        if not config_files:
            QMessageBox.warning(self, "Warning", "No config files found in directory!")
            return

        # Block signals while adding items and restoring selection
        self.config_files_cbox.blockSignals(True)
        for config in sorted(config_files):
            self.config_files_cbox.addItem(config.stem, str(config))

        # Restore last selected config if it exists in this directory
        restored_index = -1
        if self.saved_selected_config:
            saved_path = Path(self.saved_selected_config)
            if saved_path.exists():
                # Normalize paths for comparison
                saved_resolved = saved_path.resolve()
                for i in range(self.config_files_cbox.count()):
                    item_path = Path(self.config_files_cbox.itemData(i))
                    if item_path.exists() and item_path.resolve() == saved_resolved:
                        # Set index while signals are blocked
                        self.config_files_cbox.setCurrentIndex(i)
                        restored_index = i
                        break
            else:
                # Saved config file doesn't exist anymore, clear the reference
                self.saved_selected_config = None
                self.save_settings()

        # If saved config not found, select first config (if any)
        if restored_index == -1 and self.config_files_cbox.count() > 0:
            self.config_files_cbox.setCurrentIndex(0)
            restored_index = 0

        # Unblock signals
        self.config_files_cbox.blockSignals(False)

        # If we have a valid index, manually trigger the change handler
        # (setCurrentIndex while blocked doesn't trigger the signal)
        if restored_index != -1:
            self.config_changed(restored_index)

    def clear_ui(self) -> None:
        """Clear all UI elements and close loaded binaries.

        Clears all patch and file UI layouts, closes all loaded binary files,
        and disables the patch button. Used when switching configurations.
        """
        self.patch_btn.setEnabled(False)
        self.clear_layout(self.patches_layout)
        self.patches.clear()
        self.clear_layout(self.files_layout)

        # Close all binary files before clearing
        for binary_name in list(self.binary_files.keys()):
            self._close_binary(binary_name)

    def config_changed(self, index: int) -> None:
        """Handle configuration file selection change.

        Loads the selected YAML configuration file, validates it, and updates
        the UI with the new configuration's files and patches.

        Args:
            index: Index of the selected item in the config combo box (-1 if none)

        Note:
            Shows error messages if file doesn't exist, is invalid YAML, or
            has invalid configuration format. Clears UI before loading new config.
        """
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

            # Save selected config (use resolved absolute path for consistency)
            self.saved_selected_config = str(config_path.resolve())
            self.save_settings()
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
        """Recursively clear all widgets from a layout.

        Removes all widgets and nested layouts from the given layout,
        scheduling them for deletion. Handles nested layouts recursively.

        Args:
            layout: The layout to clear (QVBoxLayout, QHBoxLayout, or QGridLayout)
        """
        while layout.count():
            item = layout.takeAt(0)

            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                self.clear_layout(item.layout())

    def update_patches_ui(self, patches: List[Patch]):
        """Update the patches UI with the given list of patches.

        Clears existing patches and creates new UI elements for each patch:
        - Creates group boxes for each patch in a 2-column grid
        - For editable patches: Creates text input widgets with current values
        - For checkbox patches: Creates checkboxes with current patch state
        - Shows location information and required binaries status
        - Enables/disables patches based on whether required binaries are loaded

        Args:
            patches: List of Patch objects to display in the UI

        Note:
            Patches are arranged in a grid with 2 columns. Shows warnings
            for patches that fail to process but continues with others.
        """
        self.clear_layout(self.patches_layout)
        self.patches.clear()

        for idx, patch in enumerate(patches):
            try:
                required_binaries = self._get_patch_required_binaries(patch)

                patch_group = QGroupBox(patch.name)
                # Prevent vertical expansion - only take space needed
                patch_group.setSizePolicy(
                    QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum
                )

                # Set description as tooltip if available
                if patch.description:
                    patch_group.setToolTip(patch.description)

                patch_layout = QVBoxLayout()

                # Check if the required binaries are loaded
                binaries_loaded = all(
                    name in self.binary_files for name in required_binaries
                )

                if patch.editable:
                    # Find editable changes (with size) and fixed changes (with value)
                    editable_changes = [c for c in patch.changes if c.size is not None]
                    fixed_changes = [c for c in patch.changes if c.value is not None]

                    # Only show input widget if there are editable changes
                    if editable_changes:
                        value_widget = QLineEdit()
                        value_widget.setEnabled(binaries_loaded)

                        if binaries_loaded and len(editable_changes) > 0:
                            first_editable_change = editable_changes[0]
                            first_binary_name = self._get_change_binary(
                                first_editable_change, patch.file
                            )
                            _, binary = self.binary_files[first_binary_name]
                            # Check if all editable changes have the same value
                            if first_editable_change.size is not None:
                                try:
                                    first_offset = self._resolve_change_offset(
                                        first_editable_change, binary
                                    )
                                    if first_offset is None:
                                        raise ValueError(
                                            "Failed to resolve offset for first editable change"
                                        )
                                    addr = self._offset_to_rva(first_offset, binary)
                                    current = int.from_bytes(
                                        binary.get_data(
                                            addr, first_editable_change.size
                                        ),
                                        byteorder="little",
                                    )

                                    # Verify all editable changes have the same value
                                    all_same = True
                                    for change in editable_changes[1:]:
                                        if change.size != first_editable_change.size:
                                            all_same = False
                                            break
                                        change_binary_name = self._get_change_binary(
                                            change, patch.file
                                        )
                                        _, change_binary = self.binary_files[
                                            change_binary_name
                                        ]
                                        change_offset = self._resolve_change_offset(
                                            change, change_binary
                                        )
                                        if change_offset is None:
                                            all_same = False
                                            break
                                        change_addr = self._offset_to_rva(
                                            change_offset, change_binary
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

                                    # Apply display formula if specified (convert stored to display format)
                                    display_value = current
                                    if first_editable_change.display_formula:
                                        try:
                                            display_value = self._evaluate_formula(
                                                first_editable_change.display_formula,
                                                current,
                                            )
                                        except Exception:
                                            # If display formula fails, use raw value
                                            pass

                                    if all_same:
                                        value_widget.setText(str(display_value))
                                    else:
                                        # Values differ, show first one with a note
                                        value_widget.setText(str(display_value))
                                        value_widget.setToolTip(
                                            f"Note: Current values differ across {len(editable_changes)} editable locations. "
                                            f"Entering a value will apply it to all editable locations."
                                        )
                                except Exception as e:
                                    QMessageBox.warning(
                                        self,
                                        "Warning",
                                        f"Failed to read current value: {e}",
                                    )
                        else:
                            if len(editable_changes) > 1:
                                value_widget.setPlaceholderText(
                                    f"Load required binaries first (will apply to {len(editable_changes)} editable locations)"
                                )
                            else:
                                value_widget.setPlaceholderText(
                                    "Load required binaries first"
                                )

                        patch_layout.addWidget(value_widget)
                        patch.widget = value_widget
                    else:
                        # No editable changes, but patch is marked as editable
                        # This shouldn't happen per validation, but handle gracefully
                        info_label = QLabel("No editable changes in this patch")
                        info_label.setStyleSheet("color: gray; font-size: 9pt;")
                        patch_layout.addWidget(info_label)
                        patch.widget = None

                    # Always show location information
                    location_parts = []
                    for i, c in enumerate(patch.changes):
                        if c.offset is not None:
                            part = f"{c.offset:#x}"
                        elif c.pattern is not None:
                            part = f"pattern: {c.pattern}"
                            if binaries_loaded:
                                # Try to resolve and show actual offset
                                change_binary_name = self._get_change_binary(
                                    c, patch.file
                                )
                                if change_binary_name in self.binary_files:
                                    _, change_binary = self.binary_files[
                                        change_binary_name
                                    ]
                                    resolved = self._resolve_change_offset(
                                        c, change_binary
                                    )
                                    if resolved is not None:
                                        part += f" → {resolved:#x}"
                        else:
                            part = "unknown"

                        # Indicate if change is editable or fixed
                        if c.size is not None:
                            part += " [editable]"
                        elif c.value is not None:
                            part += " [fixed]"

                        if c.formula:
                            part += f" ({c.formula})"
                        location_parts.append(part)

                    if len(patch.changes) > 1:
                        locations_text = (
                            f"Applies to {len(patch.changes)} location(s): "
                            + ", ".join(location_parts)
                        )
                    else:
                        locations_text = f"Location: {location_parts[0]}"

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
                                resolved_offset = self._resolve_change_offset(
                                    change, change_binary
                                )
                                if resolved_offset is None:
                                    all_match = False
                                    break
                                addr = self._offset_to_rva(
                                    resolved_offset, change_binary
                                )
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

                    # Always show location information
                    location_parts = []
                    for i, c in enumerate(patch.changes):
                        if c.offset is not None:
                            part = f"{c.offset:#x}"
                        elif c.pattern is not None:
                            part = f"pattern: {c.pattern}"
                            if binaries_loaded:
                                # Try to resolve and show actual offset
                                change_binary_name = self._get_change_binary(
                                    c, patch.file
                                )
                                if change_binary_name in self.binary_files:
                                    _, change_binary = self.binary_files[
                                        change_binary_name
                                    ]
                                    resolved = self._resolve_change_offset(
                                        c, change_binary
                                    )
                                    if resolved is not None:
                                        part += f" → {resolved:#x}"
                        else:
                            part = "unknown"

                        if c.formula:
                            part += f" ({c.formula})"
                        location_parts.append(part)

                    if len(patch.changes) > 1:
                        locations_text = (
                            f"Applies to {len(patch.changes)} location(s): "
                            + ", ".join(location_parts)
                        )
                    else:
                        locations_text = f"Location: {location_parts[0]}"

                    locations_label = QLabel(locations_text)
                    locations_label.setStyleSheet("color: gray; font-size: 9pt;")
                    locations_label.setWordWrap(True)
                    patch_layout.addWidget(locations_label)

                    patch.widget = value_widget

                if not binaries_loaded:
                    missing = [
                        name
                        for name in required_binaries
                        if name not in self.binary_files
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
                self.patches_layout.addWidget(
                    patch_group, row, col, 1, 1, Qt.AlignmentFlag.AlignTop
                )
                self.patches[patch.name] = patch
            except Exception as e:
                QMessageBox.warning(
                    self, "Error", f"Error processing patch {patch.name}: {e}"
                )
                continue

        self.update_patch_button_state()

    def update_binary_ui(self, files: Dict[str, BinaryFile]):
        """Update the binary files UI with the given file configuration.

        Clears existing file UI and creates input widgets for each binary file
        defined in the configuration. Attempts to load saved binary paths
        from settings if they exist and are valid PE files.

        Args:
            files: Dictionary mapping binary names to BinaryFile configurations

        Note:
            Creates a label, read-only text field, and select button for each binary.
            Automatically loads binaries from saved paths if they exist and are valid.
        """
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
        """Initialize the user interface.

        Creates and arranges all UI components:
        - Config group: Combo box for config files and directory selector
        - Files group: Scrollable area for binary file selectors
        - Patches group: Scrollable grid area for patch group boxes
        - Patch button: Button to apply all enabled patches

        Sets up layouts, scroll areas, and connects signals to handlers.
        """
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
    """Main entry point for the application.

    Creates the QApplication, sets the Fusion style, creates and shows
    the main window, then starts the event loop.
    """
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
