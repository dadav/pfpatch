import sys
import yaml
import pefile
import shutil
import struct
import tomllib
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from pydantic import BaseModel, Field, field_validator, model_validator

def _get_version() -> str:
    if getattr(sys, "frozen", False):
        # PyInstaller: look in bundle directory
        pyproject_path = Path(sys._MEIPASS) / "pyproject.toml"
    else:
        # Running as script
        pyproject_path = Path(__file__).parent / "pyproject.toml"
    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)
    return data["project"]["version"]

__version__ = _get_version()

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
    QProgressDialog,
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
    type: Optional[str] = (
        "int"  # Data type: "int" (default), "float" (IEEE 754 single-precision, 4 bytes), or "double" (IEEE 754 double-precision, 8 bytes)
    )
    formula: Optional[str] = (
        None  # Formula/expression for editable patches (e.g., "value * 0x10", "value + 5")
    )
    display_formula: Optional[str] = (
        None  # Formula to convert stored value to display value (e.g., "value / 86400" for seconds to days)
    )
    input_formula: Optional[str] = (
        None  # Formula to convert display value to stored value (e.g., "value * 86400" for days to seconds)
    )
    repeat: Optional[Union[int, str]] = (
        None  # Number of times to repeat writing the value at consecutive offsets (e.g., 0x14FF or 5375)
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
                    code = compile(v, "<offset_expression>", "eval")
                    result = eval(code, {"__builtins__": {}}, {})
                    if not isinstance(result, (int, float)):
                        raise ValueError(
                            f"Offset expression must evaluate to a number: {v}"
                        )
                    return int(result)
                except SyntaxError:
                    raise ValueError(
                        f"Invalid offset expression syntax: {v}. Must be valid arithmetic like '0x12345 + 4'"
                    )
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
                if len(part) != 2:
                    raise ValueError(
                        f"Invalid hex byte in pattern: {part} (must be exactly 2 hex digits)"
                    )
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

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: Optional[str]) -> Optional[str]:
        """Validate type field"""
        if v is None:
            return "int"
        v = v.strip().lower()
        if v not in ("int", "double", "float"):
            raise ValueError(f"Invalid type: {v}. Must be 'int', 'double', or 'float'")
        return v

    @field_validator("repeat")
    @classmethod
    def validate_repeat(cls, v: Optional[Union[int, str]]) -> Optional[int]:
        """Validate repeat field - must be a positive integer"""
        if v is None:
            return None
        if isinstance(v, int):
            if v <= 0:
                raise ValueError(f"Repeat must be a positive integer, got {v}")
            return v
        if isinstance(v, str):
            v = v.strip()
            try:
                # Try parsing as hex (0x prefix) or decimal
                result = int(v, 0)  # 0 allows auto-detection of hex (0x) or decimal
                if result <= 0:
                    raise ValueError(f"Repeat must be a positive integer, got {result}")
                return result
            except ValueError:
                raise ValueError(
                    f"Invalid repeat value: {v}. Must be a positive integer or hex value like '0x14FF'"
                )
        raise ValueError(f"Invalid repeat type: {type(v)}. Must be int or str")

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
    group: Optional[str] = None
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
            for i, change in enumerate(v):
                if change.size is not None and change.value is not None:
                    raise ValueError(
                        f"Editable patch change {i} cannot have both size and value"
                    )
                if change.size is None and change.value is None:
                    raise ValueError(
                        f"Editable patch change {i} must specify either size (for editable) or value (for fixed)"
                    )

            # Note: Editable changes can have different sizes when using formulas
            # Each change will use its own size when reading/writing
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
    enable_binary_backups: bool = True


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
        self.enable_binary_backups: bool = True
        self.all_patches: List[Patch] = []  # Store all patches for filtering
        self.patch_widgets: Dict[
            str, QGroupBox
        ] = {}  # Map patch name to its widget for filtering
        self.group_widgets: Dict[
            str, QGroupBox
        ] = {}  # Map group name to its widget for filtering

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

    def _value_to_bytes(self, value: Union[int, float], change: PatchChange) -> bytes:
        """Convert a value to bytes based on change configuration.

        Args:
            value: The value to convert
            change: PatchChange with size and type information

        Returns:
            Bytes representation of the value

        Raises:
            ValueError: If value is out of range or conversion fails
        """
        data_type = change.type or "int"
        size = change.size

        if data_type == "double":
            if size != 8:
                raise ValueError(f"Double type requires size 8, got {size}")
            return struct.pack("<d", float(value))
        elif data_type == "float":
            if size != 4:
                raise ValueError(f"Float type requires size 4, got {size}")
            return struct.pack("<f", float(value))
        else:
            # Integer type
            int_value = int(value)
            max_value = (1 << (size * 8)) - 1
            if int_value > max_value:
                raise ValueError(
                    f"Value {int_value} exceeds maximum for {size} byte(s)"
                )
            if int_value < 0:
                raise ValueError(
                    f"Value {int_value} is negative. Only unsigned integers are supported."
                )
            return int_value.to_bytes(size, byteorder="little", signed=False)

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

            # Optimize: find first non-wildcard byte to start search
            first_fixed_byte = None
            first_fixed_index = 0
            for idx, (byte_val, is_wildcard) in enumerate(search_pattern):
                if not is_wildcard:
                    first_fixed_byte = byte_val
                    first_fixed_index = idx
                    break

            # Search for pattern
            pattern_len = len(search_pattern)

            if first_fixed_byte is not None:
                # Optimized search: start by finding the first fixed byte
                for i in range(len(binary_data) - pattern_len + 1):
                    if binary_data[i + first_fixed_index] == first_fixed_byte:
                        # Potential match, check full pattern
                        match = True
                        for j, (expected_byte, is_wildcard) in enumerate(
                            search_pattern
                        ):
                            if not is_wildcard and binary_data[i + j] != expected_byte:
                                match = False
                                break

                        if match:
                            # Found match at RVA i, convert to virtual address
                            return binary.OPTIONAL_HEADER.ImageBase + i
            else:
                # All wildcards - shouldn't happen, but handle it
                return binary.OPTIONAL_HEADER.ImageBase

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

    def _iter_change_offsets(
        self, change: PatchChange, binary: pefile.PE, value_size: int
    ) -> List[int]:
        """Generate list of offsets for a change, handling repeat.

        Args:
            change: The patch change
            binary: PE file object
            value_size: Size of the value in bytes (for calculating repeat offsets)

        Returns:
            List of virtual address offsets. Returns empty list if base offset
            cannot be resolved.
        """
        base_offset = self._resolve_change_offset(change, binary)
        if base_offset is None:
            return []

        if change.repeat is not None:
            return [base_offset + (i * value_size) for i in range(change.repeat)]
        return [base_offset]

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

    def _build_locations_label(
        self, patch: Patch, binaries_loaded: bool, show_editable_indicator: bool = False
    ) -> QLabel:
        """Build a label showing location information for a patch.

        Args:
            patch: The patch to build location info for
            binaries_loaded: Whether required binaries are loaded
            show_editable_indicator: Whether to show [editable]/[fixed] indicators

        Returns:
            QLabel with formatted location text
        """
        location_parts = []
        for c in patch.changes:
            if c.offset is not None:
                part = f"{c.offset:#x}"
            elif c.pattern is not None:
                part = f"pattern: {c.pattern}"
                if binaries_loaded:
                    change_binary_name = self._get_change_binary(c, patch.file)
                    if change_binary_name in self.binary_files:
                        _, change_binary = self.binary_files[change_binary_name]
                        resolved = self._resolve_change_offset(c, change_binary)
                        if resolved is not None:
                            part += f" → {resolved:#x}"
            else:
                part = "unknown"

            if show_editable_indicator:
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
        return locations_label

    def _update_progress(
        self,
        progress: QProgressDialog,
        processed_count: int,
        total_patches: int,
    ) -> bool:
        """Update progress dialog and check for cancellation.

        Args:
            progress: The progress dialog to update
            processed_count: Number of patches processed so far
            total_patches: Total number of patches to process

        Returns:
            True if cancelled, False to continue
        """
        progress.setValue(processed_count)
        progress.setLabelText(
            f"Applying patches... ({processed_count}/{total_patches})"
        )
        # Only process events every 5 patches or on last patch to reduce overhead
        if processed_count % 5 == 0 or processed_count == total_patches:
            QApplication.processEvents()
        if progress.wasCanceled():
            progress.close()
            QMessageBox.warning(
                self,
                "Cancelled",
                "Patch operation was cancelled.",
            )
            return True
        return False

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
                        self.enable_binary_backups = settings.enable_binary_backups
                    else:
                        self.config_dir = None
                        self.saved_selected_config = None
                        self.enable_binary_backups = True
            except (yaml.YAMLError, ValueError, KeyError) as e:
                QMessageBox.warning(self, "Warning", f"Failed to load settings: {e}")
                self.config_dir = None
                self.saved_selected_config = None
                self.enable_binary_backups = True
            except Exception as e:
                QMessageBox.warning(
                    self, "Warning", f"Unexpected error loading settings: {e}"
                )
                self.config_dir = None
                self.saved_selected_config = None
                self.enable_binary_backups = True
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
                enable_binary_backups=self.enable_binary_backups,
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

    def get_binary_backup_path(self, binary_name: str) -> Path:
        """Generate full binary backup file path.

        Args:
            binary_name: Name of the binary to get backup path for

        Returns:
            Path object pointing to the full binary backup file
        """
        return self.backup_dir / f"{binary_name}_backup.bin"

    def binary_backup_exists(self, binary_name: str) -> bool:
        """Check if a full binary backup exists.

        Args:
            binary_name: Name of the binary to check

        Returns:
            True if binary backup file exists, False otherwise
        """
        backup_path = self.get_binary_backup_path(binary_name)
        return backup_path.exists()

    def backup_binary_file(self, binary_name: str) -> bool:
        """Backup the whole binary file before patching.

        Args:
            binary_name: Name of the binary to backup

        Returns:
            True if backup was successful, False otherwise

        Note:
            Only creates backup if it doesn't already exist. Shows warnings
            if backup fails but does not interrupt execution.
        """
        if binary_name not in self.binary_files:
            return False

        # Ensure backup directory exists
        try:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
        except (IOError, OSError) as e:
            QMessageBox.warning(
                self,
                "Warning",
                f"Failed to create backup directory: {e}",
            )
            return False

        backup_path = self.get_binary_backup_path(binary_name)

        # Only backup if no backup exists
        if backup_path.exists():
            return True

        binary_path, _ = self.binary_files[binary_name]

        try:
            shutil.copy2(binary_path, backup_path)
            return True
        except (IOError, OSError, shutil.Error) as e:
            QMessageBox.warning(
                self,
                "Warning",
                f"Failed to create binary backup for {binary_name}: {e}",
            )
            return False

    def restore_binary_file(self, binary_name: str) -> bool:
        """Restore a binary file from backup.

        Args:
            binary_name: Name of the binary to restore

        Returns:
            True if restoration was successful, False otherwise

        Note:
            Shows warnings if backup doesn't exist or restoration fails.
        """
        if binary_name not in self.binary_files:
            QMessageBox.warning(
                self,
                "Warning",
                f"Binary {binary_name} is not loaded. Please load it first.",
            )
            return False

        backup_path = self.get_binary_backup_path(binary_name)

        if not backup_path.exists():
            QMessageBox.warning(
                self,
                "Warning",
                f"No backup found for {binary_name}!",
            )
            return False

        binary_path, _ = self.binary_files[binary_name]

        try:
            shutil.copy2(backup_path, binary_path)
            # Reload the binary after restoration
            self._close_binary(binary_name)
            binary = pefile.PE(binary_path, fast_load=True)
            self.binary_files[binary_name] = (binary_path, binary)
            return True
        except (IOError, OSError, shutil.Error) as e:
            QMessageBox.warning(
                self,
                "Warning",
                f"Failed to restore binary {binary_name}: {e}",
            )
            return False
        except pefile.PEFormatError as e:
            QMessageBox.warning(
                self,
                "Warning",
                f"Restored file is not a valid PE file: {e}",
            )
            return False

    def restore_all_binaries(self) -> None:
        """Restore all loaded binaries from their backups.

        Shows a confirmation dialog before restoring, and displays
        success/error messages for each binary.
        """
        if not self.binary_files:
            QMessageBox.information(
                self,
                "Info",
                "No binaries are currently loaded.",
            )
            return

        # Check which binaries have backups
        binaries_with_backups = [
            name for name in self.binary_files.keys() if self.binary_backup_exists(name)
        ]

        if not binaries_with_backups:
            QMessageBox.information(
                self,
                "Info",
                "No backups found for any loaded binaries.",
            )
            return

        # Confirm restoration
        count = len(binaries_with_backups)
        reply = QMessageBox.question(
            self,
            "Confirm Restore",
            f"Restore {count} {'binary' if count == 1 else 'binaries'} from backup?\n\n"
            f"This will overwrite the current files: {', '.join(binaries_with_backups)}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        # Restore each binary
        restored = []
        failed = []
        for binary_name in binaries_with_backups:
            if self.restore_binary_file(binary_name):
                restored.append(binary_name)
            else:
                failed.append(binary_name)

        # Update UI after restoration
        if self.current_config:
            self.all_patches = self.current_config.patches
            self.update_patches_ui(self.current_config.patches)
        self.update_patch_button_state()
        self.update_restore_button_state()

        # Show results
        if restored and not failed:
            count = len(restored)
            QMessageBox.information(
                self,
                "Success",
                f"Successfully restored {count} {'binary' if count == 1 else 'binaries'}:\n"
                + "\n".join(restored),
            )
        elif restored and failed:
            QMessageBox.warning(
                self,
                "Partial Success",
                f"Restored: {', '.join(restored)}\n\nFailed: {', '.join(failed)}",
            )
        elif failed:
            QMessageBox.warning(
                self,
                "Error",
                f"Failed to restore: {', '.join(failed)}",
            )

    def update_restore_button_state(self) -> None:
        """Enable restore button if at least one loaded binary has a backup.

        Checks all currently loaded binaries to see if any have backups.
        """
        if not hasattr(self, "restore_btn"):
            return

        has_backup = any(
            self.binary_backup_exists(name) for name in self.binary_files.keys()
        )
        self.restore_btn.setEnabled(has_backup)

    def is_binary_patched(self, binary_name: str) -> bool:
        """Check if binary has been patched (backup exists).

        Args:
            binary_name: Name of the binary to check

        Returns:
            True if backup file exists, False otherwise
        """
        backup_path = self.get_backup_path(binary_name)
        return backup_path.exists()

    def _normalize_offset(self, offset: Union[int, str]) -> int:
        """Normalize offset to integer for comparison.

        Handles both integer and hex string formats (e.g., "0x12345").

        Args:
            offset: Offset as int or hex string

        Returns:
            Integer offset value

        Raises:
            ValueError: If offset is not an int or str
        """
        if isinstance(offset, int):
            return offset
        if isinstance(offset, str):
            # Handle hex string format
            if offset.startswith("0x") or offset.startswith("0X"):
                return int(offset, 16)
            # Try parsing as decimal
            return int(offset)
        raise ValueError(f"Invalid offset type: {type(offset)}. Must be int or str.")

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
            Offsets are saved as hex addresses (e.g., "0x12345").
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
                    # Normalize offsets to integers for comparison (handle both hex strings and ints)
                    existing_offsets = {
                        self._normalize_offset(item["offset"])
                        for item in existing_data
                        if "offset" in item
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
            # Determine size for this change
            size = (
                len(bytes.fromhex(change.value))
                if change.value is not None
                else change.size
            )
            if size is None:
                continue

            # Get all offsets for this change (handles repeat)
            offsets = self._iter_change_offsets(change, binary, size)
            if not offsets:
                QMessageBox.warning(
                    self,
                    "Warning",
                    "Failed to resolve offset for change: pattern not found or invalid",
                )
                continue

            for current_offset in offsets:
                if current_offset in existing_offsets:
                    continue
                addr = self._offset_to_rva(current_offset, binary)
                try:
                    original_bytes = binary.get_data(addr, size)
                    new_data.append(
                        {
                            "offset": f"{current_offset:#x}",
                            "value": original_bytes.hex(),
                        }
                    )
                    existing_offsets.add(current_offset)
                except (
                    pefile.PEFormatError,
                    ValueError,
                    IndexError,
                    AttributeError,
                ) as e:
                    QMessageBox.warning(
                        self,
                        "Warning",
                        f"Failed to read original bytes at offset {current_offset:#x}: {e}",
                    )
                except Exception as e:
                    QMessageBox.warning(
                        self,
                        "Warning",
                        f"Unexpected error reading bytes at offset {current_offset:#x}: {e}",
                    )

        # Merge existing and new data
        merged_data = existing_data + new_data

        try:
            with open(backup_path, "w", encoding="utf-8") as f:
                yaml.dump(merged_data, f, default_flow_style=False)
        except (IOError, OSError, yaml.YAMLError) as e:
            QMessageBox.warning(self, "Warning", f"Failed to save backup: {e}")

    def is_patch_applied(self, patch: Patch) -> bool:
        """Check if a patch is currently applied to the binary.

        Verifies that all changes in the patch match the current binary state.
        Returns True only if all patch locations have the expected patched values.

        Args:
            patch: The patch to check

        Returns:
            True if the patch is currently applied, False otherwise
        """
        try:
            changes_by_binary = self._group_changes_by_binary(patch)
        except ValueError:
            return False

        required_binaries = set(changes_by_binary.keys())

        # Check if all binaries are loaded
        if any(b not in self.binary_files for b in required_binaries):
            return False

        # Check if all changes match the patched state
        for binary_name, changes in changes_by_binary.items():
            _, binary = self.binary_files[binary_name]
            for change in changes:
                if change.value is None:
                    continue

                desired = bytes.fromhex(change.value)
                offsets = self._iter_change_offsets(change, binary, len(desired))
                if not offsets:
                    return False

                for current_offset in offsets:
                    addr = self._offset_to_rva(current_offset, binary)
                    try:
                        current = binary.get_data(addr, len(desired))
                        if current != desired:
                            return False
                    except Exception:
                        return False

        return True

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
            Handles offsets in both hex string format (e.g., "0x12345") and integer format.
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
                # Normalize offset (handle both hex strings and integers)
                offset = self._normalize_offset(change["offset"])
                addr = self._offset_to_rva(offset, binary)
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
        progress = None
        total_patches = 0
        try:
            # Collect all binaries that will be modified
            binaries_to_modify = set()
            for patch_name, patch in self.patches.items():
                try:
                    changes_by_binary = self._group_changes_by_binary(patch)
                except ValueError:
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

                # For editable patches, check if they will modify anything
                if patch.editable:
                    if patch.widget is None:
                        continue
                    new_value_text = patch.widget.text().strip()
                    if not new_value_text:
                        # Empty value might restore, but we'll include it to be safe
                        binaries_to_modify.update(required_binaries)
                    else:
                        binaries_to_modify.update(required_binaries)
                else:
                    # For checkbox patches, include if checked
                    if patch.widget is not None and patch.widget.isChecked():
                        binaries_to_modify.update(required_binaries)

            # Count patches that will be processed for progress bar
            patches_to_process = []
            for patch_name, patch in self.patches.items():
                try:
                    changes_by_binary = self._group_changes_by_binary(patch)
                except ValueError:
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

                # Check if this patch will be processed
                will_process = False
                if patch.editable:
                    if patch.widget is not None:
                        new_value_text = patch.widget.text().strip()
                        if new_value_text:  # Has a value to apply
                            will_process = True
                        # Empty value might restore, but we'll include it
                        if (
                            not new_value_text
                            and required_binaries
                            and self.is_binary_patched(list(required_binaries)[0])
                        ):
                            will_process = True
                else:
                    # For checkbox patches, include if checked
                    if patch.widget is not None and patch.widget.isChecked():
                        will_process = True
                    # Or if it needs to be restored
                    elif self.is_patch_applied(patch):
                        will_process = True

                if will_process:
                    patches_to_process.append((patch_name, patch))

            # Create progress dialog
            total_patches = len(patches_to_process)
            if total_patches > 0:
                progress = QProgressDialog(
                    "Applying patches...", "Cancel", 0, total_patches, self
                )
                progress.setWindowModality(Qt.WindowModality.WindowModal)
                progress.setMinimumDuration(0)  # Show immediately
                progress.setValue(0)
                QApplication.processEvents()  # Update UI

            # Backup whole binaries if enabled and no backup exists
            backed_up_binaries = []
            if self.enable_binary_backups:
                for binary_name in binaries_to_modify:
                    if not self.binary_backup_exists(binary_name):
                        if self.backup_binary_file(binary_name):
                            backed_up_binaries.append(binary_name)

            # Collect all changes that need backing up (batch backup operations)
            # This avoids reading/writing backup files multiple times
            changes_to_backup: Dict[str, List[PatchChange]] = {}

            for patch_name, patch in self.patches.items():
                try:
                    changes_by_binary = self._group_changes_by_binary(patch)
                except ValueError:
                    continue

                required_binaries = set(changes_by_binary.keys())

                # Check if all binaries are loaded
                if any(b not in self.binary_files for b in required_binaries):
                    continue

                # Skip if patch widget is disabled
                if (
                    patch.editable
                    and patch.widget is not None
                    and not patch.widget.isEnabled()
                ):
                    continue

                # Collect changes that need backing up
                if patch.editable:
                    if patch.widget is not None:
                        new_value_text = patch.widget.text().strip()
                        if new_value_text:  # Has a value to apply, needs backup
                            for binary_name, changes in changes_by_binary.items():
                                if binary_name not in changes_to_backup:
                                    changes_to_backup[binary_name] = []
                                changes_to_backup[binary_name].extend(changes)
                else:
                    # Non-editable patch - backup if checked
                    if patch.widget is not None and patch.widget.isChecked():
                        for binary_name, changes in changes_by_binary.items():
                            if binary_name not in changes_to_backup:
                                changes_to_backup[binary_name] = []
                            changes_to_backup[binary_name].extend(changes)

            # Batch save all backups (one file write per binary instead of one per patch)
            for binary_name, changes in changes_to_backup.items():
                self.save_original_bytes(binary_name, changes)

            modified_binaries = set()
            processed_count = 0

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

                        # Original bytes already backed up in batch above
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
                                processed_count += 1
                                if total_patches > 0 and self._update_progress(
                                    progress, processed_count, total_patches
                                ):
                                    return
                                continue

                            # Get first editable change for input_formula (each change uses its own size when writing)
                            first_editable_change = editable_changes[0]
                            data_type = first_editable_change.type or "int"

                            # Parse input value based on type
                            try:
                                if data_type in ("double", "float"):
                                    display_value = float(new_value_text)
                                else:
                                    display_value = int(new_value_text)
                            except ValueError:
                                QMessageBox.warning(
                                    self,
                                    "Error",
                                    f"Invalid {data_type} value: {new_value_text}",
                                )
                                continue

                            # Convert display value to stored value using input_formula if specified
                            stored_value_int = display_value
                            if first_editable_change.input_formula:
                                try:
                                    stored_value_int = self._evaluate_formula(
                                        first_editable_change.input_formula,
                                        display_value,
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

                                    # Calculate final value using formula if specified
                                    try:
                                        final_value_calc = self._evaluate_formula(
                                            change.formula, stored_value_int
                                        )
                                        final_value = self._value_to_bytes(
                                            final_value_calc, change
                                        )
                                        addr = self._offset_to_rva(
                                            resolved_offset, binary
                                        )
                                        binary.set_bytes_at_rva(addr, final_value)
                                    except ValueError as e:
                                        QMessageBox.warning(
                                            self,
                                            "Error",
                                            f"Error at offset {resolved_offset:#x}: {e}",
                                        )
                                        success = False
                                        break
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
                                        offsets = self._iter_change_offsets(
                                            change, binary, len(final_value)
                                        )
                                        for offset in offsets:
                                            addr = self._offset_to_rva(offset, binary)
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
                            processed_count += 1
                            if total_patches > 0 and self._update_progress(
                                progress, processed_count, total_patches
                            ):
                                return
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
                    # Non-editable patch
                    if patch.widget is not None and patch.widget.isChecked():
                        # Original bytes already backed up in batch above
                        for binary_name, changes in changes_by_binary.items():
                            _, binary = self.binary_files[binary_name]
                            for change in changes:
                                if change.value is None:
                                    continue
                                final_value = bytes.fromhex(change.value)
                                offsets = self._iter_change_offsets(
                                    change, binary, len(final_value)
                                )
                                if not offsets:
                                    QMessageBox.warning(
                                        self,
                                        "Error",
                                        f"Failed to resolve offset for change in patch {patch_name}: pattern not found or invalid",
                                    )
                                    continue
                                for offset in offsets:
                                    addr = self._offset_to_rva(offset, binary)
                                    binary.set_bytes_at_rva(addr, final_value)
                            modified_binaries.add(binary_name)
                        processed_count += 1
                        if total_patches > 0 and self._update_progress(
                            progress, processed_count, total_patches
                        ):
                            return
                    else:
                        # Only restore if the patch was previously applied (currently active)
                        if self.is_patch_applied(patch):
                            for binary_name in required_binaries:
                                if self.restore_original_bytes(binary_name):
                                    modified_binaries.add(binary_name)
                            processed_count += 1
                            if total_patches > 0 and self._update_progress(
                                progress, processed_count, total_patches
                            ):
                                return

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

            # Build success message
            success_parts = []
            if modified_binaries:
                success_parts.append(
                    f"Patches applied to {len(modified_binaries)} binary(ies) successfully!"
                )
            if backed_up_binaries:
                backup_paths = [
                    str(self.get_binary_backup_path(name))
                    for name in backed_up_binaries
                ]
                backup_dir_abs = str(self.backup_dir.resolve())
                success_parts.append(
                    f"Backups created: {', '.join(backed_up_binaries)}\n"
                    f"Location: {backup_dir_abs}"
                )

            # Close progress dialog
            if progress is not None:
                progress.setValue(total_patches)
                QApplication.processEvents()  # Ensure final update is shown
                progress.close()

            if success_parts:
                QMessageBox.information(self, "Success", "\n\n".join(success_parts))
            else:
                QMessageBox.information(self, "Info", "No changes to apply.")

            # Update restore button state in case backups were created
            self.update_restore_button_state()
        except Exception as e:
            # Close progress dialog if it exists
            if progress is not None:
                progress.close()
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
                    self.all_patches = self.current_config.patches
                    self.update_patches_ui(self.current_config.patches)
                self.update_patch_button_state()
                self.update_restore_button_state()

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
            patch.widget is not None and patch.widget.isEnabled()
            for patch in self.patches.values()
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
        if hasattr(self, "patch_widgets"):
            self.patch_widgets.clear()
        if hasattr(self, "group_widgets"):
            self.group_widgets.clear()
        self.clear_layout(self.files_layout)

        # Close all binary files before clearing
        for binary_name in list(self.binary_files.keys()):
            self._close_binary(binary_name)

        self.update_restore_button_state()

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

            # Clear filter when config changes
            if hasattr(self, "patch_filter"):
                self.patch_filter.clear()

            self.update_binary_ui(self.current_config.files)

            # Show patches (disabled initially)
            self.all_patches = self.current_config.patches
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

    def _filter_patches(self) -> None:
        """Filter patches based on the filter text field.

        Filters patches by name, description, or group name (case-insensitive).
        Shows/hides patch widgets without recreating them to preserve state.
        """
        if not hasattr(self, "all_patches") or not self.all_patches:
            return

        filter_text = self.patch_filter.text().strip().lower()

        # Determine which patches match the filter
        matching_patches = set()
        if not filter_text:
            # Show all patches if filter is empty
            matching_patches = {patch.name for patch in self.all_patches}
        else:
            # Filter patches by name, description, or group
            for patch in self.all_patches:
                # Check name
                if filter_text in patch.name.lower():
                    matching_patches.add(patch.name)
                    continue

                # Check description
                if patch.description and filter_text in patch.description.lower():
                    matching_patches.add(patch.name)
                    continue

                # Check group
                group_name = patch.group if patch.group else "Ungrouped"
                if filter_text in group_name.lower():
                    matching_patches.add(patch.name)

        # Show/hide patch widgets based on filter
        # Only filter if widgets have been created
        if not self.patch_widgets:
            return

        for patch_name, patch_widget in self.patch_widgets.items():
            if patch_name in matching_patches:
                patch_widget.setVisible(True)
            else:
                patch_widget.setVisible(False)

        # Show/hide group boxes based on whether they have visible patches
        for group_name, group_box in self.group_widgets.items():
            # Check if any patch in this group is visible
            has_visible_patch = False
            for patch in self.all_patches:
                patch_group_name = patch.group if patch.group else "Ungrouped"
                if patch_group_name == group_name and patch.name in matching_patches:
                    has_visible_patch = True
                    break

            group_box.setVisible(has_visible_patch)

    def update_patches_ui(self, patches: List[Patch]):
        """Update the patches UI with the given list of patches.

        Clears existing patches and creates new UI elements for each patch:
        - Groups patches by their 'group' field (or 'Ungrouped' if not specified)
        - Creates group boxes for each patch group in a 2-column grid
        - For editable patches: Creates text input widgets with current values
        - For checkbox patches: Creates checkboxes with current patch state
        - Shows location information and required binaries status
        - Enables/disables patches based on whether required binaries are loaded

        Args:
            patches: List of Patch objects to display in the UI

        Note:
            Patch groups are arranged in a grid with 2 columns. Shows warnings
            for patches that fail to process but continues with others.
        """
        self.clear_layout(self.patches_layout)
        self.patches.clear()
        self.patch_widgets.clear()
        self.group_widgets.clear()

        # Group patches by their 'group' field
        grouped_patches: Dict[str, List[Patch]] = {}
        for patch in patches:
            group_name = patch.group if patch.group else "Ungrouped"
            grouped_patches.setdefault(group_name, []).append(patch)

        # Create UI for each group
        for group_idx, (group_name, group_patches) in enumerate(
            sorted(grouped_patches.items())
        ):
            # Create a group box for this patch group
            group_box = QGroupBox(group_name)
            group_box.setSizePolicy(
                QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum
            )
            self.group_widgets[group_name] = group_box
            group_layout = QVBoxLayout()
            group_layout.setContentsMargins(5, 5, 5, 5)

            # Process each patch in this group
            for patch in group_patches:
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
                        editable_changes = [
                            c for c in patch.changes if c.size is not None
                        ]
                        fixed_changes = [
                            c for c in patch.changes if c.value is not None
                        ]

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
                                        # Special handling for split 64-bit values (high byte + low 32 bits)
                                        # Pattern: first change is 4 bytes with formula "value & 0xFFFFFFFF",
                                        # second change is 1 byte with formula "value >> 32"
                                        is_split_64bit = (
                                            len(editable_changes) >= 2
                                            and first_editable_change.size == 4
                                            and first_editable_change.formula
                                            == "value & 0xFFFFFFFF"
                                            and editable_changes[1].size == 1
                                            and editable_changes[1].formula
                                            == "value >> 32"
                                        )

                                        if is_split_64bit:
                                            # Read low 32 bits from first change
                                            first_offset = self._resolve_change_offset(
                                                first_editable_change, binary
                                            )
                                            if first_offset is None:
                                                raise ValueError(
                                                    "Failed to resolve offset for first editable change"
                                                )
                                            first_addr = self._offset_to_rva(
                                                first_offset, binary
                                            )
                                            low_32_bits_bytes = binary.get_data(
                                                first_addr, 4
                                            )
                                            low_32_bits = int.from_bytes(
                                                low_32_bits_bytes, byteorder="little"
                                            )

                                            # Read high byte from second change
                                            second_editable_change = editable_changes[1]
                                            second_binary_name = (
                                                self._get_change_binary(
                                                    second_editable_change, patch.file
                                                )
                                            )
                                            _, second_binary = self.binary_files[
                                                second_binary_name
                                            ]
                                            second_offset = self._resolve_change_offset(
                                                second_editable_change, second_binary
                                            )
                                            if second_offset is None:
                                                raise ValueError(
                                                    "Failed to resolve offset for second editable change"
                                                )
                                            second_addr = self._offset_to_rva(
                                                second_offset, second_binary
                                            )
                                            high_byte_bytes = second_binary.get_data(
                                                second_addr, 1
                                            )
                                            high_byte = int.from_bytes(
                                                high_byte_bytes, byteorder="little"
                                            )

                                            # Reconstruct full 64-bit value
                                            current = (high_byte << 32) | low_32_bits
                                        else:
                                            # Normal handling for single-location values
                                            first_offset = self._resolve_change_offset(
                                                first_editable_change, binary
                                            )
                                            if first_offset is None:
                                                raise ValueError(
                                                    "Failed to resolve offset for first editable change"
                                                )
                                            addr = self._offset_to_rva(
                                                first_offset, binary
                                            )
                                            data_bytes = binary.get_data(
                                                addr, first_editable_change.size
                                            )
                                            data_type = (
                                                first_editable_change.type or "int"
                                            )
                                            if data_type == "double":
                                                if first_editable_change.size != 8:
                                                    raise ValueError(
                                                        f"Double type requires size 8, but got {first_editable_change.size}"
                                                    )
                                                current = struct.unpack(
                                                    "<d", data_bytes
                                                )[0]
                                            elif data_type == "float":
                                                if first_editable_change.size != 4:
                                                    raise ValueError(
                                                        f"Float type requires size 4, but got {first_editable_change.size}"
                                                    )
                                                current = struct.unpack(
                                                    "<f", data_bytes
                                                )[0]
                                            else:
                                                current = int.from_bytes(
                                                    data_bytes, byteorder="little"
                                                )

                                        # Verify all editable changes have the same value
                                        # Note: If sizes differ, we can't directly compare raw values,
                                        # so we'll mark as different and use the first change's value for display
                                        # For split 64-bit values, we reconstruct the value from each pair
                                        all_same = True
                                        if is_split_64bit:
                                            # For split 64-bit values, verify all pairs have the same combined value
                                            for i in range(2, len(editable_changes), 2):
                                                if i + 1 >= len(editable_changes):
                                                    all_same = False
                                                    break
                                                low_change = editable_changes[i]
                                                high_change = editable_changes[i + 1]

                                                if (
                                                    low_change.size != 4
                                                    or high_change.size != 1
                                                ):
                                                    all_same = False
                                                    break

                                                # Read low 32 bits
                                                low_binary_name = (
                                                    self._get_change_binary(
                                                        low_change, patch.file
                                                    )
                                                )
                                                _, low_binary = self.binary_files[
                                                    low_binary_name
                                                ]
                                                low_offset = (
                                                    self._resolve_change_offset(
                                                        low_change, low_binary
                                                    )
                                                )
                                                if low_offset is None:
                                                    all_same = False
                                                    break
                                                low_addr = self._offset_to_rva(
                                                    low_offset, low_binary
                                                )
                                                low_bytes = low_binary.get_data(
                                                    low_addr, 4
                                                )
                                                pair_low = int.from_bytes(
                                                    low_bytes, byteorder="little"
                                                )

                                                # Read high byte
                                                high_binary_name = (
                                                    self._get_change_binary(
                                                        high_change, patch.file
                                                    )
                                                )
                                                _, high_binary = self.binary_files[
                                                    high_binary_name
                                                ]
                                                high_offset = (
                                                    self._resolve_change_offset(
                                                        high_change, high_binary
                                                    )
                                                )
                                                if high_offset is None:
                                                    all_same = False
                                                    break
                                                high_addr = self._offset_to_rva(
                                                    high_offset, high_binary
                                                )
                                                high_bytes = high_binary.get_data(
                                                    high_addr, 1
                                                )
                                                pair_high = int.from_bytes(
                                                    high_bytes, byteorder="little"
                                                )

                                                # Reconstruct and compare
                                                pair_value = (
                                                    pair_high << 32
                                                ) | pair_low
                                                if pair_value != current:
                                                    all_same = False
                                                    break
                                        else:
                                            # Normal comparison for non-split values
                                            for change in editable_changes[1:]:
                                                # If sizes differ, we can't directly compare values
                                                if (
                                                    change.size
                                                    != first_editable_change.size
                                                ):
                                                    all_same = False
                                                    break
                                                change_binary_name = (
                                                    self._get_change_binary(
                                                        change, patch.file
                                                    )
                                                )
                                                _, change_binary = self.binary_files[
                                                    change_binary_name
                                                ]
                                                change_offset = (
                                                    self._resolve_change_offset(
                                                        change, change_binary
                                                    )
                                                )
                                                if change_offset is None:
                                                    all_same = False
                                                    break
                                                change_addr = self._offset_to_rva(
                                                    change_offset, change_binary
                                                )
                                                change_data_bytes = (
                                                    change_binary.get_data(
                                                        change_addr, change.size
                                                    )
                                                )
                                                change_data_type = change.type or "int"
                                                if change_data_type == "double":
                                                    if change.size != 8:
                                                        all_same = False
                                                        break
                                                    change_value = struct.unpack(
                                                        "<d", change_data_bytes
                                                    )[0]
                                                elif change_data_type == "float":
                                                    if change.size != 4:
                                                        all_same = False
                                                        break
                                                    change_value = struct.unpack(
                                                        "<f", change_data_bytes
                                                    )[0]
                                                else:
                                                    change_value = int.from_bytes(
                                                        change_data_bytes,
                                                        byteorder="little",
                                                    )
                                                # For floats/doubles, use approximate comparison due to floating point precision
                                                first_type = (
                                                    first_editable_change.type or "int"
                                                )
                                                if change_data_type in (
                                                    "double",
                                                    "float",
                                                ) or first_type in ("double", "float"):
                                                    if (
                                                        abs(change_value - current)
                                                        > 1e-10
                                                    ):
                                                        all_same = False
                                                        break
                                                else:
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

                        locations_label = self._build_locations_label(
                            patch, binaries_loaded, show_editable_indicator=True
                        )
                        patch_layout.addWidget(locations_label)
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
                                    _, change_binary = self.binary_files[
                                        change_binary_name
                                    ]
                                    desired = bytes.fromhex(change.value)
                                    offsets = self._iter_change_offsets(
                                        change, change_binary, len(desired)
                                    )
                                    if not offsets:
                                        all_match = False
                                        break
                                    for offset in offsets:
                                        addr = self._offset_to_rva(
                                            offset, change_binary
                                        )
                                        current = change_binary.get_data(
                                            addr, len(desired)
                                        )
                                        if current != desired:
                                            all_match = False
                                            break
                                    if not all_match:
                                        break
                                if all_match:
                                    value_widget.setChecked(True)
                            except Exception:
                                pass

                        patch_layout.addWidget(value_widget)

                        # Store widget reference so apply_patches can check if it's checked
                        patch.widget = value_widget

                        locations_label = self._build_locations_label(
                            patch, binaries_loaded
                        )
                        patch_layout.addWidget(locations_label)

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
                    # Add patch to the group layout
                    group_layout.addWidget(patch_group)
                    self.patches[patch.name] = patch
                    self.patch_widgets[patch.name] = patch_group
                except Exception as e:
                    QMessageBox.warning(
                        self, "Error", f"Error processing patch {patch.name}: {e}"
                    )
                    continue

            # Set layout for the group box and add to vertical layout
            group_box.setLayout(group_layout)
            self.patches_layout.addWidget(group_box)

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
        self.update_restore_button_state()

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

        # Filter text field
        filter_layout = QHBoxLayout()
        filter_label = QLabel("Filter:")
        self.patch_filter = QLineEdit()
        self.patch_filter.setPlaceholderText(
            "Search patches by name, description, or group..."
        )
        self.patch_filter.textChanged.connect(self._filter_patches)
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.patch_filter)
        patches_layout.addLayout(filter_layout)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
        """)
        self.patches_widget = QWidget()
        self.patches_layout = QVBoxLayout(self.patches_widget)
        self.patches_layout.setSpacing(10)
        scroll.setWidget(self.patches_widget)
        patches_layout.addWidget(scroll)
        patches_group.setLayout(patches_layout)
        # -----------------------------------------
        # Binary backup checkbox and restore button
        backup_restore_layout = QHBoxLayout()
        self.binary_backup_checkbox = QCheckBox("Create backup before patching")
        self.binary_backup_checkbox.setToolTip(
            "Backup the whole binary file before patching (only if no backup exists)"
        )
        self.binary_backup_checkbox.setChecked(self.enable_binary_backups)
        self.binary_backup_checkbox.stateChanged.connect(self._on_binary_backup_changed)

        self.restore_btn = QPushButton("Restore Binaries")
        self.restore_btn.setToolTip(
            "Restore all loaded binaries from their backups (only enabled if backups exist)"
        )
        self.restore_btn.clicked.connect(self.restore_all_binaries)
        self.restore_btn.setEnabled(False)

        backup_restore_layout.addWidget(self.binary_backup_checkbox)
        backup_restore_layout.addStretch()
        backup_restore_layout.addWidget(self.restore_btn)

        # -----------------------------------------
        # Patch button
        self.patch_btn = QPushButton("Patch")
        self.patch_btn.clicked.connect(self.apply_patches)
        self.patch_btn.setEnabled(False)

        main_layout.addWidget(config_group)
        main_layout.addWidget(files_group)
        main_layout.addWidget(patches_group)
        main_layout.addLayout(backup_restore_layout)
        main_layout.addWidget(self.patch_btn)

        # Version label at bottom right
        version_label = QLabel(f"v{__version__}")
        version_label.setStyleSheet("color: gray; font-size: 11px;")
        version_layout = QHBoxLayout()
        version_layout.addStretch()
        version_layout.addWidget(version_label)
        main_layout.addLayout(version_layout)

    def _on_binary_backup_changed(self, state: int) -> None:
        """Handle binary backup checkbox state change.

        Args:
            state: Checkbox state (Qt.CheckState)
        """
        self.enable_binary_backups = Qt.CheckState(state) == Qt.CheckState.Checked
        self.save_settings()


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
