# Private Files Patcher

![UI](ui.png)

A simple tool to patch Silkroad private server files with an easy-to-use graphical interface.

## Quick Start

### Download & Install

1. Download the latest release from [Releases](https://github.com/dadav/pfpatch/releases)
2. Extract and run:
   - **Windows**: `pfpatch-vX.X.X-windows.exe`
   - **Linux**: `pfpatch-vX.X.X-linux`

On first run, patch files will be copied to a `patches` folder next to the executable.

### How to Use

1. **Select a patch config** - Choose a YAML file from the dropdown (in the `patches` folder)
2. **Select your game files** - Click "Select" next to each file name and choose your game executables (e.g., `SR_Gameserver.exe`, `GatewayServer.exe`)
3. **Configure patches**:
   - **Editable patches**: Enter a number in the text field (e.g., level cap, max characters)
   - **Regular patches**: Check the box to enable/disable
4. **Apply** - Click "Patch" to apply all enabled patches
5. **Restore** - Clear values or uncheck boxes, then click "Patch" again to restore original files

**Note**: The tool automatically backs up your files before patching, so you can always restore them.

## Creating Patch Files

Patch files are YAML configuration files placed in the `patches` directory. Here are the most common patterns:

### Basic Patch (simple byte replacement)

```yaml
files:
  gameserver:
    default: "SR_Gameserver.exe"

patches:
  - name: "Disable login captcha"
    description: "Removes the login captcha requirement"
    editable: false
    file: gameserver
    changes:
      - offset: 0x40509d
        value: "30 6e 40"
```

### Editable Patch (Let users enter values)

```yaml
patches:
  - name: "Max characters per account"
    editable: true
    file: sro_client
    changes:
      - offset: 0x85de6d
        size: 1  # 1 byte = 0-255, 2 bytes = 0-65535, 4 bytes = larger numbers
```

### Multiple Locations

Apply the same patch to multiple offsets:

```yaml
patches:
  - name: "Level cap"
    editable: true
    file: gameserver
    changes:
      - offset: 0x4e52c9
        size: 1
      - offset: 0x4d641e
        size: 1
```

### Pattern Matching (for different game versions)

Instead of fixed offsets, search for byte patterns:

```yaml
patches:
  - name: "Pattern-based patch"
    editable: false
    file: gameserver
    changes:
      - pattern: "48 8B 05 ?? ?? ?? ??"
        value: "90 90 90 90 90 90 90"
```

- Use `??` as wildcards (matches any byte)
- Useful when offsets change between game versions

### Value Formulas

Convert user input before writing to the file:

```yaml
patches:
  - name: "Spawn limit"
    editable: true
    file: gameserver
    changes:
      - offset: 0x54d6da
        size: 4
        formula: "value * 0x1D0"  # Multiply user input by 0x1D0
```

### Display Conversion

Show values in a different format than stored:

```yaml
patches:
  - name: "Guild penalty days"
    editable: true
    file: gameserver
    changes:
      - offset: 0x5c3f95
        size: 4
        display_formula: "value / 86400"  # Show as days
        input_formula: "value * 86400"    # Store as seconds
```

Users enter days, but the game stores seconds.

## Backup & Restore

- Backups are automatically created in the `backups` folder
- To restore: Clear editable values or uncheck patches, then click "Patch"
- Original files are always preserved

## Advanced Usage

### Building from Source

If you want to modify the tool:

```bash
# Install dependencies
pip install -r requirements.txt

# Run
python pfpatch.py
```

**Requirements**: Python 3.12+

## License

[Apache](./LICENSE)
