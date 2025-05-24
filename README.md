# Network Configuration Parser

A robust Python-based tool that transforms heterogeneous network configuration files from multiple vendors into standardized, structured CSV inventories. This system can parse configuration files from Cisco, Palo Alto, F5, Fortigate, Juniper, and other network devices in various formats (CLI dumps, XML, JSON, txt, conf, cfg).

## 🚀 Features

- **Automatic Vendor Detection**: Intelligently identifies vendor (Cisco, Palo Alto, etc.) and OS type (IOS, NX-OS, PAN-OS, etc.) based on content patterns
- **Multi-Format Support**: Processes text-based configurations, XML files, JSON data, and CLI command outputs
- **Comprehensive Data Extraction**: Extracts detailed information into 20 standardized CSV files
- **Vendor-Specific Parsing**: Specialized parsers for major network vendors
- **Batch Processing**: Efficiently handles large numbers of configuration files
- **Data Normalization**: Transforms vendor-specific data models into a common schema

## 📊 Output CSV Files

The parser generates 20 standardized CSV files:

| File | Description |
|------|-------------|
| `devices.csv` | Device information (hostname, model, OS version, etc.) |
| `interfaces.csv` | Interface configurations and status |
| `vlans_vrfs.csv` | VLAN and VRF configurations |
| `acls.csv` | Access Control Lists |
| `routing_static.csv` | Static routing entries |
| `routing_dynamic.csv` | Dynamic routing (BGP, OSPF) configurations |
| `ntp.csv` | NTP server configurations |
| `aaa_servers.csv` | AAA server configurations |
| `snmp.csv` | SNMP configurations |
| `users_local.csv` | Local user accounts |
| `log_targets.csv` | Logging destinations |
| `crypto_tls.csv` | Certificate and crypto configurations |
| `feature_flags.csv` | Feature flags and global settings |
| `firmware_inventory.csv` | Firmware and image information |
| `ha_status.csv` | High availability status |
| `nat_rules.csv` | NAT rule configurations |
| `service_inventory.csv` | Network service inventory |
| `vpn_tunnels.csv` | VPN tunnel configurations |
| `zones.csv` | Security zone configurations |
| `login_banner.csv` | Login banners and MOTD |

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd network-config-parser
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**:
   ```bash
   python main.py --version
   ```

## 📖 Usage

### Basic Usage

```bash
# Parse configurations from a directory
python main.py /path/to/config/files

# Specify output directory
python main.py /path/to/configs -o /path/to/output

# Enable verbose logging
python main.py /path/to/configs --verbose
```

### Advanced Usage

```bash
# Use custom configuration file
python main.py /path/to/configs --config custom_config.yaml

# Parse with specific output directory and verbose logging
python main.py /path/to/configs -o ./network_inventory -v
```

### Configuration File Structure

The parser expects configuration files in these formats:
- **Text files**: `.txt`, `.conf`, `.cfg`
- **XML files**: `.xml` (for ACI, PAN-OS)
- **JSON files**: `.json`
- **Log files**: `.log` (CLI command outputs)

## 🏗️ Architecture

The system follows a modular pipeline architecture:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   File Scanner  │───▶│ Vendor Detector │───▶│ Parser Registry │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐    ┌─────────────────┐    ┌─────────▼─────────┐
│   CSV Writer    │◀───│ Data Normalizer │◀───│ Vendor Parsers   │
└─────────────────┘    └─────────────────┘    └───────────────────┘
```

### Core Components

1. **File Scanner** (`core/file_scanner.py`): Discovers configuration files
2. **Vendor Detector** (`core/vendor_detector.py`): Identifies vendor and OS type
3. **Parser Registry** (`core/parser_registry.py`): Routes files to appropriate parsers
4. **Vendor Parsers** (`parsers/`): Extract structured data from configurations
5. **Data Normalizer** (`output/data_normalizer.py`): Normalizes and cleans data
6. **CSV Writer** (`output/csv_writer.py`): Generates standardized CSV files

### Supported Vendors

| Vendor | OS Family | Parser Status | Supported Formats |
|--------|-----------|---------------|-------------------|
| Cisco | IOS/IOS-XE | ✅ Full | `.txt`, `.conf`, `.cfg`, `.log` |
| Cisco | NX-OS | 🟡 Basic | `.txt`, `.conf`, `.cfg`, `.log` |
| Cisco | ACI | 🟡 Basic | `.xml` |
| Palo Alto | PAN-OS | 🟡 Placeholder | `.xml`, `.conf`, `.txt` |
| Fortinet | FortiOS | ✅ Partial | `.conf`, `.cfg`, `.txt` |
| F5 | TMOS | 🟡 Placeholder | `.conf`, `.txt`, `.cfg` |
| F5 | F5OS | 🟡 Placeholder | `.conf`, `.txt`, `.cfg`, `.json` |
| Juniper | JunOS | 🟡 Placeholder | `.conf`, `.txt`, `.cfg` |

## 🔧 Extending the Parser

### Adding a New Vendor Parser

1. **Create parser directory**:
   ```bash
   mkdir parsers/newvendor
   touch parsers/newvendor/__init__.py
   ```

2. **Implement parser class**:
   ```python
   # parsers/newvendor/newos_parser.py
   from parsers.base_parser import BaseParser
   
   class NewVendorParser(BaseParser):
       def __init__(self):
           super().__init__()
           self.vendor = "newvendor"
           self.os_family = "newos"
       
       def parse_file(self, file_path, vendor_info):
           # Implementation here
           pass
       
       def extract_device_info(self, content):
           # Implementation here
           pass
   ```

3. **Register parser**:
   ```python
   # core/parser_registry.py
   from parsers.newvendor.newos_parser import NewVendorParser
   
   # Add to _initialize_parsers method
   self._register_parser('newvendor', 'newos', NewVendorParser())
   ```

4. **Add vendor detection patterns**:
   ```python
   # core/vendor_detector.py
   # Add patterns to detection_patterns dictionary
   ```

### Adding Custom Data Fields

1. **Extend data models** in `core/data_models.py`
2. **Update CSV schemas** in `output/csv_writer.py`
3. **Add normalization rules** in `output/data_normalizer.py`

## 📝 Configuration File Examples

### Example Directory Structure
```
configs/
├── cisco/
│   ├── switch1-running-config.txt
│   ├── router1-startup-config.cfg
│   └── nexus1-config.conf
├── fortinet/
│   ├── fw1-config.conf
│   └── fw2-backup.cfg
├── palo_alto/
│   └── pa-config.xml
└── logs/
    ├── show-run-output.log
    └── show-version.txt
```

### Sample Command Output
```bash
$ python main.py ./configs -o ./output -v

2024-01-15 10:30:01 - INFO - Starting network configuration parsing
2024-01-15 10:30:01 - INFO - Input directory: ./configs  
2024-01-15 10:30:01 - INFO - Output directory: ./output
2024-01-15 10:30:01 - INFO - Scanning for configuration files...
2024-01-15 10:30:01 - INFO - Found 25 configuration files

2024-01-15 10:30:02 - INFO - Processing: ./configs/cisco/switch1-running-config.txt
2024-01-15 10:30:02 - INFO - Detected: cisco/ios (confidence: 0.95)
2024-01-15 10:30:03 - INFO - Successfully processed: ./configs/cisco/switch1-running-config.txt

2024-01-15 10:30:04 - INFO - Processing: ./configs/fortinet/fw1-config.conf  
2024-01-15 10:30:04 - INFO - Detected: fortinet/fortios (confidence: 0.89)
2024-01-15 10:30:05 - INFO - Successfully processed: ./configs/fortinet/fw1-config.conf

2024-01-15 10:30:15 - INFO - Parsing completed. Processed: 23, Failed: 2
2024-01-15 10:30:15 - INFO - CSV generation completed. 18 files written.

✅ Parsing completed successfully!
📁 CSV files saved to: ./output
```

## 🔍 Output Analysis

After parsing, you'll find:

- **18 CSV files** with extracted data
- **metadata.json** with parsing statistics
- **parsing_summary.txt** with detailed results

### Sample CSV Output

**devices.csv**:
```csv
device_id,hostname,vendor,model,os_family,os_version,source_file
SW001_a1b2c3d4,CORE-SW-001,cisco,C3850,ios,16.09.04,switch1-config.txt
FW001_e5f6g7h8,FIREWALL-001,fortinet,FG100D,fortios,6.4.7,fw1-config.conf
```

**interfaces.csv**:
```csv
device_id,interface_name,ip_address,subnet_mask,admin_status,operational_status
SW001_a1b2c3d4,GigabitEthernet1/0/1,192.168.1.1,255.255.255.0,up,up
SW001_a1b2c3d4,GigabitEthernet1/0/2,,,,down,down
```

## 🧪 Testing

Run the parser on sample configurations:

```bash
# Test with provided sample configs
python main.py ./sample_configs -o ./test_output -v

# Validate output files
ls -la ./test_output/*.csv
```

## 📋 Troubleshooting

### Common Issues

1. **No files found**:
   - Check file permissions
   - Verify file extensions are supported
   - Use `-v` flag for detailed logging

2. **Vendor detection fails**:
   - Check if configuration contains vendor-specific keywords
   - Review vendor detection patterns in `core/vendor_detector.py`

3. **Parser errors**:
   - Enable verbose logging (`-v`)
   - Check parser logs for specific error messages
   - Validate configuration file format

### Debug Mode

```bash
# Enable maximum logging detail
python main.py ./configs -o ./output -v --debug
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests for new functionality
5. Submit a pull request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Check code quality
flake8 .
black .
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:

- Create an issue in the repository
- Check the troubleshooting section above
- Review the logs with verbose mode enabled

## 🔮 Roadmap

- [ ] Enhanced Palo Alto PAN-OS parser
- [ ] Complete F5 TMOS/F5OS parsers  
- [ ] Full Juniper JunOS parser
- [ ] HPE/Aruba parser support
- [ ] Real-time configuration monitoring
- [ ] Web-based interface
- [ ] API endpoints
- [ ] Configuration compliance checking
- [ ] Change detection and reporting #   P a r s i n g - S y s t e m  
 