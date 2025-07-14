# Terraform SBOM Generator

A Go tool for generating Software Bill of Materials (SBOM) from Terraform configurations.

## Features

- Analyzes Terraform configurations to identify module dependencies
- Supports multiple output formats: JSON, XML, CSV, TSV
- Recursive scanning of Terraform modules
- Command-line interface with verbose output options

## Installation

### Build from source

```bash
git clone https://github.com/rodmhgl/tf-sbom.git
cd tf-sbom
make build
```

### Using Go install

```bash
make install
```

## Usage

```
./terraform-sbom [options] <terraform-directory>
```

### Options

- `-f string`: Output format(s) - comma-separated (json, xml, csv, tsv) (default "json")
- `-o string`: Output file path base (extensions added automatically)
- `-r`: Recursively scan for Terraform modules
- `-v`: Verbose output

### Examples

Generate JSON SBOM for a Terraform configuration:
```bash
./terraform-sbom ./terraform
```

Generate multiple formats with custom output file:
```bash
./terraform-sbom -f json,xml,csv -o sbom ./terraform
```

Recursively scan all modules with verbose output:
```bash
./terraform-sbom -r -v -f json -o sbom ./project
```

## Development

### Requirements

- Go 1.24+
- Make

### Commands

```bash
# Build the project
make build

# Run tests
make test

# Format code
make fmt

# Run linters
make lint

# Generate coverage report
make coverage

# Clean build artifacts
make clean

# Run all validation checks
make validate
```

### Project Structure

```
.
├── Makefile
├── README.md
├── cmd/
│   └── terraform-sbom/ # Main application entry point
├── internal
│   ├── cli/            # Command-line interface handling
│   ├── export/         # Export functionality for various formats
│   └── sbom/           # Core SBOM generation logic and types
```

## Supported Output Formats

- **JSON**: Standard JSON format
- **XML**: XML representation
- **CSV/TSV**: Comma/Tab-separated values

## License

TBD - Not sure how this works with Hashicorp BUSL. 