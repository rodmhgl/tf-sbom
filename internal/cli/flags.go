package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Config holds the parsed command line configuration
type Config struct {
	Format     []string
	Output     string
	Verbose    bool
	Recursive  bool
	ConfigPath string
}

// ParseFlags parses command line flags and returns the configuration
func ParseFlags() (*Config, error) {
	var (
		format    = flag.String("f", "json", "Output format(s) - comma-separated (json, xml, csv, tsv, spdx, cyclonedx)")
		output    = flag.String("o", "", "Output file path base (extensions added automatically)")
		verbose   = flag.Bool("v", false, "Verbose output")
		recursive = flag.Bool("r", false, "Recursively scan for Terraform modules")
	)
	flag.Parse()

	if flag.NArg() < 1 {
		printUsage()
		return nil, fmt.Errorf("missing terraform-directory argument")
	}

	configPath := flag.Arg(0)

	// Parse comma-separated formats
	formats := strings.Split(*format, ",")
	for i, fmt := range formats {
		formats[i] = strings.TrimSpace(fmt)
	}

	return &Config{
		Format:     formats,
		Output:     *output,
		Verbose:    *verbose,
		Recursive:  *recursive,
		ConfigPath: configPath,
	}, nil
}

// printUsage prints the usage information
func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] <terraform-directory>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nOptions:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nArguments:\n")
	fmt.Fprintf(os.Stderr, "  terraform-directory: Directory containing Terraform configuration files\n")
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  %s -f json -o sbom.json ./terraform\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s -r -f spdx -o sbom ./project    # Recursively scan all modules\n", os.Args[0])
}
