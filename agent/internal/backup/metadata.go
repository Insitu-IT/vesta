package backup

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

// BackupMetadata holds information parsed from the backup output.
type BackupMetadata struct {
	TotalSizeBytes int64
	DisksBackedUp  []DiskMetadata
	CheckpointName string
	VMConfig       string // raw XML content
}

// DiskMetadata describes one backed-up disk.
type DiskMetadata struct {
	Target    string
	Filename  string
	SizeBytes int64
	Encrypted bool
}

// ParseMetadata scans a backup output directory and extracts metadata.
func ParseMetadata(outputPath string) (*BackupMetadata, error) {
	meta := &BackupMetadata{}

	entries, err := os.ReadDir(outputPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		info, _ := entry.Info()

		// vmconfig*.xml
		if strings.HasPrefix(name, "vmconfig") && strings.HasSuffix(name, ".xml") {
			meta.VMConfig = filepath.Join(outputPath, name)
			// Extract checkpoint name from filename: vmconfig.checkpoint-name.xml
			parts := strings.SplitN(strings.TrimPrefix(name, "vmconfig"), ".", 3)
			if len(parts) > 1 && parts[0] == "" && parts[1] != "xml" {
				meta.CheckpointName = parts[1]
			}
		}

		// *.data or *.data.enc
		if strings.HasSuffix(name, ".data") || strings.HasSuffix(name, ".data.enc") {
			size := int64(0)
			if info != nil {
				size = info.Size()
			}
			encrypted := strings.HasSuffix(name, ".data.enc")
			target := extractDiskTarget(name)

			meta.DisksBackedUp = append(meta.DisksBackedUp, DiskMetadata{
				Target:    target,
				Filename:  name,
				SizeBytes: size,
				Encrypted: encrypted,
			})
			meta.TotalSizeBytes += size
		}
	}

	return meta, nil
}

// extractDiskTarget extracts the disk target from a backup data filename.
// e.g., "sda.data" → "sda", "vda.data.enc" → "vda"
func extractDiskTarget(filename string) string {
	name := filename
	name = strings.TrimSuffix(name, ".enc")
	name = strings.TrimSuffix(name, ".data")
	// Handle virtnbdbackup format: may include checkpoint info
	parts := strings.Split(name, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return name
}

// VMConfigXML is a minimal struct for parsing the VM config from backup output.
type VMConfigXML struct {
	XMLName xml.Name `xml:"domain"`
	Name    string   `xml:"name"`
	UUID    string   `xml:"uuid"`
}

// ReadVMConfig reads and parses the VM config XML from backup output.
func ReadVMConfig(configPath string) (*VMConfigXML, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var cfg VMConfigXML
	if err := xml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
