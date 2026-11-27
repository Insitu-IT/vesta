package backup

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type mockStageFile struct {
	name string
	info fs.FileInfo
}

type mockBackupStage struct {
	path      string
	files     []mockStageFile
	encrypted bool
	uploading bool
}

func closeMockStage(path string, encrypted bool) (mockBackupStage, error) {
	stage := mockBackupStage{path: path, encrypted: encrypted}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return stage, fmt.Errorf("mock stage must be an absolute canonical directory")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return stage, fmt.Errorf("mock stage must be free of symlinks")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return stage, fmt.Errorf("mock stage must be a private directory")
	}
	dataFiles := 0
	err = filepath.WalkDir(path, func(filename string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular mock staging file: %s", entry.Name())
		}
		if mockDataFile(entry.Name()) {
			dataFiles++
			if encrypted && !strings.HasSuffix(entry.Name(), ".enc") {
				return fmt.Errorf("plaintext remains in an encrypted mock stage: %s", entry.Name())
			}
		}
		name, err := filepath.Rel(path, filename)
		if err != nil {
			return err
		}
		stage.files = append(stage.files, mockStageFile{name: name, info: info})
		return nil
	})
	if err == nil && dataFiles == 0 {
		err = fmt.Errorf("mock stage has no backup data files")
	}
	return stage, err
}

func mockDataFile(name string) bool {
	for _, pattern := range backupDataPatterns {
		if strings.HasSuffix(name, strings.TrimPrefix(pattern, "*")) {
			return true
		}
	}
	return false
}

func sameMockFile(expected, observed fs.FileInfo) bool {
	return observed.Mode().IsRegular() && os.SameFile(expected, observed) &&
		observed.Mode() == expected.Mode() && observed.Size() == expected.Size() &&
		observed.ModTime().Equal(expected.ModTime())
}

func (s mockBackupStage) recheck() error {
	current, err := closeMockStage(s.path, s.encrypted)
	if err != nil {
		return err
	}
	if len(current.files) != len(s.files) {
		return fmt.Errorf("mock stage membership changed")
	}
	for i, item := range s.files {
		if item.name != current.files[i].name || !sameMockFile(item.info, current.files[i].info) {
			return fmt.Errorf("mock staging file changed: %s", item.name)
		}
	}
	return nil
}
