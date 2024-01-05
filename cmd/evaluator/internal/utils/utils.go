package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

func ReadFiles(dir string, ignore string) ([]string, error) {
	var projectsPath []string
	absIgnore, err := filepath.Abs(ignore)
	if err != nil {
		return nil, err
	}
	err = filepath.Walk(dir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			absPath, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			// Skip the ignore file.
			if absPath == absIgnore {
				return nil
			}
			// Skip directories.
			if info.IsDir() {
				return nil
			}
			projectsPath = append(projectsPath, path)
			return nil
		})
	return projectsPath, err
}

func Log(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format, a...)
}
