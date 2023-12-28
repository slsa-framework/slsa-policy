package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func validatePaths(orgPath, projectsPath string) error {
	is, _ := relativeTo(orgPath, projectsPath)
	if is {
		return fmt.Errorf("%q is relative to %q", orgPath, projectsPath)
	}

	is, _ = relativeTo(projectsPath, orgPath)
	if is {
		return fmt.Errorf("%q is relative to %q", projectsPath, orgPath)
	}
	return nil
}

func relativeTo(p1, p2 string) (bool, error) {
	abs1, err := filepath.Abs(p1)
	if err != nil {
		return false, err
	}
	abs2, err := filepath.Abs(p2)
	if err != nil {
		return false, err
	}
	if abs1 == abs2 {
		return true, nil
	}
	if strings.HasPrefix(abs1, abs2+string(os.PathSeparator)) {
		return true, nil
	}
	return false, nil
}

func readFiles(dir string) ([]string, error) {
	var projectsPath []string
	err := filepath.Walk(dir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
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
