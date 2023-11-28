package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/laurentsimon/slsa-policy/pkg/release"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator/files_reader"
)

// TODO: use URI + environment to key the structure:
// URI_env1, URI_env2, etc. Look up will be faster.
// And we can easily tell if there's overlap or not.
// if env is empty, we'll...
// need a map[URI_env] = policy
// TODO: artifact + dev must come frm the same folder?
// I think we only want once, taht's it. if use env,
// must be in a sigle file anyway.
// var policies []Policy
// err := filepath.Walk(".",
// 	func(path string, info os.FileInfo, err error) error {
// 		if err != nil {
// 			return err
// 		}
// 		absPath, err := filepath.Abs(path)
// 		if err != nil {
// 			return fmt.Errorf("failed to read absolute policy path: %w", err)
// 		}
// 		if absPath == orgPolicy.Path() {
// 			return nil
// 		}
//		files = append(files, absPath)
// 		fmt.Println(path, info.Size())

// 		return nil
// 	})
// validate for unique artifact across all files.
// use orgPolicy.Path()
// use RootBuilderNames()
//return nil, nil

func main() {
	fmt.Println("Hello, Modules!")
	var projectsPath []string
	orgPath, err := filepath.Abs("main.go")
	if err != nil {
		panic(err)
	}
	err = filepath.Walk(".",
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			absPath, err := filepath.Abs(path)
			if err != nil {
				return fmt.Errorf("failed to read absolute policy path: %w", err)
			}
			if absPath == orgPath {
				return nil
			}
			projectsPath = append(projectsPath, absPath)
			fmt.Println(path, info.Size())
			return nil
		})
	projectsReader := files_reader.FromPaths(projectsPath)
	organizationReader, err := os.Open(orgPath)
	_, err = release.New(organizationReader, projectsReader)
	if err != nil {
		panic(err)
	}
}
