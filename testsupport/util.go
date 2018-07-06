package testsupport

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
)

func GetFileContent(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	fmt.Println(absPath)
	content, err := ioutil.ReadFile(absPath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}
