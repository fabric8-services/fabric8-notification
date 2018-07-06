package testsupport

import (
	"io/ioutil"
	"path/filepath"
)

func GetFileContent(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	content, err := ioutil.ReadFile(absPath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}
