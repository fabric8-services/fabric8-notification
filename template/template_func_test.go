package template

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSizeImage(t *testing.T) {
	var v string

	v = sizeImage("image.pn?v=1", 22)
	assert.Equal(t, "image.pn?v=1&s=22", v)

	v = sizeImage("image.pn", 22)
	assert.Equal(t, "image.pn?s=22", v)
}

func TestJsonToArray(t *testing.T) {
	data := `[
		{
			"name": "com.logback.core",
			"version": "2.0",
			"cves": [
				{
					"CVE": "CVE-2016-7643",
					"CVSS": "8.0"
				},
				{
					"CVE": "CVE-2016-7643",
					"CVSS": "5.0"
				}
			],
			"cve_count": 2
		},
		{
			"name": "com.logback.web",
			"version": "1.5",
			"cves": [
				{
					"CVE": "CVE-2016-7643",
					"CVSS": "8.0"
				}
			],
			"cve_count": 1
		}
	]`
	values := jsonToArray(data)
	assert.NotNil(t, values)
	assert.Equal(t, 2, len(values))
}

func TestJsonToArrayNeg(t *testing.T) {
	data := `[
		{
			"name": "com.logback.core",
			"version": "2.0",
			"cves": [
				{
					"CVE": "CVE-2016-7643",
					"CVSS": "8.0"
				},
				{
					"CVE": "CVE-2016-7643",
					"CVSS": "5.0"
				}
			],
			"cve_count": 2
		},
		{
			"name": "com.logback.web",
			"version": "1.5",
			"cves": [
				{
					"CVE": "CVE-2016-7643",
					"CVSS": "8.0"
				}
			],
			"cve_count": 1
		}
	`
	values := jsonToArray(data)
	assert.NotNil(t, values)
	assert.Equal(t, 0, len(values))
}
