package house_arrest

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseFileInfoDirectory(t *testing.T) {
	response := "st_size\u00002560\u0000" +
		"st_blocks\u00000\u0000" +
		"st_nlink\u000080\u0000" +
		"st_ifmt\u0000S_IFDIR\u0000" +
		"st_mtime\u00001645256258468441173\u0000" +
		"st_birthtime\u00001549345196392467665\u0000"

	expected := FileInfo{
		Size:      2560,
		Blocks:    0,
		NLink:     80,
		IFmt:      IFDIR,
		MTime:     1645256258468441173,
		BirthTime: 1549345196392467665,
	}

	res, err := parseFileInfo([]byte(response))
	assert.NoError(t, err)
	assert.Equal(t, expected, res)
}

func TestParseFileInfoFile(t *testing.T) {
	r := "" +
		"st_size\u000084280\u0000" +
		"st_blocks\u0000168\u0000" +
		"st_nlink\u00001\u0000" +
		"st_ifmt\u0000S_IFREG\u0000" +
		"st_mtime\u00001645348035632337976\u0000" +
		"st_birthtime\u00001645348035625462021\u0000"

	expected := FileInfo{
		Size:      84280,
		Blocks:    168,
		NLink:     1,
		IFmt:      IFREG,
		MTime:     1645348035632337976,
		BirthTime: 1645348035625462021,
	}

	res, err := parseFileInfo([]byte(r))
	assert.NoError(t, err)
	assert.Equal(t, expected, res)
}
