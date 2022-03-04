package house_arrest

import (
	"github.com/danielpaulus/go-ios/ios"
	"path"
	"sort"
)

type CrashReports struct {
	afc  *AfcClient
	Conn *Connection
}

func NewCrashReports(c ios.DeviceConnectionInterface) *CrashReports {
	conn := &Connection{
		deviceConn: c,
	}
	return &CrashReports{
		afc:  &AfcClient{deviceConn: c},
		Conn: conn,
	}
}

func (c *CrashReports) ListCrashReports() ([]string, error) {
	reports, err := c.recursiveListReports(".")
	if err != nil {
		return nil, err
	}
	sort.Strings(reports)
	return reports, nil
}

func (c *CrashReports) recursiveListReports(dir string) ([]string, error) {
	files, err := c.afc.ListFiles(dir)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0)
	for _, f := range files {
		if f == "." || f == ".." {
			continue
		}
		info, err := c.afc.ReadFileInfo(path.Join(dir, f))
		if err != nil {
			return nil, err
		}
		switch info.IFmt {
		case IFDIR:
			contents, err := c.recursiveListReports(path.Join(dir, f))
			if err != nil {
				return nil, err
			}
			result = append(result, contents...)
		case IFREG:
			result = append(result, path.Join(dir, f))
		}
		if info.IFmt == IFDIR {
		}
	}
	return result, nil
}

func (c *CrashReports) FetchCrashReport(name string) ([]byte, error) {
	handle, err := c.afc.OpenFileReadOnly(name)
	if err != nil {
		return nil, err
	}
	defer c.afc.CloseFile(handle)
	return c.afc.ReadFully(handle)
}

func (c *CrashReports) DeleteReport(name string) error {
	return c.Conn.RemovePath(name)
}
