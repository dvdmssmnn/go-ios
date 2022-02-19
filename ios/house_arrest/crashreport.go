package house_arrest

import "github.com/danielpaulus/go-ios/ios"

type CrashReports struct {
	Conn Connection
}

func NewCrashReports(c ios.DeviceConnectionInterface) *CrashReports {
	return &CrashReports{Conn: Connection{
		deviceConn: c,
	}}
}

func (c *CrashReports) ListCrashReports() ([]string, error) {
	response, err := c.Conn.ListFiles("")
	if err != nil {
		return nil, err
	}
	filtered := make([]string, 0)
	for _, f := range response {
		if f == "." || f == ".." {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered, nil
	//if err != nil {
	//	return nil, err
	//}
	//log.Info(files)
	//for _, f := range files {
	//	if f == "." || f == ".." {
	//		continue
	//	}
	//	data, err := h.openFileForReading(f)
	//	if err != nil {
	//		continue
	//	}
	//	log.Infof("file %s: %s", f, string(data))
	//	h.readFileContents(data)
	//}
	//return nil
}

func (c *CrashReports) FetchCrashReport(name string) ([]byte, error) {
	c.Conn.ReadFile(name)
	handle, err := c.Conn.openFileForReading(name)
	if err != nil {
		return nil, err
	}
	defer c.Conn.closeHandle(handle)
	return c.Conn.readFileContents(handle)
}

func (c *CrashReports) DeleteReport(name string) error {
	return c.Conn.RemovePath(name)
}
