package afc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/danielpaulus/go-ios/ios"
	log "github.com/sirupsen/logrus"
)

const serviceName = "com.apple.afc"

type Connection struct {
	conn          io.ReadWriteCloser
	packageNumber uint64
}

type statInfo struct {
	stSize       int64
	stBlocks     int64
	stCtime      int64
	stMtime      int64
	stNlink      string
	stIfmt       string
	stLinktarget string
}

func (s *statInfo) IsDir() bool {
	return s.stIfmt == "S_IFDIR"
}

func (s *statInfo) IsLink() bool {
	return s.stIfmt == "S_IFLNK"
}

func New(device ios.DeviceEntry) (*Connection, error) {
	deviceConn, err := ios.ConnectToService(device, serviceName)
	if err != nil {
		return nil, err
	}
	return &Connection{conn: deviceConn}, nil
}

// NewFromConn allows to use AFC on an existing connection, see crashreport for an example
func NewFromConn(conn io.ReadWriteCloser) *Connection {
	return &Connection{conn: conn}
}

func (conn *Connection) writeRequestAndCheckResponse(p Packet) error {
	res, err := conn.writeRequestAndReadResponse(p)
	if err != nil {
		return err
	}
	if err = conn.checkResponseStatus(res); err != nil {
		return fmt.Errorf("unexpected afc status: %v", err)
	}
	return nil
}

func (conn *Connection) writeRequestAndReadResponse(p Packet) (Packet, error) {
	err := conn.write(p)
	if err != nil {
		return Packet{}, err
	}
	return conn.read()
}

func (conn *Connection) checkResponseStatus(packet Packet) error {
	if packet.Op == Afc_operation_status {
		errorCode := binary.LittleEndian.Uint64(packet.HeaderPayload)
		if errorCode != Afc_Err_Success {
			return getError(errorCode)
		}
	}
	return nil
}

func (conn *Connection) Remove(path string) error {
	p := Packet{
		Op:            Afc_operation_remove_path,
		HeaderPayload: []byte(path),
	}
	err := conn.writeRequestAndCheckResponse(p)
	if err != nil {
		return fmt.Errorf("remove: %w", err)
	}
	return nil
}

func (conn *Connection) RemovePathAndContents(path string) error {
	p := Packet{
		Op:            Afc_operation_remove_path_and_contents,
		HeaderPayload: []byte(fmt.Sprintf("%s\x00", path)),
	}
	err := conn.writeRequestAndCheckResponse(p)
	if err != nil {
		return fmt.Errorf("remove: %w", err)
	}
	return nil
}

func (conn *Connection) RemoveAll(srcPath string) error {
	fileInfo, err := conn.Stat(srcPath)
	if err != nil {
		return err
	}
	if fileInfo.IsDir() {
		fileList, err := conn.listDir(srcPath)
		if err != nil {
			return err
		}
		for _, v := range fileList {
			sp := path.Join(srcPath, v)
			err = conn.RemoveAll(sp)
			if err != nil {
				return err
			}
		}
	}
	return conn.Remove(srcPath)
}

func (conn *Connection) MkDir(path string) error {
	p := Packet{
		Op:            Afc_operation_make_dir,
		HeaderPayload: []byte(fmt.Sprintf("%s\000", path)),
	}
	err := conn.writeRequestAndCheckResponse(p)
	if err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	return nil
}

func (conn *Connection) Stat(path string) (*statInfo, error) {
	p := Packet{
		Op:            Afc_operation_file_info,
		HeaderPayload: []byte(path),
	}
	response, err := conn.writeRequestAndReadResponse(p)
	if err != nil {
		return nil, err
	}
	if err = conn.checkResponseStatus(response); err != nil {
		return nil, fmt.Errorf("stat: unexpected afc status: %v", err)
	}
	ret := bytes.Split(response.Payload, []byte{0})
	retLen := len(ret)
	if retLen%2 != 0 {
		retLen = retLen - 1
	}
	statInfoMap := make(map[string]string)
	for i := 0; i <= retLen-2; i = i + 2 {
		k := string(ret[i])
		v := string(ret[i+1])
		statInfoMap[k] = v
	}

	var si statInfo
	si.stSize, _ = strconv.ParseInt(statInfoMap["st_size"], 10, 64)
	si.stBlocks, _ = strconv.ParseInt(statInfoMap["st_blocks"], 10, 64)
	si.stCtime, _ = strconv.ParseInt(statInfoMap["st_birthtime"], 10, 64)
	si.stMtime, _ = strconv.ParseInt(statInfoMap["st_mtime"], 10, 64)
	si.stNlink = statInfoMap["st_nlink"]
	si.stIfmt = statInfoMap["st_ifmt"]
	si.stLinktarget = statInfoMap["st_linktarget"]
	return &si, nil
}

func (conn *Connection) listDir(path string) ([]string, error) {
	p := Packet{
		Op:            Afc_operation_read_dir,
		HeaderPayload: []byte(path),
	}
	response, err := conn.writeRequestAndReadResponse(p)
	if err != nil {
		return nil, err
	}
	if err = conn.checkResponseStatus(response); err != nil {
		return nil, fmt.Errorf("list dir: unexpected afc status: %v", err)
	}
	ret := bytes.Split(response.Payload, []byte{0})
	var fileList []string
	for _, v := range ret {
		if string(v) != "." && string(v) != ".." && string(v) != "" {
			fileList = append(fileList, string(v))
		}
	}
	return fileList, nil
}

func (conn *Connection) GetSpaceInfo() (*AFCDeviceInfo, error) {
	p := Packet{Op: Afc_operation_device_info}
	response, err := conn.writeRequestAndReadResponse(p)
	if err != nil {
		return nil, err
	}
	if err = conn.checkResponseStatus(response); err != nil {
		return nil, fmt.Errorf("mkdir: unexpected afc status: %v", err)
	}

	bs := bytes.Split(response.Payload, []byte{0})
	strs := make([]string, len(bs)-1)
	for i := 0; i < len(strs); i++ {
		strs[i] = string(bs[i])
	}
	m := make(map[string]string)
	if strs != nil {
		for i := 0; i < len(strs); i += 2 {
			m[strs[i]] = strs[i+1]
		}
	}

	totalBytes, err := strconv.ParseUint(m["FSTotalBytes"], 10, 64)
	if err != nil {
		return nil, err
	}
	freeBytes, err := strconv.ParseUint(m["FSFreeBytes"], 10, 64)
	if err != nil {
		return nil, err
	}
	blockSize, err := strconv.ParseUint(m["FSBlockSize"], 10, 64)
	if err != nil {
		return nil, err
	}

	return &AFCDeviceInfo{
		Model:      m["Model"],
		TotalBytes: totalBytes,
		FreeBytes:  freeBytes,
		BlockSize:  blockSize,
	}, nil
}

// ListFiles returns all files in the given directory, matching the pattern.
// Example: ListFiles(".", "*") returns all files and dirs in the current path the afc connection is in
func (conn *Connection) ListFiles(cwd string, matchPattern string) ([]string, error) {
	p := Packet{
		Op:            Afc_operation_read_dir,
		HeaderPayload: []byte(cwd),
	}

	response, err := conn.writeRequestAndReadResponse(p)
	if err != nil {
		return nil, err
	}
	fileList := string(response.Payload)
	files := strings.Split(fileList, string([]byte{0}))
	var filteredFiles []string
	for _, f := range files {
		if f == "" {
			continue
		}
		matches, err := filepath.Match(matchPattern, f)
		if err != nil {
			log.Warn("error while matching pattern", err)
		}
		if matches {
			filteredFiles = append(filteredFiles, f)
		}
	}
	return filteredFiles, nil
}

func (conn *Connection) TreeView(dpath string, prefix string, treePoint bool) error {
	fileInfo, err := conn.Stat(dpath)
	if err != nil {
		return err
	}
	namePrefix := "`--"
	if !treePoint {
		namePrefix = "|--"
	}
	tPrefix := prefix + namePrefix
	if fileInfo.IsDir() {
		fmt.Printf("%s %s/\n", tPrefix, filepath.Base(dpath))
		fileList, err := conn.listDir(dpath)
		if err != nil {
			return err
		}
		for i, v := range fileList {
			tp := false
			if i == len(fileList)-1 {
				tp = true
			}
			rp := prefix + "    "
			if !treePoint {
				rp = prefix + "|   "
			}
			nPath := path.Join(dpath, v)
			err = conn.TreeView(nPath, rp, tp)
			if err != nil {
				return err
			}
		}
	} else {
		fmt.Printf("%s %s\n", tPrefix, filepath.Base(dpath))
	}
	return nil
}

func (conn *Connection) OpenFile(path string, mode uint64) (uint64, error) {
	pathBytes := []byte(path)
	pathBytes = append(pathBytes, 0)
	headerLength := 8 + uint64(len(pathBytes))
	headerPayload := make([]byte, headerLength)
	binary.LittleEndian.PutUint64(headerPayload, mode)
	copy(headerPayload[8:], pathBytes)
	p := Packet{
		Op:            Afc_operation_file_open,
		HeaderPayload: headerPayload,
	}

	response, err := conn.writeRequestAndReadResponse(p)
	if err != nil {
		return 0, err
	}
	if err = conn.checkResponseStatus(response); err != nil {
		return 0, fmt.Errorf("open file: unexpected afc status: %v", err)
	}
	fd := binary.LittleEndian.Uint64(response.HeaderPayload)
	if fd == 0 {
		return 0, fmt.Errorf("file descriptor should not be zero")
	}

	return fd, nil
}

func (conn *Connection) CloseFile(fd uint64) error {
	headerPayload := make([]byte, 8)
	binary.LittleEndian.PutUint64(headerPayload, fd)
	p := Packet{
		Op:            Afc_operation_file_close,
		HeaderPayload: headerPayload,
	}
	if err := conn.writeRequestAndCheckResponse(p); err != nil {
		return fmt.Errorf("close file: %w", err)
	}
	return nil
}

func (conn *Connection) PullSingleFile(srcPath, dstPath string) error {
	fileInfo, err := conn.Stat(srcPath)
	if err != nil {
		return err
	}
	if fileInfo.IsLink() {
		srcPath = fileInfo.stLinktarget
	}
	fd, err := conn.OpenFile(srcPath, Afc_Mode_RDONLY)
	if err != nil {
		return err
	}
	defer conn.CloseFile(fd)

	f, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()

	leftSize := fileInfo.stSize
	maxReadSize := 64 * 1024
	for leftSize > 0 {
		headerPayload := make([]byte, 16)
		binary.LittleEndian.PutUint64(headerPayload, fd)
		binary.LittleEndian.PutUint64(headerPayload[8:], uint64(maxReadSize))
		p := Packet{
			Op:            Afc_operation_file_read,
			HeaderPayload: headerPayload,
			Payload:       nil,
		}
		response, err := conn.writeRequestAndReadResponse(p)
		if err != nil {
			return err
		}
		if err = conn.checkResponseStatus(response); err != nil {
			return fmt.Errorf("read file: unexpected afc status: %v", err)
		}
		leftSize = leftSize - int64(len(response.Payload))
		f.Write(response.Payload)
	}
	return nil
}

func (conn *Connection) Pull(srcPath, dstPath string) error {
	fileInfo, err := conn.Stat(srcPath)
	if err != nil {
		return err
	}
	if fileInfo.IsDir() {
		ret, _ := ios.PathExists(dstPath)
		if !ret {
			err = os.MkdirAll(dstPath, os.ModePerm)
			if err != nil {
				return err
			}
		}
		fileList, err := conn.listDir(srcPath)
		if err != nil {
			return err
		}
		for _, v := range fileList {
			sp := path.Join(srcPath, v)
			dp := path.Join(dstPath, v)
			err = conn.Pull(sp, dp)
			if err != nil {
				return err
			}
		}
	} else {
		return conn.PullSingleFile(srcPath, dstPath)
	}
	return nil
}

func (conn *Connection) Push(srcPath, dstPath string) error {
	ret, _ := ios.PathExists(srcPath)
	if !ret {
		return fmt.Errorf("%s: no such file.", srcPath)
	}

	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if fileInfo, _ := conn.Stat(dstPath); fileInfo != nil {
		if fileInfo.IsDir() {
			dstPath = path.Join(dstPath, filepath.Base(srcPath))
		}
	}

	return conn.WriteToFile(f, dstPath)
}

func (conn *Connection) WriteToFile(reader io.Reader, dstPath string) error {
	if fileInfo, _ := conn.Stat(dstPath); fileInfo != nil {
		if fileInfo.IsDir() {
			return fmt.Errorf("%s is a directory, cannot write to it as file", dstPath)
		}
	}

	fd, err := conn.OpenFile(dstPath, Afc_Mode_WR)
	if err != nil {
		return err
	}
	defer conn.CloseFile(fd)

	maxWriteSize := 64 * 1024
	chunk := make([]byte, maxWriteSize)
	for {
		n, err := reader.Read(chunk)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}
		bytesRead := chunk[:n]
		headerPayload := make([]byte, 8)
		binary.LittleEndian.PutUint64(headerPayload, fd)
		p := Packet{
			Op:            Afc_operation_file_write,
			HeaderPayload: headerPayload,
			Payload:       bytesRead,
		}
		response, err := conn.writeRequestAndReadResponse(p)
		if err != nil {
			return err
		}
		if err = conn.checkResponseStatus(response); err != nil {
			return fmt.Errorf("write file: unexpected afc status: %v", err)
		}

	}
	return nil
}

func (conn *Connection) Close() {
	conn.conn.Close()
}

func (conn *Connection) write(p Packet) error {
	hl := Afc_header_size + uint64(len(p.HeaderPayload))
	tl := hl + uint64(len(p.Payload))
	packet := AfcPacket{
		Header: AfcPacketHeader{
			Magic:         Afc_magic,
			Entire_length: tl,
			This_length:   hl,
			Packet_num:    conn.packageNumber,
			Operation:     p.Op,
		},
		HeaderPayload: p.HeaderPayload,
		Payload:       p.Payload,
	}
	conn.packageNumber++
	return Encode(packet, conn.conn)
}

func (conn *Connection) read() (Packet, error) {
	p, err := Decode(conn.conn)
	if err != nil {
		return Packet{}, err
	}
	return Packet{
		Op:            p.Header.Operation,
		HeaderPayload: p.HeaderPayload,
		Payload:       p.Payload,
	}, nil
}

type Packet struct {
	Op            uint64
	HeaderPayload []byte
	Payload       []byte
}
