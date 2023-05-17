package afc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"path"
	"testing"
)

/*
import (
	"fmt"
	"github.com/danielpaulus/go-ios/ios"
	log "github.com/sirupsen/logrus"
	"path"
	"testing"
)

const test_device_udid = "udid_here"

func TestConnection_Remove(t *testing.T) {
	deviceEnrty, _ := ios.GetDevice(test_device_udid)

	conn, err := New(deviceEnrty)
	if err != nil {
		log.Fatalf("connect service failed: %v", err)
	}

	err = conn.Remove("/DCIM/fsync.go")
	if err != nil {
		log.Fatalf("remove failed:%v", err)
	}
}

func TestConnection_RemoveAll(t *testing.T) {
	deviceEnrty, _ := ios.GetDevice(test_device_udid)

	conn, err := New(deviceEnrty)
	if err != nil {
		log.Fatalf("connect service failed: %v", err)
	}

	err = conn.RemoveAll("/DCIM/TestDir")
	if err != nil {
		log.Fatalf("remove failed:%v", err)
	}
}

func TestConnection_Mkdir(t *testing.T) {
	deviceEnrty, _ := ios.GetDevice(test_device_udid)

	conn, err := New(deviceEnrty)
	if err != nil {
		log.Fatalf("connect service failed: %v", err)
	}

	err = conn.MkDir("/DCIM/TestDir")
	if err != nil {
		log.Fatalf("mkdir failed:%v", err)
	}
}

func TestConnection_stat(t *testing.T) {
	deviceEnrty, _ := ios.GetDevice(test_device_udid)

	conn, err := New(deviceEnrty)
	if err != nil {
		log.Fatalf("connect service failed: %v", err)
	}

	si, err := conn.Stat("/DCIM/architecture_diagram.png")
	if err != nil {
		log.Fatalf("get Stat failed:%v", err)
	}
	log.Printf("Stat :%+v", si)
}

func TestConnection_listDir(t *testing.T) {
	deviceEnrty, _ := ios.GetDevice(test_device_udid)

	conn, err := New(deviceEnrty)
	if err != nil {
		log.Fatalf("connect service failed: %v", err)
	}

	flist, err := conn.listDir("/DCIM/")
	if err != nil {
		log.Fatalf("tree view failed:%v", err)
	}
	for _, v := range flist {
		fmt.Printf("path: %+v\n", v)
	}
}

func TestConnection_TreeView(t *testing.T) {
	deviceEnrty, _ := ios.GetDevice(test_device_udid)

	conn, err := New(deviceEnrty)
	if err != nil {
		log.Fatalf("connect service failed: %v", err)
	}

	err = conn.TreeView("/DCIM/", "", true)
	if err != nil {
		log.Fatalf("tree view failed:%v", err)
	}
}

func TestConnection_pullSingleFile(t *testing.T) {
	deviceEnrty, _ := ios.GetDevice(test_device_udid)

	conn, err := New(deviceEnrty)
	if err != nil {
		log.Fatalf("connect service failed: %v", err)
	}

	err = conn.PullSingleFile("/DCIM/architecture_diagram.png", "architecture_diagram.png")
	if err != nil {
		log.Fatalf("pull single file failed:%v", err)
	}
}

func TestConnection_Pull(t *testing.T) {
	deviceEnrty, _ := ios.GetDevice(test_device_udid)

	conn, err := New(deviceEnrty)
	if err != nil {
		log.Fatalf("connect service failed: %v", err)
	}
	srcPath := "/DCIM/"
	dstpath := "TempRecv"
	dstpath = path.Join(dstpath, srcPath)
	err = conn.Pull(srcPath, dstpath)
	if err != nil {
		log.Fatalf("pull failed:%v", err)
	}
}

func TestConnection_Push(t *testing.T) {
	deviceEnrty, _ := ios.GetDevice(test_device_udid)
	conn, err := New(deviceEnrty)
	if err != nil {
		log.Fatalf("connect service failed: %v", err)
	}

	srcPath := "fsync.go"
	dstpath := "/DCIM/"

	err = conn.Push(srcPath, dstpath)
	if err != nil {
		log.Fatalf("push failed:%v", err)
	}
}
*/

func TestCodec(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	packet := AfcPacket{
		Header: AfcPacketHeader{
			Magic:         Afc_magic,
			Entire_length: Afc_header_size + 6 + 7,
			This_length:   Afc_header_size + 6,
			Packet_num:    0xABCD,
			Operation:     Afc_operation_remove_path,
		},
		HeaderPayload: []byte("header"),
		Payload:       []byte("payload"),
	}

	Encode(packet, buf)
	rec, err := Decode(buf)
	assert.Zero(t, buf.Len())
	assert.NoError(t, err)
	assert.Equal(t, packet, rec)
}

func TestWriteReadPacket(t *testing.T) {
	buf := closingBuffer{bytes.NewBuffer(nil)}
	conn := Connection{
		conn: buf,
	}

	p := Packet{
		Op:            Afc_operation_file_close,
		HeaderPayload: []byte("header"),
		Payload:       []byte("payload"),
	}

	err := conn.write(p)
	assert.NoError(t, err)
	rec, err := conn.read()
	assert.NoError(t, err)
	assert.Equal(t, p, rec)
}

func TestWriteAfcPacket(t *testing.T) {
	buf := closingBuffer{bytes.NewBuffer(nil)}

	c := Connection{
		conn: buf,
	}

	t.Run("package couner gets increased", func(t *testing.T) {
		pre := c.packageNumber
		writeSuccess(c.conn)
		c.Remove("/tmp")
		assert.Equal(t, pre+1, c.packageNumber)
		buf.Reset()
	})

	t.Run("remove", func(t *testing.T) {
		err := writeSuccess(c.conn)
		assert.NoError(t, err)
		c.Remove("/tmp")
		p, _ := c.read()

		assert.Equal(t, "/tmp", string(p.HeaderPayload))
		assert.Zero(t, buf.Len())
	})

	t.Run("remove path and contents", func(t *testing.T) {
		err := writeSuccess(c.conn)
		assert.NoError(t, err)
		c.RemovePathAndContents("/tmp")
		p, _ := c.read()

		assert.Equal(t, "/tmp\x00", string(p.HeaderPayload))
		assert.Zero(t, buf.Len())
	})

	t.Run("list dir", func(t *testing.T) {
		err := writeSuccessWithPayload(c.conn, []byte("/tmp\000/abc"))
		assert.NoError(t, err)
		ls, err := c.listDir("/")
		p, _ := c.read()
		assert.Equal(t, "/", string(p.HeaderPayload))
		assert.Equal(t, []string{"/tmp", "/abc"}, ls)
		assert.Zero(t, buf.Len())
	})

	t.Run("list dir removes '.' and '..'", func(t *testing.T) {
		err := writeSuccessWithPayload(c.conn, []byte(".\000..\000/tmp\000/abc"))
		assert.NoError(t, err)
		ls, err := c.listDir("/")
		c.read()
		assert.Equal(t, []string{"/tmp", "/abc"}, ls)
		assert.Zero(t, buf.Len())
	})

	t.Run("mkdir", func(t *testing.T) {
		err := writeSuccess(c.conn)
		assert.NoError(t, err)
		err = c.MkDir("/tmp/test")
		assert.NoError(t, err)
		p, _ := c.read()
		assert.Equal(t, "/tmp/test\000", string(p.HeaderPayload))
		assert.Zero(t, buf.Len())
	})

	t.Run("file stat", func(t *testing.T) {
		writeSuccessWithPayload(buf, []byte("st_size\0001024\000"+
			"st_blocks\000256\000"+
			"st_birthtime\0001\000"+
			"st_mtime\0002\000"+
			"st_nlink\00016\000"+
			"st_ifmt\000S_IFREG\000"+
			"st_linktarget\0000\000"))
		info, err := c.Stat("/tmp/somefile")
		assert.NoError(t, err)

		expected := &statInfo{
			stSize:       1024,
			stBlocks:     256,
			stCtime:      1,
			stMtime:      2,
			stNlink:      "16",
			stIfmt:       "S_IFREG",
			stLinktarget: "0",
		}
		assert.Equal(t, expected, info)

		req, _ := c.read()
		assert.Equal(t, "/tmp/somefile", string(req.HeaderPayload))
	})

	t.Run("write single file", func(t *testing.T) {
		b := make([]byte, maxWriteChunkSize+1)

		writeStatInfo(buf, statInfo{
			stSize:       1024,
			stBlocks:     256,
			stCtime:      1,
			stMtime:      2,
			stNlink:      "16",
			stIfmt:       "S_IFREG",
			stLinktarget: "0",
		})

		writeOpenFile(buf, 1)
		// response to first write
		writeSuccess(buf)
		// response to second write
		writeSuccess(buf)
		// response to close
		writeSuccess(buf)

		c.WriteToFile(bytes.NewReader(b), "/tmp/test")

		stat, _ := c.read()
		assert.Equal(t, Afc_operation_file_info, stat.Op)
		open, _ := c.read()
		assert.Equal(t, Afc_operation_file_open, open.Op)
		chunk1, _ := c.read()
		assert.EqualValues(t, maxWriteChunkSize, len(chunk1.Payload))
		assert.EqualValues(t, Afc_operation_file_write, chunk1.Op)
		chunk2, _ := c.read()
		assert.EqualValues(t, 1, len(chunk2.Payload))
		assert.EqualValues(t, Afc_operation_file_write, chunk2.Op)
		close, _ := c.read()
		assert.Equal(t, Afc_operation_file_close, close.Op)

		assert.Zero(t, buf.Len())
	})
}

func TestPushDirectory(t *testing.T) {
	// setup source directory
	d, _ := os.MkdirTemp("", "")
	sub := path.Join(d, "sub")
	os.Mkdir(sub, 0750)
	f1, _ := os.Create(path.Join(d, "a"))
	f1.Close()
	f2, _ := os.Create(path.Join(sub, "b"))
	f2.Close()

	buf := closingBuffer{bytes.NewBuffer(nil)}

	c := Connection{
		conn: buf,
	}

	// stat /tmp/root
	writeStatus(buf, Afc_Err_ObjectNotFound, nil)
	// mkdir /tmp/root
	writeSuccess(buf)
	// stat /tmp/a
	writeStatus(buf, Afc_Err_ObjectNotFound, nil)
	// open /tmp/a
	writeOpenFile(buf, 1)
	// close /tmp/a
	writeSuccess(buf)
	// mkdir /tmp/root/sub
	writeSuccess(buf)
	// stat /tmp/root/sub/b
	writeStatus(buf, Afc_Err_ObjectNotFound, nil)
	// open /tmp/root/sub/b
	writeOpenFile(buf, 2)
	// close /tmp/root/sub/b
	writeSuccess(buf)

	c.Push(d, "/tmp/dir")

	req, _ := c.read()
	assert.Equal(t, Afc_operation_file_info, req.Op)
	req, _ = c.read()
	assert.Equal(t, Afc_operation_make_dir, req.Op)
	assert.Equal(t, "/tmp/dir\000", string(req.HeaderPayload))
	req, _ = c.read()
	assert.Equal(t, Afc_operation_file_info, req.Op)
	req, _ = c.read()
	assert.Equal(t, Afc_operation_file_open, req.Op)
	assert.Equal(t, "/tmp/dir/a\000", string(req.HeaderPayload[8:]))
	req, _ = c.read()
	assert.Equal(t, Afc_operation_file_close, req.Op)
	req, _ = c.read()
	assert.Equal(t, Afc_operation_make_dir, req.Op)
	assert.Equal(t, "/tmp/dir/sub\000", string(req.HeaderPayload))
	req, _ = c.read()
	assert.Equal(t, Afc_operation_file_info, req.Op)
	req, _ = c.read()
	assert.Equal(t, Afc_operation_file_open, req.Op)
	assert.Equal(t, "/tmp/dir/sub/b\000", string(req.HeaderPayload[8:]))
	req, _ = c.read()
	assert.Equal(t, Afc_operation_file_close, req.Op)
}

type closingBuffer struct {
	*bytes.Buffer
}

func (b closingBuffer) Close() error {
	return nil
}

func writeSuccess(w io.Writer) error {
	return writeSuccessWithPayload(w, nil)
}

func writeSuccessWithPayload(w io.Writer, payload []byte) error {
	return writeStatus(w, Afc_Err_Success, payload)
}

func writeStatus(w io.Writer, status uint64, payload []byte) error {
	s := make([]byte, 8)
	binary.LittleEndian.PutUint64(s, status)
	return write(w, Afc_operation_status, s, payload)
}

func write(w io.Writer, op uint64, headerPayload, payload []byte) error {
	status := make([]byte, 8)
	binary.LittleEndian.PutUint64(status, Afc_Err_Success)
	success := AfcPacket{
		Header: AfcPacketHeader{
			Magic:         Afc_magic,
			Entire_length: Afc_header_size + uint64(len(headerPayload)) + uint64(len(payload)),
			This_length:   Afc_header_size + uint64(len(headerPayload)),
			Packet_num:    0,
			Operation:     op,
		},
		HeaderPayload: headerPayload,
		Payload:       payload,
	}

	return Encode(success, w)
}

func writeStatInfo(w io.Writer, info statInfo) error {
	return writeSuccessWithPayload(w, []byte(fmt.Sprintf("st_size\0001024\000"+
		"st_blocks\000%d\000"+
		"st_birthtime\000%d\000"+
		"st_mtime\000%d\000"+
		"st_nlink\000%s\000"+
		"st_ifmt\000%s\000"+
		"st_linktarget\000%s\000",
		info.stBlocks, info.stCtime, info.stMtime, info.stNlink, info.stIfmt, info.stLinktarget)))
}

func writeOpenFile(w io.Writer, fd uint64) error {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, fd)
	return write(w, Afc_operation_file_open, b, nil)
}
