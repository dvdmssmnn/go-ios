package afc

import (
	"bytes"
	"encoding/binary"
	"github.com/stretchr/testify/assert"
	"io"
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
	status := make([]byte, 8)
	binary.LittleEndian.PutUint64(status, Afc_Err_Success)
	l := Afc_header_size + 8
	success := AfcPacket{
		Header: AfcPacketHeader{
			Magic:         Afc_magic,
			Entire_length: l + uint64(len(payload)),
			This_length:   l,
			Packet_num:    0,
			Operation:     Afc_operation_status,
		},
		HeaderPayload: status,
		Payload:       payload,
	}

	return Encode(success, w)
}
