package house_arrest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/danielpaulus/go-ios/ios"
	log "github.com/sirupsen/logrus"
	"io"
	"strconv"
	"strings"
)

/*
byte fileHandle = afcClient.executeRemoteOpenFileWriteCommand(relativeTestConfigurationPath);
			afcClient.executeSendFileCommand(serializedXctestConfig, fileHandle);
			afcClient.closeFile(fileHandle);
*/
type AfcPacketHeader struct {
	Magic         uint64
	Entire_length uint64
	This_length   uint64
	Packet_num    uint64
	Operation     uint64
}

type AfcPacket struct {
	header        AfcPacketHeader
	headerPayload []byte
	payload       []byte
}

func Decode(reader io.Reader) (AfcPacket, error) {
	var header AfcPacketHeader
	err := binary.Read(reader, binary.LittleEndian, &header)
	if err != nil {
		return AfcPacket{}, err
	}
	if header.Magic != afc_magic {
		return AfcPacket{}, fmt.Errorf("Wrong magic:%x expected: %x", header.Magic, afc_magic)
	}
	headerPayloadLength := header.This_length - afc_header_size
	headerPayload := make([]byte, headerPayloadLength)
	_, err = io.ReadFull(reader, headerPayload)
	if err != nil {
		return AfcPacket{}, err
	}

	contentPayloadLength := header.Entire_length - header.This_length
	payload := make([]byte, contentPayloadLength)
	_, err = io.ReadFull(reader, payload)
	if err != nil {
		return AfcPacket{}, err
	}
	return AfcPacket{header, headerPayload, payload}, nil
}

func Encode(packet AfcPacket, writer io.Writer) error {
	err := binary.Write(writer, binary.LittleEndian, packet.header)
	if err != nil {
		return err
	}
	_, err = writer.Write(packet.headerPayload)
	if err != nil {
		return err
	}

	_, err = writer.Write(packet.payload)
	if err != nil {
		return err
	}
	return nil
}

const (
	afc_magic                      uint64 = 0x4141504c36414643
	afc_header_size                uint64 = 40
	afc_fopen_ronly                uint64 = 0x1
	afc_fopen_wronly               uint64 = 0x3
	afc_operation_status           uint64 = 0x1
	afc_operation_data             uint64 = 0x2
	afc_operation_read_dir         uint64 = 0x3
	afc_operation_get_file_info    uint64 = 0xa
	afc_operation_file_open        uint64 = 0x0000000D
	afc_operation_file_close       uint64 = 0x00000014
	afc_operation_file_write       uint64 = 0x00000010
	afc_operation_file_open_result uint64 = 0x0000000E
	afc_operation_file_read        uint64 = 0x0000000F
)

type AfcClient struct {
	deviceConn ios.DeviceConnectionInterface
	packageNum uint64
}

func (c *AfcClient) ListFiles(path string) ([]string, error) {
	msg := AfcMsg{
		Operation: afc_operation_read_dir,
		Header:    []byte(path),
		Payload:   nil,
	}
	res, err := c.sendAndReceive(msg)
	if err != nil {
		return nil, err
	}
	fileList := string(res.Payload)
	if len(fileList) == 0 {
		return []string{}, nil
	}
	return strings.Split(fileList[:len(fileList)-1], string([]byte{0})), nil
}

func (c *AfcClient) ReadFileInfo(name string) (FileInfo, error) {
	msg := AfcMsg{
		Operation: afc_operation_get_file_info,
		Header:    []byte(name),
		Payload:   nil,
	}
	res, err := c.sendAndReceive(msg)
	if err != nil {
		return FileInfo{}, err
	}
	return parseFileInfo(res.Payload)
}

func (c *AfcClient) OpenFileReadOnly(filePath string) (uint64, error) {
	pathBytes := []byte(filePath)
	headerLength := 8 + uint64(len(pathBytes))
	headerPayload := make([]byte, headerLength)
	binary.LittleEndian.PutUint64(headerPayload, afc_fopen_ronly)
	copy(headerPayload[8:], pathBytes)

	msg := AfcMsg{
		Operation: afc_operation_file_open,
		Header:    headerPayload,
		Payload:   nil,
	}

	res, err := c.sendAndReceive(msg)
	if err != nil {
		return 0, err
	}
	fd := binary.LittleEndian.Uint64(res.Header)
	return fd, nil
}

func (c *AfcClient) CloseFile(fd uint64) error {
	header := make([]byte, 8)
	binary.LittleEndian.PutUint64(header, fd)

	msg := AfcMsg{
		Operation: afc_operation_file_close,
		Header:    header,
		Payload:   nil,
	}

	_, err := c.sendAndReceive(msg)
	return err
}

func (c *AfcClient) ReadFully(fd uint64) ([]byte, error) {
	type headerPayload struct {
		handle uint64
		length uint64
	}
	hp := headerPayload{
		handle: fd,
		length: 8 * 1024,
	}
	buf := bytes.NewBuffer(nil)
	binary.Write(buf, binary.LittleEndian, hp)

	file := bytes.NewBuffer(nil)

	msg := AfcMsg{
		Operation: afc_operation_file_read,
		Header:    buf.Bytes(),
		Payload:   nil,
	}

	for {
		res, err := c.sendAndReceive(msg)
		if err != nil {
			return nil, err
		}
		if len(res.Payload) == 0 {
			break
		}
		file.Write(res.Payload)
	}
	return file.Bytes(), nil
}

func (c *AfcClient) sendPacket(msg AfcMsg) error {
	headerLength := uint64(len(msg.Header))

	this_length := afc_header_size + headerLength
	totalLength := this_length + uint64(len(msg.Payload))
	header := AfcPacketHeader{
		Magic:         afc_magic,
		Packet_num:    c.packageNum,
		Operation:     msg.Operation,
		This_length:   this_length,
		Entire_length: totalLength,
	}
	c.packageNum++
	packet := AfcPacket{header: header, headerPayload: msg.Header, payload: msg.Payload}

	err := Encode(packet, c.deviceConn.Writer())
	if err != nil {
		return err
	}
	return nil
}

func (c *AfcClient) receivePacket() (AfcMsg, error) {
	packet, err := Decode(c.deviceConn.Reader())
	if err != nil {
		return AfcMsg{}, err
	}
	msg := AfcMsg{
		Operation: packet.header.Operation,
		Header:    packet.headerPayload,
		Payload:   packet.payload,
	}
	return msg, nil
}

func (c *AfcClient) sendAndReceive(msg AfcMsg) (AfcMsg, error) {
	err := c.sendPacket(msg)
	if err != nil {
		return AfcMsg{}, err
	}
	res, err := c.receivePacket()
	return res, err
}

type AfcMsg struct {
	Operation uint64
	Header    []byte
	Payload   []byte
}

func parseFileInfo(b []byte) (FileInfo, error) {
	parts := strings.Split(string(b), "\u0000")

	var size, blocks, nLink, time, birthtime uint64
	var format IFormat

	for i := 1; i < len(parts); i = i + 2 {
		key := parts[i-1]
		val := parts[i]
		switch key {
		case "st_size":
			n, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return FileInfo{}, fmt.Errorf("failed to convert 'st_size' value: %s. %w", val, err)
			}
			size = n
		case "st_blocks":
			n, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return FileInfo{}, fmt.Errorf("failed to convert 'st_blocks' value: %s. %w", val, err)
			}
			blocks = n
		case "st_nlink":
			n, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return FileInfo{}, fmt.Errorf("failed to convert 'st_nlink' value: %s. %w", val, err)
			}
			nLink = n
		case "st_ifmt":
			switch val {
			case IFDIR:
				format = IFDIR
			case IFREG:
				format = IFREG
			default:
				log.WithField("ifmt", val).Warn("unknown format")
			}
		case "st_mtime":
			n, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return FileInfo{}, fmt.Errorf("failed to convert 'st_mtime' value: %s. %w", val, err)
			}
			time = n
		case "st_birthtime":
			n, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return FileInfo{}, fmt.Errorf("failed to convert 'st_birthtime' value: %s. %w", val, err)
			}
			birthtime = n

		}
	}
	return FileInfo{
		Size:      size,
		Blocks:    blocks,
		NLink:     nLink,
		IFmt:      format,
		MTime:     time,
		BirthTime: birthtime,
	}, nil
}

type FileInfo struct {
	Size      uint64
	Blocks    uint64
	NLink     uint64
	IFmt      IFormat
	MTime     uint64
	BirthTime uint64
}

type IFormat string

const (
	IFDIR = "S_IFDIR"
	IFREG = "S_IFREG"
)
