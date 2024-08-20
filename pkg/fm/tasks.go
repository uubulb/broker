package fm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/pkg/sftp"

	pb "github.com/uubulb/broker/proto"
)

type Task struct {
	taskClient pb.NezhaService_IOStreamClient
	printf     func(string, ...interface{})
	remoteData *pb.IOStreamData
	sfc        *sftp.Client
	tmpDir     string
}

func NewFMClient(client pb.NezhaService_IOStreamClient, sftpClient *sftp.Client, td string, printFunc func(string, ...interface{})) *Task {
	return &Task{
		taskClient: client,
		printf:     printFunc,
		sfc:        sftpClient,
		tmpDir:     td,
	}
}

func (t *Task) DoTask(data *pb.IOStreamData) {
	t.remoteData = data

	switch t.remoteData.Data[0] {
	case 0:
		t.listDir()
	case 1:
		go t.download()
	case 2:
		t.upload()
	}
}

func (t *Task) listDir() {
	dir := string(t.remoteData.Data[1:])
	var entries []fs.FileInfo
	var err error
	for {
		entries, err = t.sfc.ReadDir(dir)
		if err != nil {
			wd, err := t.sfc.Getwd()
			if err != nil {
				t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
				return
			}
			dir = wd + string(filepath.Separator)
			continue
		}
		break
	}
	var buffer bytes.Buffer
	td := Create(&buffer, dir)
	for _, e := range entries {
		newBin := AppendFileName(td, e.Name(), e.IsDir())
		td = newBin
	}
	t.taskClient.Send(&pb.IOStreamData{Data: td})
}

func (t *Task) download() {
	path := string(t.remoteData.Data[1:])
	file, err := t.sfc.Open(path)
	if err != nil {
		t.printf("Error opening file: %s", err)
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		t.printf("Error getting file info: %s", err)
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return
	}

	fileSize := fileInfo.Size()
	if fileSize <= 0 {
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(errors.New("requested file is empty"))})
		return
	}

	// Send header (12 bytes)
	var header bytes.Buffer
	headerData := CreateFile(&header, uint64(fileSize))
	if err := t.taskClient.Send(&pb.IOStreamData{Data: headerData}); err != nil {
		t.printf("Error sending file header: %s", err)
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return
	}

	// Save data to a temporary file
	tmp, err := os.CreateTemp(t.tmpDir, "broker-*.bin")
	if err != nil {
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return
	}
	defer tmp.Close()

	if _, err = file.WriteTo(tmp); err != nil {
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return
	}

	// Rewind to the beginning of the file
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return
	}

	buffer := make([]byte, 1024*1024)
	for {
		n, err := tmp.Read(buffer)
		if err != nil {
			if err == io.EOF {
				return
			}
			t.printf("Error reading file: %s", err)
			t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
			return
		}

		if err := t.taskClient.Send(&pb.IOStreamData{Data: buffer[:n]}); err != nil {
			t.printf("Error sending file chunk: ", err)
			t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
			return
		}
	}
}

func (t *Task) upload() {
	if len(t.remoteData.Data) < 9 {
		const err string = "data is invalid"
		t.printf(err)
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(errors.New(err))})
		return
	}

	fileSize := binary.BigEndian.Uint64(t.remoteData.Data[1:9])
	path := string(t.remoteData.Data[9:])

	file, err := t.sfc.Create(path)
	if err != nil {
		t.printf("Error creating file: %s", err)
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return
	}
	defer file.Close()

	// Save data to a temporary file first
	tmp, err := os.CreateTemp(t.tmpDir, "broker-*.bin")
	if err != nil {
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return
	}
	defer tmp.Close()

	totalReceived := uint64(0)

	t.printf("receiving file: %s, size: %d", file.Name(), fileSize)
	for totalReceived < fileSize {
		if t.remoteData, err = t.taskClient.Recv(); err != nil {
			t.printf("Error receiving data: %s", err)
			t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
			return
		}

		bytesWritten, err := tmp.Write(t.remoteData.Data)
		if err != nil {
			t.printf("Error writing to file: %s", err)
			t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
			return
		}

		totalReceived += uint64(bytesWritten)
	}

	// Rewind to the beginning of the file
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return
	}

	_, err = file.ReadFrom(tmp)
	if err != nil {
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return
	}
	t.printf("received file %s.", file.Name())
	t.taskClient.Send(&pb.IOStreamData{Data: completeIdentifier}) // NZUP
}
