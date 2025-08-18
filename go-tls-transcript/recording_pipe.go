package susgobench

import (
	"encoding/binary"
	"net"
	"os"
	"time"
)

// Transmission is a chunk of bytes sent by a TLS participant.
type Transmission struct {
	// "client" or "server"
	Name string
	Data []byte
}

// Each clients owns a dummy connection
type RecordingPipe struct {
	// "client" or "server"
	name string
	// a channel used to read bytes from the peer
	readCh chan []byte
	// a channel used to writes bytes to the peer
	writeCh chan []byte

	// TODO: get rid of this buffer
	readBuf []byte

	// stores all of the transcripts
	Transcript *[]Transmission
}

func NewClientServerRecordingPipe() (*RecordingPipe, *RecordingPipe, *[]Transmission) {
	clientTransmit := make(chan []byte)
	serverTransmit := make(chan []byte)

	transcript := make([]Transmission, 0)

	clientConn := NewRecordingPipe("client", serverTransmit, clientTransmit)
	serverConn := NewRecordingPipe("server", clientTransmit, serverTransmit)

	// Go is giving me anxiety. How did it decide what transcript would be? Implicit
	// default?
	clientConn.Transcript = &transcript
	serverConn.Transcript = &transcript

	return clientConn, serverConn, &transcript
}

func NewRecordingPipe(name string, readCh, writeCh chan []byte) *RecordingPipe {
	return &RecordingPipe{
		name:    name,
		readCh:  readCh,
		writeCh: writeCh,
	}
}

func (pipe *RecordingPipe) Read(destination []byte) (n int, err error) {
	if len(pipe.readBuf) == 0 {
		pipe.readBuf = <-pipe.readCh
	}

	n = copy(destination, pipe.readBuf)
	pipe.readBuf = pipe.readBuf[n:]

	return n, nil
}

func (pipe *RecordingPipe) Write(source []byte) (n int, err error) {
	pipe.writeCh <- source

	dataCopy := make([]byte, len(source))
	copy(dataCopy, source)
	transmission := Transmission{
		Name: pipe.name,
		Data: dataCopy,
	}
	*pipe.Transcript = append(*pipe.Transcript, transmission)

	return len(source), nil
}

func (pipe *RecordingPipe) Close() error {
	return nil
}

func (pipe *RecordingPipe) LocalAddr() net.Addr {
	return dummyAddr{}
}

func (pipe *RecordingPipe) RemoteAddr() net.Addr {
	return dummyAddr{}
}

func (pipe *RecordingPipe) SetDeadline(t time.Time) error {
	return nil
}

func (pipe *RecordingPipe) SetReadDeadline(t time.Time) error {
	return nil
}

func (pipe *RecordingPipe) SetWriteDeadline(t time.Time) error {
	return nil
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "dummy" }
func (dummyAddr) String() string  { return "dummy" }

func peerByte(peer string) byte {
	switch peer {
	case "client":
		return 'c'
	case "server":
		return 's'
	default:
		panic("unknown peer")
	}
}

func DumpTranscript(filename string, transcript *[]Transmission) error {
	outFile := "resources/" + filename + "_transcript.bin"
	f, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, t := range *transcript {
		// write Peer
		peerBytes := peerByte(t.Name)
		f.Write([]byte{peerBytes})

		// write Data
		if err := binary.Write(f, binary.BigEndian, uint64(len(t.Data))); err != nil {
			return err
		}
		if _, err := f.Write(t.Data); err != nil {
			return err
		}
	}

	return nil
}
