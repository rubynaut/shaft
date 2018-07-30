package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	Trace *log.Logger
	Info  *log.Logger
)

func logEnable(enable bool) {
	sink := ioutil.Discard
	if enable {
		sink = os.Stdout
	}
	Trace = log.New(sink,
		"TRACE: ",
		log.Lmicroseconds|log.Lshortfile)

	Info = log.New(sink,
		"INFO:  ",
		log.Lmicroseconds|log.Lshortfile)
}

func offsetToByte(offset int) int {
	return offset / 8
}
func offsetToBit(offset int) int {
	return offset % 8
}

type Stats struct {
	started        time.Time
	bytes          int
	maxHashes      uint64
	maxHashedBytes uint64
	curHashes      uint64
	curHashedBytes uint64
}

func NewStats(bytes int) *Stats {
	maxHashes := uint64(bytes * 8)
	maxHashedBytes := uint64(bytes) * maxHashes / 2

	return &Stats{time.Now(), bytes, maxHashes, maxHashedBytes, 0, 0}
}

func (s *Stats) hashed(hashedBytes int) {
	atomic.AddUint64(&s.curHashes, 1)
	atomic.AddUint64(&s.curHashedBytes, uint64(hashedBytes))
}

func (s *Stats) lap() (progress int, elapsedSec uint64, estimateSec uint64, hashesPerSec uint64) {
	elapsedSec = uint64(time.Since(s.started).Seconds())
	if elapsedSec > 0 {
		hashesPerSec = s.curHashedBytes / (1024 * 1024 * elapsedSec)
	}

	progress = int(s.curHashes * 100 / s.maxHashes)
	if s.curHashedBytes > 0 {
		estimateSec = elapsedSec * s.maxHashedBytes / s.curHashedBytes
	}
	return
}

func (s *Stats) lap4() (progress int, elapsedSec uint64, estimateSec uint64, hashesPerSec uint64) {
	elapsedSec = uint64(time.Since(s.started).Seconds())
	if elapsedSec > 0 {
		hashesPerSec = s.curHashes * uint64(s.bytes) / (1024 * 1024 * elapsedSec)
	}

	progress = int(s.curHashes * 100 / s.maxHashes)
	if s.curHashes > 0 {
		estimateSec = elapsedSec * s.maxHashes / s.curHashes
	}
	return
}

func (s *Stats) fin() (elapsedSec uint64, hashesPerSec uint64) {
	elapsedSec = uint64(time.Since(s.started).Seconds())
	if elapsedSec > 0 {
		hashesPerSec = s.curHashedBytes / (1024 * 1024 * elapsedSec)
	}
	return
}

// FxSha bla bla
type FxSha struct {
	blockSize int
	fixpoints [][]byte
	digest    []byte
	data      []byte
}

func NewFxSha(data []byte) *FxSha {
	sha := sha512.New()

	blockSize := sha.BlockSize()
	fixpoints := make([][]byte, 0, len(data)/blockSize+1)
	Info.Printf("NewFxSha blocksize=%d fixpoints=%d", blockSize, cap(fixpoints))

	marshaler, ok := sha.(encoding.BinaryMarshaler)
	if !ok {
		log.Fatal("sha512 does not implement encoding.BinaryMarshaler")
	}

	var start, stop int
	for i := 0; i < len(data); i += blockSize {
		s, err := marshaler.MarshalBinary()
		if err != nil {
			log.Fatal("unable to marshal hash:", err)
		}
		fixpoints = append(fixpoints, s)

		start, stop = i, i+blockSize
		if stop > len(data) {
			stop = len(data)
		}
		// Trace.Printf("NewFxSha write[%d:%d]", start, stop)
		sha.Write(data[start:stop])
	}

	// Trace.Printf("fixpoints %#v", fixpoints)
	return &FxSha{blockSize, fixpoints, sha.Sum(nil), data}
}

// Remaing data
func (s FxSha) Overwrite(offset int, p byte) hash.Hash {
	idx := offset / s.blockSize
	fixpoint := s.fixpoints[idx]

	// restore nearest sha
	sha := sha512.New()
	unmarshaler, ok := sha.(encoding.BinaryUnmarshaler)
	if !ok {
		log.Fatal("unable to prepare unmarshaler")
	}
	if err := unmarshaler.UnmarshalBinary(fixpoint); err != nil {
		Trace.Printf("UnmarshalBinary %d %#v", idx, fixpoint)
		log.Fatal("unable to unmarshal hash: ", err)
	}

	// digest change and remainder
	sha.Write(s.data[idx*s.blockSize : offset])
	sha.Write([]byte{p})
	sha.Write(s.data[offset+1:])

	return sha
}

type searchfct func(ctx context.Context, fxsha *FxSha, id int, stride int, data []byte, mdOrig []byte) (bool, int, byte)

// https://golang.org/src/crypto/sha512/sha512.go
var stats *Stats

var digString, filename string
var threads int
var verbose bool
var exhaustive bool
var forward bool
var logging bool

func main() {
	flag.StringVar(&digString, "s", "dead", "sha512 DIGEST of original data")
	flag.StringVar(&filename, "f", "f", "FILE to inspect for bit errors")
	flag.IntVar(&threads, "t", 1, "number of THREADS to utilize")
	flag.BoolVar(&exhaustive, "x", false, "exhaustive search")
	flag.BoolVar(&forward, "F", false, "use (slow) FORWARD search")
	flag.BoolVar(&verbose, "v", false, "enable VERBOSE")
	flag.BoolVar(&logging, "l", false, "enable LOGGING")

	flag.Bool("Version", false, "V0.1.729")
	flag.Parse()

	logEnable(logging)
	if logging && verbose {
		Trace.Println("Disable verbose since logging")
		verbose = false
	}

	searchfct := searchBackward
	if forward {
		searchfct = searchForward
	}
	dig, err := hex.DecodeString(digString)
	if err != nil {
		log.Fatal(err)
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	fxsha := NewFxSha(data)
	if bytes.Equal(dig, fxsha.digest) {
		fmt.Printf("File matches digest\n")
		return
	}

	stats = NewStats(len(data))

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			success, offset, byt := searchfct(ctx, fxsha, i, threads, data, dig)
			if success {
				fmt.Printf("*** file[0x%06x] = 0x%02x\n", offset, byt)
				if !exhaustive {
					cancel()
				}
			}
		}(i)
	}

	waitCompletion(&wg, cancel)
	//		fmt.Printf("No match found\n")
}

func searchBackward(ctx context.Context, fxsha *FxSha, id int, stride int, data []byte, mdOrig []byte) (bool, int, byte) {
	Trace.Printf("Worker %d started\n", id)
	var offset int = -1
	var solution byte

	// step through data by stride bits
loop:
	for i := len(data)*8 - 1 - id; i > 0; i -= stride {
		bit, byt := offsetToBit(i), offsetToByte(i)

		select {
		case <-ctx.Done():
			Trace.Println("Worker stopped")
			break loop

		default:
			b := (1 << uint(bit)) ^ data[byt]
			md := fxsha.Overwrite(byt, b).Sum(nil)
			if bytes.Equal(mdOrig, md) {
				offset = byt
				solution = b
				Trace.Printf("Worker %d found fix at %04x.                        \n", id, byt)
				if !exhaustive {
					break loop
				}
				Trace.Println("Continue")
			}
			// bytes "actually" hashed
			stats.hashed(len(data) - byt)
		}
	}

	Trace.Printf("Worker %d done\n", id)
	return offset >= 0, offset, solution
}

func searchForward(ctx context.Context, fxsha *FxSha, id int, stride int, data []byte, mdOrig []byte) (bool, int, byte) {
	Trace.Printf("Worker %d started\n", id)
	var offset int = -1
	var solution byte

	// step through data by stride bits
loop:
	for i := id; i < len(data)*8; i += stride {
		bit, byt := offsetToBit(i), offsetToByte(i)

		select {
		case <-ctx.Done():
			Trace.Println("Worker stopped")
			break loop

		default:
			b := (1 << uint(bit)) ^ data[byt]
			md := fxsha.Overwrite(byt, b).Sum(nil)
			if bytes.Equal(mdOrig, md) {
				offset = byt
				solution = b
				Trace.Printf("Worker %d found fix at %04x.                        \n", id, byt)
				if !exhaustive {
					break loop
				}
				Trace.Println("Continue")
			}
			stats.hashed(len(data) - byt)
		}
	}

	Trace.Printf("Worker %d done\n", id)
	return offset >= 0, offset, solution
}

func waitCompletion(wg *sync.WaitGroup, cancel context.CancelFunc) {
	animation := "-\\|/"
	animationIdx := 0

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		defer close(done)
		Trace.Println("WaitGroup waiting ..")
		wg.Wait()
		Trace.Println("WaitGroup done")
	}()

	var interrupted os.Signal
	go func() { // FIXME howto stop this GR
		interrupted = <-sigs
		Trace.Println("Signal received")
		cancel()
	}()

	if verbose {
		var sporadic int
		Trace.Println("Main loop ..")
	loop:
		for {
			select {
			case <-done:
				break loop

			case <-time.After(150 * time.Millisecond):
				if sporadic%10 == 0 {
					progress, elapsedSec, estimateSec, hashesPerSec := stats.lap()
					fmt.Printf("%c [%2d%% done in %ds of ~%ds] hashing %dMB/s\r",
						animation[animationIdx%4],
						progress, elapsedSec, estimateSec, hashesPerSec)
				} else {
					fmt.Printf("%c \r", animation[animationIdx%4])
				}
				sporadic++
				animationIdx++

			}
		}
	} else {
		Trace.Println("Main wait ..")
		<-done
	}

	elapsedSec, hashesPerSec := stats.fin()

	if verbose {
		fmt.Printf("                                                                                             \r")
		fmt.Printf("Crunched %d bytes in %d threads for %ds hashing %dMB/s on average\n",
			stats.bytes, threads, elapsedSec, hashesPerSec)
	}

	if interrupted != nil {
		Info.Printf("Interrupted after %ds hashing %dMB/s on average\n",
			elapsedSec, hashesPerSec)
	} else {
		// fmt.Printf("Crunched %d bytes in %d threads for %ds hashing %dMB/s on average to restore %s...\n",
		// 	stats.bytes, threads, elapsedSec, hashesPerSec, digString[0:8])
		Info.Printf("Crunched %d bytes in %d threads for %ds hashing %dMB/s on average\n",
			stats.bytes, threads, elapsedSec, hashesPerSec)
	}

}
