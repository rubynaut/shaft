package main

import (
	"crypto/sha512"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
)

const (
	dataTemplate   = "%s.bin"
	shaTemplate    = "%s.sha512"
	sampleTemplate = "%s-%06x-%02x-%02x.bin"

	fileMode = 0644
)

func dataFileName(prefix string) string {
	return fmt.Sprintf(dataTemplate, prefix)
}
func shaFileName(prefix string) string {
	return fmt.Sprintf(shaTemplate, prefix)
}
func sampleFileName(prefix string, offset int, orig byte, flip byte) string {
	return fmt.Sprintf(sampleTemplate, prefix, offset, orig, flip)
}

func writeFile(filename string, data []byte) {
	err := ioutil.WriteFile(filename, data, fileMode)
	if err != nil {
		panic(err)
	}
}

func createData(len int) []byte {
	data := make([]byte, len)
	rand.Read(data)

	return data
}

func randInt(min int, max int) int {
	return min + rand.Intn(max-min)
}

// deprecated
func flipBit(b byte) byte {
	return (1 << uint(rand.Intn(8))) ^ b
}

func writeNSamples(sampleCnt int, data []byte, filenameFu func(int, byte, byte) string) {
	inuse := make(map[int]bool, sampleCnt)

	for len(inuse) < sampleCnt {
		offset := randInt(0, len(data))
		bytep := &data[offset]
		orig := *bytep
		flip := (1 << uint(rand.Intn(8))) ^ orig // flipBit(orig)

		*bytep = flip
		writeFile(filenameFu(offset, orig, flip), data)
		*bytep = orig

		inuse[offset] = true
	}
}

func write8Sample(data []byte, filenameFu func(int, byte, byte) string) {
	offset := randInt(0, len(data))
	bytep := &data[offset]
	orig := *bytep

	for i := uint(0); i < 8; i++ {
		flip := (1 << i) ^ orig
		*bytep = flip
		writeFile(filenameFu(offset, orig, flip), data)
		*bytep = orig
	}
}

func sha512Digest(data []byte) []byte {
	sha := sha512.New()
	sha.Write(data)

	return sha.Sum(nil)
}

func main() {
	flagFilesize := flag.Int("s", 1000, "size of data file to create")
	flagSampleCnt := flag.Int("n", 4, "number of samples to write")
	flagSample8Bits := flag.Bool("8", false, "flip all 8 bits of a single byte")
	flagWriteShaFile := flag.Bool("sha", false, "write .sha512 file containing hex-digest")
	// modeJson := flag.Bool("j", false, "write .json file describing modifications")
	// { file, hash, 1bit [ {file, offset, soll, ist} ]}
	flag.Bool("Version", false, "V0.1.728")
	flag.Parse()

	rand.Seed(int64(os.Getpid()))

	data := createData(*flagFilesize)
	sha512 := sha512Digest(data)
	sha512String := fmt.Sprintf("%x", sha512)
	prefix := sha512String[0:8]
	generateFilename := func(offset int, orig byte, flip byte) string {
		return sampleFileName(prefix, offset, orig, flip)
	}

	writeFile(dataFileName(prefix), data)
	if *flagWriteShaFile {
		writeFile(shaFileName(prefix), []byte(sha512String))
	}
	if *flagSample8Bits {
		write8Sample(data, generateFilename)
	} else {
		writeNSamples(*flagSampleCnt, data, generateFilename)
	}
}
