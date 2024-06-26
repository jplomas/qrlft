package sign

import (
	"encoding/hex"
	"errors"
	"os"

	"github.com/theQRL/go-qrllib/dilithium"
)

func SignMessage(message []byte, hexseed string) string {
	// fmt.Print(hex.EncodeToString(message[:]) + "\n")
	d, err := dilithium.NewDilithiumFromHexSeed(hexseed)
	if err != nil {
		panic("failed to generate new dilithium from seed " + err.Error())
	}

	signature, err := d.Sign(message)
	if err != nil {
		panic("failed to sign " + err.Error())
	}
	return hex.EncodeToString(signature[:])
}

func SignFile(filename string, hexseed string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	fileinfo, err := file.Stat()
	if err != nil {
		return "", err
	}

	if fileinfo.IsDir() {
		return "", errors.New("file is a directory")
	}

	filesize := fileinfo.Size()
	buffer := make([]byte, filesize)

	bytesread, err := file.Read(buffer)
	if err != nil {
		return "", err
	}
	return SignMessage(buffer[:bytesread], hexseed), nil
}

func SignString(stringToSign string, hexseed string) (string, error) {
	return SignMessage([]byte(stringToSign), hexseed), nil
}
