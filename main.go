package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/tuneinsight/lattigo/v4/ckks"
)

func main() {

	var logN, logQ, levels, scale uint64

	// Scheme params
	logN = 10
	logQ = 30
	levels = 8
	scale = logQ
	sigma := 3.19

	a := 6.0
	b := 7.0

	argCount := len(os.Args[1:])

	if argCount > 0 {
		a, _ = strconv.ParseFloat(os.Args[1], 64)

	}
	if argCount > 1 {
		b, _ = strconv.ParseFloat(os.Args[2], 64)

	}

	// Context
	var ckkscontext *ckks.CkksContext
	ckkscontext, _ = ckks.NewCkksContext(logN, logQ, scale, levels, sigma)

	kgen := ckkscontext.NewKeyGenerator()

	// Keys
	var sk *ckks.SecretKey
	var pk *ckks.PublicKey
	sk, pk, _ = kgen.NewKeyPair()

	// Encryptor
	var encryptor *ckks.Encryptor
	encryptor, _ = ckkscontext.NewEncryptor(pk)

	// Decryptor
	var decryptor *ckks.Decryptor
	decryptor, _ = ckkscontext.NewDecryptor(sk)

	// Values to encrypt
	values1 := make([]complex128, 1<<(logN-1))
	values2 := make([]complex128, 1<<(logN-1))

	values1[0] = complex(a, 0)
	values2[0] = complex(b, 0)

	fmt.Printf("HEAAN parameters : logN = %d, logQ = %d, levels = %d (%d bits), logPrecision = %d, logScale = %d, sigma = %f \n", logN, logQ, levels, 60+(levels-1)*logQ, ckkscontext.Precision(), scale, sigma)

	plaintext1 := ckkscontext.NewPlaintext(levels-1, scale)
	plaintext1.EncodeComplex(values1)
	plaintext2 := ckkscontext.NewPlaintext(levels-1, scale)
	plaintext2.EncodeComplex(values2)

	// Encryption process
	var ciphertext1, ciphertext2 *ckks.Ciphertext
	ciphertext1, _ = encryptor.EncryptNew(plaintext1)
	ciphertext2, _ = encryptor.EncryptNew(plaintext2)

	fmt.Printf("\nCipher (a): %v\n", ciphertext1)
	fmt.Printf("\nCipher (b): %v\n", ciphertext2)

	evaluator := ckkscontext.NewEvaluator()
	evaluator.Sub(ciphertext1, ciphertext2, ciphertext1)

	plaintext1, _ = decryptor.DecryptNew(ciphertext1)

	valuesTest := plaintext1.DecodeComplex()

	fmt.Printf("\nInput: %f-%f", a, b)

	fmt.Printf("\nCipher (a+b): %v\n\nDecrypted: ", *ciphertext1)

	ch := real(valuesTest[0])
	fmt.Printf("%.2f", ch)

}
