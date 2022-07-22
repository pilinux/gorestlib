package common

// github.com/pilinux/gorestlib
// The MIT License (MIT)
// Copyright (c) 2022 pilinux

import "github.com/alexedwards/argon2id"

type hashPassConfig struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

// HashPass - securely hash passwords using Argon2id
func HashPass(config hashPassConfig, pass string) (string, error) {
	configureHash := config
	params := &argon2id.Params{
		Memory:      configureHash.memory * 1024, // the amount of memory used by the Argon2 algorithm (in kibibytes)
		Iterations:  configureHash.iterations,    // the number of iterations (or passes) over the memory
		Parallelism: configureHash.parallelism,   // the number of threads (or lanes) used by the algorithm
		SaltLength:  configureHash.saltLength,    // length of the random salt. 16 bytes is recommended for password hashing
		KeyLength:   configureHash.keyLength,     // length of the generated key (or password hash). 16 bytes or more is recommended
	}
	h, err := argon2id.CreateHash(pass, params)
	if err != nil {
		return "", err
	}
	return h, err
}
