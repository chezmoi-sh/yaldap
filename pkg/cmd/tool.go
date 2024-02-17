package cmd

import (
	allow_fmt "fmt"

	"github.com/aldy505/phc-crypto/argon2"
	"github.com/aldy505/phc-crypto/bcrypt"
	"github.com/aldy505/phc-crypto/pbkdf2"
	"github.com/aldy505/phc-crypto/scrypt"
)

type (
	Tools struct {
		*Base `kong:"-"`

		Hash Hash `cmd:"" help:"Hashing tool"`
	}

	Hash struct {
		Argon2 Argon2 `cmd:"" name:"argon2" help:"Argon2 hashing algorithm"`
		Scrypt Scrypt `cmd:"" name:"scrypt" help:"Scrypt hashing algorithm"`
		Bcrypt Bcrypt `cmd:"" name:"bcrypt" help:"Bcrypt hashing algorithm"`
		PBKDF2 PBKDF2 `cmd:"" name:"pbkdf2" help:"PBKDF2 hashing algorithm"`
	}

	HashCommon struct {
		Password string `arg:"" name:"password" help:"Password to hash" required:""`
	}

	Argon2 struct {
		HashCommon

		Variant     string `name:"variant" enum:"i, id" help:"Variant of argon2 to use" default:"id"`
		Iterations  int    `name:"iterations" help:"Number of iterations to use" default:"10"`
		Memory      int    `name:"memory" help:"Memory to use in kibibytes" default:"64"`
		Parallelism int    `name:"parallelism" help:" Degree of parallelism to use" default:"1"`
	}

	Scrypt struct {
		HashCommon

		Blocksize   int `name:"block-size" help:"Amount of memory to use in kibibytes" default:"8"`
		Cost        int `name:"cost" help:"CPU/memory cost of the scrypt algorithm" default:"16"`
		Parallelism int `name:"parallelism" help:"Degree of parallelism to use" default:"1"`
	}

	Bcrypt struct {
		HashCommon

		Rounds int `name:"rounds" help:"Number of iterations to use as 2^rounds" default:"8"`
	}

	PBKDF2 struct {
		HashCommon

		Iterations int    `name:"iterations" help:"Number of iterations to use" default:"10"`
		Digest     string `name:"digest" enum:"md5, sha1, sha256, sha224, sha384, sha512" help:"Digest to use when applying the key derivation function" default:"sha256"`
	}
)

func (h *HashCommon) prepare() {
	// Handle password from stdin (- argument)
	if h.Password == "-" {
		allow_fmt.Scanln(&h.Password)
	}
}

func (a *Argon2) Run() error {
	a.HashCommon.prepare()
	config := argon2.Config{
		Memory:      a.Memory * 1024,
		Parallelism: a.Parallelism,
		Time:        a.Iterations,
	}
	switch a.Variant {
	case "i":
		config.Variant = argon2.I
	case "id":
		config.Variant = argon2.ID
	}

	hash, err := argon2.Hash(a.Password, config)
	if err != nil {
		return err
	}

	allow_fmt.Println(hash)
	return nil
}

func (s *Scrypt) Run() error {
	s.HashCommon.prepare()
	config := scrypt.Config{
		Cost:        s.Cost,
		Parallelism: s.Parallelism,
		Rounds:      s.Blocksize,
	}

	hash, err := scrypt.Hash(s.Password, config)
	if err != nil {
		return err
	}

	allow_fmt.Println(hash)
	return nil
}

func (b *Bcrypt) Run() error {
	b.HashCommon.prepare()
	config := bcrypt.Config{Rounds: b.Rounds}

	hash, err := bcrypt.Hash(b.Password, config)
	if err != nil {
		return err
	}

	allow_fmt.Println(hash)
	return nil
}

func (p *PBKDF2) Run() error {
	p.HashCommon.prepare()
	config := pbkdf2.Config{Rounds: p.Iterations}
	switch p.Digest {
	case "md5":
		config.HashFunc = pbkdf2.MD5
	case "sha1":
		config.HashFunc = pbkdf2.SHA1
	case "sha256":
		config.HashFunc = pbkdf2.SHA256
	case "sha224":
		config.HashFunc = pbkdf2.SHA224
	case "sha384":
		config.HashFunc = pbkdf2.SHA384
	case "sha512":
		config.HashFunc = pbkdf2.SHA512
	}

	hash, err := pbkdf2.Hash(p.Password, config)
	if err != nil {
		return err
	}

	allow_fmt.Println(hash)
	return nil
}
