package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aldy505/phc-crypto/argon2"
	"github.com/aldy505/phc-crypto/bcrypt"
	"github.com/aldy505/phc-crypto/pbkdf2"
	"github.com/aldy505/phc-crypto/scrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArgon2(t *testing.T) {
	buff := bytes.NewBuffer(nil)
	tool := Argon2{
		HashCommon: HashCommon{
			Password: "password",
			writer:   buff,
		},
		Iterations: 1,
	}

	err := tool.Run()
	require.NoError(t, err)

	hash := strings.TrimSpace(buff.String())
	valid, err := argon2.Verify(hash, "password")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestScrypt(t *testing.T) {
	buff := bytes.NewBuffer(nil)
	tool := Scrypt{
		HashCommon: HashCommon{
			Password: "password",
			writer:   buff,
		},
		Cost: 2,
	}

	err := tool.Run()
	require.NoError(t, err)

	hash := strings.TrimSpace(buff.String())
	valid, err := scrypt.Verify(hash, "password")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestBcrypt(t *testing.T) {
	buff := bytes.NewBuffer(nil)
	tool := Bcrypt{
		HashCommon: HashCommon{
			Password: "password",
			writer:   buff,
		},
		Rounds: 1,
	}

	err := tool.Run()
	require.NoError(t, err)

	hash := strings.TrimSpace(buff.String())
	valid, err := bcrypt.Verify(hash, "password")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestPBKDF2(t *testing.T) {
	buff := bytes.NewBuffer(nil)
	tool := PBKDF2{
		HashCommon: HashCommon{
			Password: "password",
			writer:   buff,
		},
		Iterations: 1,
	}

	err := tool.Run()
	require.NoError(t, err)

	hash := strings.TrimSpace(buff.String())
	valid, err := pbkdf2.Verify(hash, "password")
	require.NoError(t, err)
	assert.True(t, valid)
}
