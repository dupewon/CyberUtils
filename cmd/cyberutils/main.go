package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dupewon/cyberutils/pkg/hash"
	"github.com/dupewon/cyberutils/pkg/jwt"
	"github.com/dupewon/cyberutils/pkg/password"
	"github.com/dupewon/cyberutils/pkg/random"
)

func main() {
	genPwd := flag.Bool("password", false, "generate a password")
	pwdLen := flag.Int("length", 20, "password length")
	useSymbols := flag.Bool("symbols", true, "include symbols")
	genUUID := flag.Bool("uuid", false, "generate a UUID")
	hashStr := flag.String("hash", "", "hash a string")
	jwtSub := flag.String("jwt-subject", "", "generate a JWT")
	jwtSecret := flag.String("jwt-secret", "default-secret", "JWT secret")

	flag.Parse()

	switch {
	case *genPwd:
		pwd, err := password.Generate(*pwdLen, *useSymbols)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		s := password.Check(pwd)
		fmt.Printf("%s (score: %d)\n", pwd, s.Score)

	case *genUUID:
		fmt.Println(random.UUID())

	case *hashStr != "":
		fmt.Printf("sha256: %s\n", hash.SHA256([]byte(*hashStr)))
		fmt.Printf("blake2b: %s\n", hash.BLAKE2b_256([]byte(*hashStr)))

	case *jwtSub != "":
		claims := jwt.Claims{
			Subject:   *jwtSub,
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		}
		token, err := jwt.New(claims, []byte(*jwtSecret))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(token)

	default:
		flag.PrintDefaults()
	}
}
