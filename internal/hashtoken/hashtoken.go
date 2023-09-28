package hashtoken

import (
	"crypto/sha1"
	"fmt"
	"os"
)

func HashRefresh(refreshToken string) string {
	hash := sha1.New()
	hash.Write([]byte(refreshToken))
	return fmt.Sprintf("%x", hash.Sum([]byte(os.Getenv("SALT"))))
}
