package app

import (
	"auth_service/config"
	"auth_service/proto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           uint
	Fname        string
	Lname        string
	Organisation string
	Email        string
	PasswordHash string
	Admin        bool
}

type UserClaims struct {
	ID    uint `json:"id"`
	Admin bool `json:"admin"`
	jwt.StandardClaims
}

type Secret struct {
	SecretId   int
	SecretKey  string
	ExpireDate string
	CreatedAt  string
}

//RefreshTokens generate new user access and refresh tokens
func (u *User) RefreshTokens(config *config.Config) (*proto.Tokens, error) {
	aToken, aExp, err := u.genToken([]byte(config.AccessKey), config.AccessExpMin)
	if err != nil {
		return nil, fmt.Errorf("generate access token error: %v", err)
	}

	rToken, _, err := u.genToken([]byte(config.RefreshKey), config.RefreshExpMin)
	if err != nil {
		return nil, fmt.Errorf("generate refresh token error: %v", err)
	}

	return &proto.Tokens{
		AccessToken:   aToken,
		RefreshToken:  rToken,
		AccessExpires: aExp,
	}, nil
}

//HashPassword hashes user password
func (u *User) HashPassword() error {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(u.PasswordHash), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hashedPass)
	return nil
}

//PasswordIsValid check user password
func (u *User) PasswordIsValid(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

func (u *User) genToken(key []byte, expMin int) (string, int64, error) {
	//set claims
	exp := time.Now().Add(time.Minute * time.Duration(expMin)).Unix()
	claims := UserClaims{
		u.ID,
		u.Admin,
		jwt.StandardClaims{
			ExpiresAt: exp,
		},
	}
	//generate  token
	token, err := generateToken(key, claims)
	if err != nil {
		return "", 0, fmt.Errorf("generate token error: %v", err)
	}
	return token, exp, nil
}

func generateToken(key []byte, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(key)
}

//UserIDFromToken parse token string, validate and get user id from claims
func UserIDFromToken(tokenString string, key string) (uint, error) {
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return 0, fmt.Errorf("couldn't parse token")
			} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				// Token is either expired or not active yet
				return 0, fmt.Errorf("token is either expired or not active yet")
			} else {
				return 0, fmt.Errorf("couldn't handle this token")
			}
		}
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok || claims.ID == 0 {
		return 0, fmt.Errorf("claims bad structure or user id is not set")
	}
	return claims.ID, nil
}

func EncryptSecret(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func DecryptSecret(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}
