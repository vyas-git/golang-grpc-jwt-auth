package storage

import (
	"auth_service/app"
	"auth_service/config"
	"auth_service/storage/postgres"
	"fmt"
)

type Storage interface {
	CreateUser(user *app.User) error
	GetUserByLogin(login string) (*app.User, error)
	GetUserByID(id uint) (*app.User, error)
	PutUserByID(id uint, user *app.User) (*app.User, error)
	DeleteUserByID(id uint) (string, error)

	NewSecretKey(id uint, secret *app.Secret) (*app.Secret, error)
	GetSecrets(uid uint) (*[]app.Secret, error)
	GetSecretExpired(secretid uint) (string, error)
	DeleteSecret(secretid uint, uid uint) (*[]app.Secret, error)
	Close() error
}

func New(conf config.Config) (Storage, error) {
	uri := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=disable",
		conf.Db.User, conf.Db.Pass, conf.Db.Host, conf.Db.Port, conf.Db.Name)
	fmt.Println(uri)
	return postgres.New(uri)
}
