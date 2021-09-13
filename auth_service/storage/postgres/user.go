package postgres

import (
	"auth_service/app"
	"database/sql"
	"fmt"

	"github.com/pkg/errors"
)

func (db *DBPostgres) CreateUser(user *app.User) error {
	var userID uint
	row := db.QueryRow("INSERT INTO users (fname,lname,email,password,organisation,admin) VALUES($1,$2,$3,$4,$5,$6) RETURNING id",
		user.Fname, user.Lname, user.Email, user.PasswordHash, user.Organisation, user.Admin)
	if err := row.Scan(&userID); err != nil {
		return errors.Wrap(err, "query err")
	}

	user.ID = userID
	return nil
}

func (db *DBPostgres) GetUserByLogin(email string) (*app.User, error) {
	var user app.User
	row := db.QueryRow("SELECT id, email, password, admin FROM users WHERE email = $1", email)
	err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Admin)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no user with such login")
		}
		return nil, errors.Wrap(err, "query err")
	}
	return &user, nil
}

func (db *DBPostgres) GetUserByID(id uint) (*app.User, error) {
	var user app.User
	row := db.QueryRow("SELECT id,fname,lname, email, password, organisation FROM users WHERE id = $1", id)
	err := row.Scan(&user.ID, &user.Fname, &user.Lname, &user.Email, &user.PasswordHash, &user.Organisation)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no user with such id")
		}
		return nil, errors.Wrap(err, "query err")
	}

	return &user, nil
}
func (db *DBPostgres) PutUserByID(uid uint, user *app.User) (*app.User, error) {
	var updatedUser app.User

	fmt.Println("UID", uid)
	_, err := db.Exec("UPDATE users set fname=$2,lname=$3,organisation=$4 WHERE id = $1", uid, user.Fname, user.Lname, user.Organisation)
	if err != nil {

		return nil, errors.Wrap(err, "query err")
	}
	row := db.QueryRow("SELECT id,fname,lname, email, password, organisation FROM users WHERE id = $1", uid)

	err = row.Scan(&updatedUser.ID, &updatedUser.Fname, &updatedUser.Lname, &updatedUser.Email, &updatedUser.PasswordHash, &updatedUser.Organisation)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no user with such id")
		}
		return nil, errors.Wrap(err, "query err")
	}
	return &updatedUser, nil
}

func (db *DBPostgres) DeleteUserByID(id uint) (*app.User, error) {
	var user app.User

	row := db.QueryRow("DELETE from users WHERE id = $1", id)
	err := row.Scan(&user.ID, &user.Fname, &user.Lname, &user.Email, &user.PasswordHash, &user.Organisation)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no user with such id")
		}
		return nil, errors.Wrap(err, "query err")
	}

	return &user, nil
}

func (db *DBPostgres) NewSecretKey(uid uint, secret *app.Secret) (*app.Secret, error) {
	var NewSecret app.Secret
	row := db.QueryRow("INSERT INTO user_secret_keys (uid,secret_key) VALUES($1,$2) RETURNING id",
		uid, secret.SecretKey)
	if err := row.Scan(&NewSecret.SecretKey); err != nil {
		return nil, errors.Wrap(err, "query err")
	}

	return &NewSecret, nil
}
