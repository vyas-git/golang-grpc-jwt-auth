package postgres

import (
	"auth_service/app"
	"database/sql"
	"fmt"
	"time"

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
	row := db.QueryRow("SELECT fname,lname, email, organisation FROM users WHERE id = $1", id)
	err := row.Scan(&user.Fname, &user.Lname, &user.Email, &user.Organisation)
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
	row := db.QueryRow("INSERT INTO user_secret_keys (uid,secret_key,expire_date) VALUES($1,$2,$3) RETURNING id,secret_key,expire_date,created_at",
		uid, secret.SecretKey, time.Now().AddDate(0, 0, +2))
	if err := row.Scan(&NewSecret.SecretId, &NewSecret.SecretKey, &NewSecret.ExpireDate, &NewSecret.CreatedAt); err != nil {
		return nil, errors.Wrap(err, "query err")
	}

	return &NewSecret, nil
}

func (db *DBPostgres) GetSecrets(uid uint) (*[]app.Secret, error) {
	var secrets []app.Secret
	rows, err := db.Query("SELECT id,secret_key,expire_date,created_at from user_secret_keys where uid=$1",
		uid)
	if err != nil {
		return nil, errors.Wrap(err, "query err")
	}
	defer rows.Close()

	// Loop through rows, using Scan to assign column data to struct fields.
	for rows.Next() {
		var secret app.Secret
		if err := rows.Scan(&secret.SecretId, &secret.SecretKey, &secret.ExpireDate, &secret.CreatedAt); err != nil {
			return &secrets, err
		}
		secrets = append(secrets, secret)
	}

	return &secrets, nil
}

func (db *DBPostgres) GetSecretExpired(secretid uint) (bool, error) {
	return true, nil
}
func (db *DBPostgres) DeleteSecret(secretid uint) ([]*app.Secret, error) {
	return nil, nil
}
