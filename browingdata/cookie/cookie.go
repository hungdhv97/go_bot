package cookie

import (
	"database/sql"
	"os"
	"sort"
	"time"

	// import sqlite3 driver
	_ "github.com/mattn/go-sqlite3"

	"github.com/moond4rk/HackBrowserData/crypto"
	"github.com/moond4rk/HackBrowserData/item"
	"github.com/moond4rk/HackBrowserData/log"
	"github.com/moond4rk/HackBrowserData/utils/typeutil"
)

type ChromiumCookie []chrome_cookie

type chrome_cookie struct {
	host_key        string
	path            string
	name            string
	encrypted_value []byte
	value           string
	is_secure       bool
	is_httponly     bool
	has_expires     bool
	is_persistent   bool
	creation_utc    int64
	expires_utc     int64
}

const (
	queryChromiumCookie = `SELECT name, encrypted_value, host_key, path, creation_utc, expires_utc, is_secure, is_httponly, has_expires, is_persistent FROM cookies`
)

func (c *ChromiumCookie) Parse(masterKey []byte) error {
	db, err := sql.Open("sqlite3", item.TempChromiumCookie)
	if err != nil {
		return err
	}
	defer os.Remove(item.TempChromiumCookie)
	defer db.Close()
	rows, err := db.Query(queryChromiumCookie)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			key, host, path                               string
			isSecure, isHTTPOnly, hasExpire, isPersistent int
			createDate, expireDate                        int64
			value, encryptValue                           []byte
		)
		if err = rows.Scan(&key, &encryptValue, &host, &path, &createDate, &expireDate, &isSecure, &isHTTPOnly, &hasExpire, &isPersistent); err != nil {
			log.Warn(err)
		}

		cookie := chrome_cookie{
			name:            key,
			host_key:        host,
			path:            path,
			encrypted_value: encryptValue,
			is_secure:       typeutil.IntToBool(isSecure),
			is_httponly:     typeutil.IntToBool(isHTTPOnly),
			has_expires:     typeutil.IntToBool(hasExpire),
			is_persistent:   typeutil.IntToBool(isPersistent),
			creation_utc:    createDate,
			expires_utc:     expireDate,
		}
		if len(encryptValue) > 0 {
			if len(masterKey) == 0 {
				value, err = crypto.DPAPI(encryptValue)
			} else {
				value, err = crypto.DecryptPass(masterKey, encryptValue)
			}
			if err != nil {
				log.Error(err)
			}
		}
		cookie.value = string(value)
		*c = append(*c, cookie)
	}
	sort.Slice(*c, func(i, j int) bool {
		return time.Unix((*c)[i].creation_utc, 0).After(time.Unix((*c)[j].creation_utc, 0))
	})
	return nil
}

func (c *ChromiumCookie) Name() string {
	return "cookie"
}

func (c *ChromiumCookie) Len() int {
	return len(*c)
}

type FirefoxCookie []firefox_cookie

type firefox_cookie struct {
	name         string
	host         string
	path         string
	isSecure     bool
	isHttpOnly   bool
	creationTime int64
	expiry       int64
	value        string
}

const (
	queryFirefoxCookie = `SELECT name, value, host, path, creationTime, expiry, isSecure, isHttpOnly FROM moz_cookies`
)

func (f *FirefoxCookie) Parse(_ []byte) error {
	db, err := sql.Open("sqlite3", item.TempFirefoxCookie)
	if err != nil {
		return err
	}
	defer os.Remove(item.TempFirefoxCookie)
	defer db.Close()

	rows, err := db.Query(queryFirefoxCookie)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			name, value, host, path string
			isSecure, isHTTPOnly    int
			creationTime, expiry    int64
		)
		if err = rows.Scan(&name, &value, &host, &path, &creationTime, &expiry, &isSecure, &isHTTPOnly); err != nil {
			log.Warn(err)
		}
		*f = append(*f, firefox_cookie{
			name:         name,
			host:         host,
			path:         path,
			isSecure:     typeutil.IntToBool(isSecure),
			isHttpOnly:   typeutil.IntToBool(isHTTPOnly),
			creationTime: creationTime,
			expiry:       expiry,
			value:        value,
		})
	}

	sort.Slice(*f, func(i, j int) bool {
		return time.Unix((*f)[i].creationTime, 0).After(time.Unix((*f)[j].creationTime, 0))
	})
	return nil
}

func (f *FirefoxCookie) Name() string {
	return "cookie"
}

func (f *FirefoxCookie) Len() int {
	return len(*f)
}
