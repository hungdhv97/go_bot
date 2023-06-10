package cookie

import (
	"database/sql"
	"net/url"
	"os"
	"sort"
	"strings"

	// import sqlite3 driver
	_ "github.com/mattn/go-sqlite3"

	"github.com/moond4rk/HackBrowserData/crypto"
	"github.com/moond4rk/HackBrowserData/item"
	"github.com/moond4rk/HackBrowserData/log"
	"github.com/moond4rk/HackBrowserData/utils/typeutil"
)

type ChromiumCookie []chrome_cookie

type chrome_cookie struct {
	HostKey        string `json:"host_key" csv:"host_key"`
	Path           string `json:"path" csv:"path"`
	Name           string `json:"name" csv:"name"`
	EncryptedValue []byte `json:"encrypted_value" csv:"encrypted_value"`
	Value          string `json:"value" csv:"value"`
	IsSecure       bool   `json:"is_secure" csv:"is_secure"`
	IsHTTPOnly     bool   `json:"is_httponly" csv:"is_httponly"`
	HasExpires     bool   `json:"has_expires" csv:"has_expires"`
	IsPersistent   bool   `json:"is_persistent" csv:"is_persistent"`
	CreationUTC    int64  `json:"creation_utc" csv:"creation_utc"`
	ExpiresUTC     int64  `json:"expires_utc" csv:"expires_utc"`
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
			Name:           key,
			HostKey:        host,
			Path:           path,
			EncryptedValue: encryptValue,
			IsSecure:       typeutil.IntToBool(isSecure),
			IsHTTPOnly:     typeutil.IntToBool(isHTTPOnly),
			HasExpires:     typeutil.IntToBool(hasExpire),
			IsPersistent:   typeutil.IntToBool(isPersistent),
			CreationUTC:    createDate,
			ExpiresUTC:     expireDate,
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
		cookie.Value = string(value)
		*c = append(*c, cookie)
	}
	sort.Slice(*c, func(i, j int) bool {
		domainI := parseDomain((*c)[i].HostKey)
		domainJ := parseDomain((*c)[j].HostKey)
		if domainI == domainJ {
			return (*c)[i].HostKey < (*c)[j].HostKey
		}
		return domainI < domainJ
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
	Name         string `json:"name" csv:"name"`
	Host         string `json:"host" csv:"host"`
	Path         string `json:"path" csv:"path"`
	IsSecure     bool   `json:"is_secure" csv:"is_secure"`
	IsHTTPOnly   bool   `json:"is_httponly" csv:"is_httponly"`
	CreationTime int64  `json:"creation_time" csv:"creation_time"`
	Expiry       int64  `json:"expiry" csv:"expiry"`
	Value        string `json:"value" csv:"value"`
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
			Name:         name,
			Host:         host,
			Path:         path,
			IsSecure:     typeutil.IntToBool(isSecure),
			IsHTTPOnly:   typeutil.IntToBool(isHTTPOnly),
			CreationTime: creationTime,
			Expiry:       expiry,
			Value:        value,
		})
	}

	sort.Slice(*f, func(i, j int) bool {
		domainI := parseDomain((*f)[i].Host)
		domainJ := parseDomain((*f)[j].Host)
		if domainI == domainJ {
			return (*f)[i].Host < (*f)[j].Host
		}
		return domainI < domainJ
	})
	return nil
}

func (f *FirefoxCookie) Name() string {
	return "cookie"
}

func (f *FirefoxCookie) Len() int {
	return len(*f)
}

func parseDomain(host string) string {
	u, err := url.Parse("http://" + host)
	if err != nil {
		return host
	}
	parts := strings.Split(u.Hostname(), ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return u.Hostname()
}
