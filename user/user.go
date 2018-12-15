package user

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
)

const userFile = "/etc/passwd"

type User struct {
	Uid      string // 用户ID
	Gid      string // 初级组ID
	Username string
	Name     string
	HomeDir  string
}

var colon = []byte{':'}

func LookupUserId(uid string) (*User, error) {
	f, err := os.Open(userFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return findUserId(uid, f)
}

func findUserId(uid string, r io.Reader) (*User, error) {
	_, e := strconv.Atoi(uid)
	if e != nil {
		return nil, e
	}
	bs := bufio.NewScanner(r)
	substr := []byte(":" + uid)
	for bs.Scan() {
		lineBytes := bs.Bytes()

		if !bytes.Contains(lineBytes, substr) || bytes.Count(lineBytes, colon) < 6 {
			continue
		}
		text := strings.TrimSpace(removeComment(string(lineBytes)))
		// kevin:x:1005:1006::/home/kevin:/usr/bin/zsh
		parts := strings.SplitN(text, ":", 7)
		if len(parts) < 6 {
			continue
		}
		if parts[2] == uid {
			return buildUser(parts), nil
		}
	}
	if err := bs.Err(); err != nil {
		return nil, err
	}
	return nil, unknownUserIdError(uid)
}

// buildUser builds a *User from the parts array. The fields in parts
// correspond to the colon-delimited fields in the /etc/passwd file. The caller
// is responsible for validating parts.
func buildUser(parts []string) *User {
	u := &User{
		Username: parts[0],
		Uid:      parts[2],
		Gid:      parts[3],
		Name:     parts[4],
		HomeDir:  parts[5],
	}
	// The pw_gecos field isn't quite standardized. Some docs
	// say: "It is expected to be a comma separated list of
	// personal data where the first item is the full name of the
	// user."
	if i := strings.Index(u.Name, ","); i >= 0 {
		u.Name = u.Name[:i]
	}
	return u
}

func findUsername(name string, r io.Reader) (*User, error) {
	bs := bufio.NewScanner(r)
	// looking for the first field
	substr := []byte(name + ":")
	for bs.Scan() {
		lineBytes := bs.Bytes()
		if !bytes.Contains(lineBytes, substr) || bytes.Count(lineBytes, colon) < 6 {
			continue
		}
		text := strings.TrimSpace(removeComment(string(lineBytes)))
		// kevin:x:1005:1006::/home/kevin:/usr/bin/zsh
		parts := strings.SplitN(text, ":", 7)
		if len(parts) < 6 {
			continue
		}
		if parts[0] == name {
			return buildUser(parts), nil
		}
	}
	if err := bs.Err(); err != nil {
		return nil, err
	}
	return nil, unknownUserError(name)
}

// removeComment returns line, removing any '#' byte and any following
// bytes.
func removeComment(line string) string {
	if i := strings.Index(line, "#"); i != -1 {
		return line[:i]
	}
	return line
}

func unknownUserError(user string) error {
	return errors.New("UnknownUserError: " + user)
}

func unknownUserIdError(id string) error {
	return errors.New("UnknownUserIdError: " + id)
}
