package auth

import (
	"encoding/json"
	"log"
	"os"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// User handles user authentication based on username and token
type User interface {
	// Sign a token and return the serialized cryptographic token.
	Login(*string, *string) error
	Authenticate(*string, *string) bool
	Logout(*string, *string) error
}

// LvldbUser implements the User interface
type LvldbUser struct {
	Db *leveldb.DB
}

// Login stores token into database
func (db *LvldbUser) Login(user *string, token *string) error {
	tokenBytes, err := db.Db.Get([]byte(*user), nil)
	var newTokens [](*string)
	if err == leveldb.ErrNotFound {
		// a new user
		newTokens = append(newTokens, token)
	} else if err != nil {
		return err
	} else {
		err = json.Unmarshal(tokenBytes, &newTokens)
		if err != nil {
			log.Printf("Error unmarshalling user token: %v during login", err)
			return err
		}
		// TODO detect duplicated tokens, which should not happen
		// We may need to store used tokens to prevent malicious user from recycling tokens
		newTokens = append(newTokens, token)
	}
	tokenJSON, err := json.Marshal(newTokens)
	err = db.Db.Put([]byte(*user), tokenJSON, nil)
	return nil
}

// Logout evicts token from the database
func (db *LvldbUser) Logout(user *string, token *string) error {
	tokenBytes, err := db.Db.Get([]byte(*user), nil)
	if err == leveldb.ErrNotFound {
		log.Printf("Could not find the user %s.", *user)
		return nil // silent this case
	} else if err != nil {
		return err
	}
	var oldTokens, newTokens [](*string)
	err = json.Unmarshal(tokenBytes, &oldTokens)
	if err != nil {
		log.Printf("Error unmarshalling user token: %v during logout", err)
		return err
	}
	for _, oldToken := range oldTokens {
		if *token != *oldToken {
			newTokens = append(newTokens, oldToken)
		}
	}
	tokenJSON, err := json.Marshal(newTokens)
	err = db.Db.Put([]byte(*user), tokenJSON, nil)
	return nil
}

// Authenticate checks if the token is still valid
func (db *LvldbUser) Authenticate(user *string, token *string) bool {
	tokenBytes, err := db.Db.Get([]byte(*user), nil)
	if err != nil {
		return false
	}
	var tokens [](*string)
	err = json.Unmarshal(tokenBytes, &tokens)
	if err != nil {
		log.Printf("Error unmarshalling user token: %v during user authentication", err)
		return false
	}
	for _, stoken := range tokens {
		if *token == *stoken {
			return true
		}
	}
	return false
}

// NewLvldbUser creates a levelDB user manager
func NewLvldbUser(filename string) (*LvldbUser, error) {
	err := os.RemoveAll(filename)
	if err != nil {
		log.Printf("error removing file %s: %v", filename, err)
	}
	db, err := leveldb.OpenFile(filename, &opt.Options{ErrorIfExist: true})
	if err != nil {
		return nil, err
	}
	user := LvldbUser{Db: db}
	return &user, nil
}
