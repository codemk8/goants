package auth

import (
	"testing"
)

const (
	testDbFileName = "test_user.db"
)

func TestUserConstructor(t *testing.T) {
	_, err := NewLvldbUser(testDbFileName)
	if err != nil {
		t.Errorf("Error creating db %v", err)
	}
}

func TestUserLogin(t *testing.T) {
	user, err := NewLvldbUser(testDbFileName)
	if err != nil {
		t.Errorf("Error creating db %v", err)
	}
	username := "test_user"
	usertoken := "dsfafwevds"
	err = user.Login(&username, &usertoken)
	if err != nil {
		t.Errorf("Error login user: %v", err)
	}
	err = user.Login(&username, &usertoken)
	if err != nil {
		t.Errorf("Error login user: %v", err)
	}
}

func TestUserLogout(t *testing.T) {
	user, err := NewLvldbUser(testDbFileName)
	if err != nil {
		t.Errorf("Error creating db %v", err)
	}
	username := "test_user"
	usertoken := "dsfafwevds"
	usertoken2 := "dsfafwevsadf "
	err = user.Login(&username, &usertoken)
	if err != nil {
		t.Errorf("Error login user: %v", err)
	}
	ok := user.Authenticate(&username, &usertoken)
	if !ok {
		t.Errorf("User should be authenticated here.")
	}
	notOk := user.Authenticate(&username, &usertoken2)
	if notOk {
		t.Errorf("User should not be authenticated here.")
	}

	err = user.Login(&username, &usertoken2)
	if err != nil {
		t.Errorf("Error login user: %v", err)
	}
	ok = user.Authenticate(&username, &usertoken2)
	if !ok {
		t.Errorf("User should be authenticated now.")
	}

	err = user.Logout(&username, &usertoken)
	if err != nil {
		t.Errorf("Error logout user: %v", err)
	}
	notOk = user.Authenticate(&username, &usertoken)
	if notOk {
		t.Errorf("User should not be authenticated here.")
	}

	err = user.Logout(&username, &usertoken)
	if err != nil {
		t.Errorf("Error logout user: %v", err)
	}
	notOk = user.Authenticate(&username, &usertoken)
	if notOk {
		t.Errorf("User should not be authenticated here.")
	}

	ok = user.Authenticate(&username, &usertoken2)
	if !ok {
		t.Errorf("User should be authenticated here.")
	}
	err = user.Logout(&username, &usertoken2)
	if err != nil {
		t.Errorf("Error logout user: %v", err)
	}
	notOk = user.Authenticate(&username, &usertoken2)
	if notOk {
		t.Errorf("User should not be authenticated here.")
	}
}
