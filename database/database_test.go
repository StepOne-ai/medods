package database

import (
	"context"
	"testing"
)

func TestInitDB(t *testing.T) {
	_, err := InitDB()
	if err != nil {
		t.Fatal(err)
	}
	defer CloseDB()
}

func TestCloseDB(t *testing.T) {
	_, err := InitDB()
	if err != nil {
		t.Fatal(err)
	}
	CloseDB()
}

func TestGetUserByGUID(t *testing.T) {
	db, err := InitDB()
	if err != nil {
		t.Fatal(err)
	}
	defer CloseDB()

	user := User{
		GUID: "test-guid2",
		HashedRefreshToken: "test-token",
	}

	_, err = db.Exec(context.Background(), "INSERT INTO users (guid, hashed_refresh_token) VALUES ($1, $2)", user.GUID, user.HashedRefreshToken)
	if err != nil {
		t.Fatal(err)
	}

	gotUser, err := GetUserByGUID(context.Background(), user.GUID)
	if err != nil {
		t.Fatal(err)
	}

	if gotUser.GUID != user.GUID {
		t.Errorf("got user GUID %q, want %q", gotUser.GUID, user.GUID)
	}
}