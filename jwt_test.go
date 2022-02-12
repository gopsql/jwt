package jwt

import (
	"testing"
)

func Test(t *testing.T) {
	expectedUid := 1
	expectedSid := "381063e6-4dd1-40bf-a2c0-8b40f4d8db68"
	sess := NewSession(nil)
	auth, err := sess.GenerateAuthorization(expectedUid, expectedSid)
	if err != nil {
		panic(err)
	}
	userId, sessionId, ok := sess.ParseAuthorization(auth)
	if ok != true {
		t.Error("ok should be true")
	}
	if userId != expectedUid {
		t.Error("user id should be equal")
	}
	if sessionId != expectedSid {
		t.Error("session id should be equal")
	}
	token := sess.MustSign(map[string]interface{}{
		"Foo": "Bar",
	})
	claims := sess.MustParse(token)
	if claims["Foo"].(string) != "Bar" {
		t.Error("map value not match")
	}
}
