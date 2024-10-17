package client

import (
	"gin-mvc/controllers"
	"gin-mvc/session"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

func CheckProducts() {
	browser := rod.New().MustConnect()
	defer browser.MustClose()

	flag_owner_session_token, err := session.GenerateSessionToken("antal.alexandru@bit-sentinel.com", "CTF{<snip>}", controllers.Key)
	if err != nil {
		panic(err)
	}

	err = browser.SetCookies([]*proto.NetworkCookieParam{
		{
			Name:    "session_token",
			Value:   flag_owner_session_token,
			Path:    "/",
			Domain:  "localhost",
			Expires: proto.TimeSinceEpoch(time.Now().Add(365 * 24 * time.Hour).Unix()),
		},
	})
	if err != nil {
		panic(err)
	}

	browser.MustPage("http://localhost:8000/products").MustWaitStable()
}
