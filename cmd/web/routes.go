package main

import (
	"github.com/gin-gonic/gin"
)

func (app *Application) runServer() error {
	router := gin.Default()

	router.POST("/register", app.HandleCreateAccount)                                              // REGISTER USER
	router.POST("/login", app.HandleLogin)                                                         // LOG USER IN
	router.POST("/logout", app.auth.WithJWTAuth(app.storage), app.HandleLogout)                    // LOG USER OUT
	router.GET("/account", app.auth.WithJWTAuth(app.storage), app.HandleGetAccountByID)            // RETRIEVE USER ACCOUNT
	router.POST("/account/update", app.auth.WithJWTAuth(app.storage), app.HandleUpdateAccount)     // UPDATE USER ACCOUNT
	router.POST("account/delete", app.auth.WithJWTAuth(app.storage), app.HandleDeleteAccount)      // DELETE USER ACOUNT
	router.POST("/trefresh", app.HandleRefreshTokens)                                              // REFRESH JWTs
	router.POST("/snippet/create", app.auth.WithJWTAuth(app.storage), app.HandleCreateSnippet)     // CREATE SNIPPET
	router.GET("/snippet/:id", app.auth.WithJWTAuth(app.storage), app.HandleGetSnippetByID)        // RETRIEVE SNIPPET
	router.POST("/snippet/:id/update", app.auth.WithJWTAuth(app.storage), app.HandleUpdateSnippet) // UPDATE SNIPPET
	router.POST("/snippet/:id/delete", app.auth.WithJWTAuth(app.storage), app.HandleDeleteSnippet) // DELETE SNIPPET
	router.GET("/snippets", app.auth.WithJWTAuth(app.storage), app.HandleGetSnippets)              // RETRIEVE ALL SNIPPETS

	return router.Run("localhost:3000")
}
