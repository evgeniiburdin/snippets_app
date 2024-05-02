package main

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/evgeniiburdin/gin_postgres_jwt_practice_1/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

// USER ACCOUNT OPERATIONS API HANDLERS
/*
//
//
//
//
//
//
//
//
//
//
*/
// API HANDLER FOR USER REGISTER (TESTED)
func (app *Application) HandleCreateAccount(c *gin.Context) {

	// Getting new account data from HTTP request body
	reqJSON := models.UserAuthRequest{}
	if err := c.ShouldBindBodyWith(&reqJSON, binding.JSON); err != nil {
		ErrorToAPI(c, http.StatusNotAcceptable, err)
		return
	}

	// User input validation
	if reqJSON.Email != "" && reqJSON.Password != "" && reqJSON.Username != "" {
		if err := validateUserData(reqJSON.Email, reqJSON.Username, reqJSON.Password, ""); err != nil {
			ErrorToAPI(c, http.StatusNotAcceptable, err)
			return
		}
	} else {
		ErrorToAPI(c, http.StatusBadRequest, errors.New("not enough data provided"))
		return
	}
	// Pushing new account data to the storage
	createdAccount, err := app.storage.StorageCreateAccount(reqJSON.Email, reqJSON.Username, reqJSON.Password)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Creating JWT for user to sign in immediately after being registered
	accessJWT, refreshJWT, err := app.auth.GetJWTs(createdAccount.ID, app.storage)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Pushing account to the cache
	err = app.cache.CacheAccount(createdAccount)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Providing with account data and JWT tokens in the HTTP 200 response body
	c.JSON(http.StatusOK, gin.H{"account:": createdAccount, "accessJWT": accessJWT, "refreshJWT": refreshJWT})
}

/*
//
//
//
//
//
//
//
//
//
//
*/
// API HANDLER FOR USER LOGIN
func (app *Application) HandleLogin(c *gin.Context) {

	// Getting sign in data from HTTP request body
	reqJSON := models.UserAuthRequest{}
	if err := c.ShouldBindJSON(&reqJSON); err != nil {
		ErrorToAPI(c, http.StatusNotAcceptable, err)
		return
	}

	// User input validation
	if reqJSON.Username != "" && reqJSON.Password != "" {
		if err := validateUserData(reqJSON.Email, reqJSON.Username, reqJSON.Password, ""); err != nil {
			ErrorToAPI(c, http.StatusNotAcceptable, err)
			return
		}
	} else {
		ErrorToAPI(c, http.StatusBadRequest, errors.New("not enough data provided"))
		return
	}

	// Retrieving account from the storage
	retrievedAccount, err := app.storage.StorageLogin(reqJSON.Username, reqJSON.Password)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Creating JWT
	accessJWT, refreshJWT, err := app.auth.GetJWTs(retrievedAccount.ID, app.storage)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Pushing account to the cache
	err = app.cache.CacheAccount(retrievedAccount)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Providing with account data and JWT tokens in the HTTP 200 response body
	c.JSON(http.StatusOK, gin.H{"accessJWT": accessJWT, "refreshJWT": refreshJWT, "account": retrievedAccount})
}

/*
//
//
//
//
//
//
//
//
//
//
*/
// API HANDLER FOR USER LOGOUT
func (app *Application) HandleLogout(c *gin.Context) {

	// This handler is being reached after JWT authorization function presented in ./middlewares/jwt/jwt.go

	// Getting user ID from Gin parameters, converting it from any to int
	u, _ := c.Get("user")
	user_id, _ := u.(int)

	// Getting user accessJWT from Gin parameters
	accessJWT, exists := c.Get("accessToken")
	if !exists {
		ErrorToAPI(c, http.StatusInternalServerError, errors.New("could not retrieve accessJWT key value"))
		return
	}

	// Requesting storage to invalidate both access and refresh JWTs
	err := app.auth.InvalidateJWTs(user_id, fmt.Sprint(accessJWT), app.storage)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Requesting cache to delete cached user account and their snippets if exists
	err = app.cache.UncacheAccountAndSnippets(user_id)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Providing with HTTP 200 response
	c.JSON(http.StatusOK, gin.H{"logged out": "jwt blacklisted"})
}

/*
//
//
//
//
//
//
//
//
//
//
*/
// API HANDLER FOR JWTs REFRESH
func (app *Application) HandleRefreshTokens(c *gin.Context) {

	// Retrieving refresh JWT from HTTP header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		ErrorToAPI(c, http.StatusUnauthorized, errors.New("missing auth header"))
		return
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		ErrorToAPI(c, http.StatusUnauthorized, errors.New("invalid auth header format"))
		return
	}
	providedRefreshJWT := parts[1]

	// Validating provided JWT as user input
	if providedRefreshJWT != "" {
		if err := validateUserData("", "", "", providedRefreshJWT); err != nil {
			ErrorToAPI(c, http.StatusUnauthorized, err)
			return
		}
	} else {
		ErrorToAPI(c, http.StatusBadRequest, errors.New("no refreshJWT provided"))
		return
	}

	// Requesting storage to update JWTs if refresh JWT exists in there
	userID, err := app.auth.ValidateRefreshToken(providedRefreshJWT, app.storage)
	if err != nil || userID == -1 {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}
	accessJWT, refreshJWT, err := app.auth.GetJWTs(userID, app.storage)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Providing with HTTP 200 response with updated JTWs and user account id in the body
	c.JSON(http.StatusOK, gin.H{"accessJWT": accessJWT, "refreshJWT": refreshJWT, "account id": fmt.Sprint(userID)})
}

/*
//
//
//
//
//
//
//
//
//
//
*/
// API HANDLER FOR GETTING USER ACCOUNT BY ID
func (app *Application) HandleGetAccountByID(c *gin.Context) {

	// This handler is being reached after JWT authorization function presented in ./middlewares/jwt/jwt.go

	// Getting user ID from Gin parameters, converting it from any to int
	u, _ := c.Get("user")
	userID, _ := u.(int)

	// Cache lookup for the requested account
	account, err := app.cache.RetrieveAccount(userID)

	// If not found, requesting storage for the account, and, if exists, pushing it to the cache
	if err != nil {

		account, err := app.storage.StorageGetAccountByID(userID)
		if err != nil {
			ErrorToAPI(c, http.StatusInternalServerError, err)
			return
		}
		err = app.cache.CacheAccount(account)
		if err != nil {
			ErrorToAPI(c, http.StatusInternalServerError, err)
			return
		}

		// Providing with HTTP 200 response with account data in the body
		c.JSON(http.StatusOK, account)
		return
	}

	// Providing with HTTP 200 response with account data in the body
	c.JSON(http.StatusOK, account)
}

/*
//
//
//
//
//
//
//
//
//
//
*/
// API HANDLER FOR UPDATING USER ACCOUNT
func (app *Application) HandleUpdateAccount(c *gin.Context) {

	// This handler is being reached after JWT authorization function presented in ./middlewares/jwt/jwt.go

	// Getting user ID from Gin parameters, converting it from any to int
	u, _ := c.Get("user")
	userID, _ := u.(int)

	// Getting updated account data from HTTP request body
	reqJSON := models.UserAuthRequest{}
	if err := c.ShouldBindBodyWith(&reqJSON, binding.JSON); err != nil {
		ErrorToAPI(c, http.StatusNotAcceptable, err)
		return
	}

	// Validating user input
	if reqJSON.Email != "" && reqJSON.Password != "" && reqJSON.Username != "" {
		if err := validateUserData(reqJSON.Email, reqJSON.Username, reqJSON.Password, ""); err != nil {
			ErrorToAPI(c, http.StatusNotAcceptable, err)
			return
		}
	} else {
		ErrorToAPI(c, http.StatusBadRequest, errors.New("not enough data provided"))
		return
	}

	// Requesting storage to update account with provided data
	updatedAccount, err := app.storage.StorageUpdateAccount(userID, reqJSON.Email, reqJSON.Username, reqJSON.Password)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Pushing updated account to the cache
	err = app.cache.CacheAccount(updatedAccount)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Providing with HTTP 200 response with updated account in the body
	c.JSON(http.StatusOK, updatedAccount)
}

/*
//
//
//
//
//
//
//
//
//
//
*/
// API HANDLER FOR DELETING USER WITH THEIR SNIPPETS
func (app *Application) HandleDeleteAccount(c *gin.Context) {

	// This handler is being reached after JWT authorization function presented in ./middlewares/jwt/jwt.go

	// Getting user ID from Gin parameters, converting it from any to int
	u, _ := c.Get("user")
	userID, _ := u.(int)

	// Requesting storage to delete account
	deletedAccountID, err := app.storage.StorageDeleteAccount(userID)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Requesting cache to uncache account and their snippets
	err = app.cache.UncacheAccountAndSnippets(deletedAccountID)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Providing with HTTP 200 response with deleted account id in the body
	c.JSON(http.StatusOK, gin.H{"account deleted": deletedAccountID})
}

/*
//
//
//
//
//
//
//
//
//
//
*/
// SNIPPET OPERATIONS API HANDLERS
/*
//
//
//
//
//
//
//
//
//
//
*/
// API HANDLER FOR CREATING A SNIPPET
func (app *Application) HandleCreateSnippet(c *gin.Context) {
	// This handler is being reached after JWT authorization function presented in ./middlewares/jwt/jwt.go

	// Getting user ID from Gin parameters, converting it from any to int
	u, _ := c.Get("user")
	userID, _ := u.(int)

	// Retrieving new snippet data from request body
	reqJSON := models.Snippet{}
	if err := c.ShouldBindBodyWith(&reqJSON, binding.JSON); err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Validating user input
	if fmt.Sprint(reqJSON.ID) != "" && fmt.Sprint(reqJSON.User_ID) != "" && reqJSON.Title != "" && reqJSON.Content != "" {
		if err := validateSnippetData(fmt.Sprint(reqJSON.ID), fmt.Sprint(reqJSON.User_ID), reqJSON.Title, reqJSON.Content); err != nil {
			ErrorToAPI(c, http.StatusNotAcceptable, err)
			return
		}
	} else {
		ErrorToAPI(c, http.StatusBadRequest, errors.New("not enough data provided"))
		return
	}

	// Requesting storage to create a new snippet
	createdSnippet, err := app.storage.StorageCreateSnippet(userID, reqJSON.Title, reqJSON.Content)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Pushing new snippet to the cache
	err = app.cache.CacheSnippet(createdSnippet)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Providing with HTTP 200 response with created snippet in the body
	c.JSON(http.StatusOK, createdSnippet)
}

/*
//
//
//
//
//
//
//
//
//
//
*/
// API FOR RETRIEVING A SINGLE SNIPPET BY ITS ID
func (app *Application) HandleGetSnippetByID(c *gin.Context) {

	// This handler is being reached after JWT authorization function presented in ./middlewares/jwt/jwt.go

	// Getting user ID from Gin parameters, converting it from any to int
	u, _ := c.Get("user")
	userID, _ := u.(int)

	// Retrieving snippet id from the address
	s_id := c.Param("id")
	snippetID, err := strconv.Atoi(s_id)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Validating user input

	if err := validateSnippetData(fmt.Sprint(snippetID), "", "", ""); err != nil {
		ErrorToAPI(c, http.StatusNotAcceptable, err)
		return
	}

	// Looking for snippet in cache
	snippet, err := app.cache.RetrieveSnippet(userID, snippetID)

	// If not found, looking for snippet in storage
	if err != nil {
		snippet, err := app.storage.StorageGetSnippetByID(userID, snippetID)
		if err != nil {
			ErrorToAPI(c, http.StatusBadRequest, err)
			return
		}

		err = app.cache.CacheSnippet(snippet)
		if err != nil {
			ErrorToAPI(c, http.StatusInternalServerError, err)
			return
		}

		// Providing with HTTP 200 response with the snippet in the body
		c.JSON(http.StatusOK, snippet)
		return
	}

	// If found, providing with HTTP 200 response with the snippet in the body
	c.JSON(http.StatusOK, snippet)
}

/*
//
//
//
//
//
//
//
//
//
//
*/
// API HANDLER TO RETRIEVE ALL THE SNIPPETS CREATED BY USER
func (app *Application) HandleGetSnippets(c *gin.Context) {

	// This handler is being reached after JWT authorization function presented in ./middlewares/jwt/jwt.go

	// Getting user ID from Gin parameters, converting it from any to int
	u, _ := c.Get("user")
	userID, _ := u.(int)

	// Looking for snippets in the storage
	snippets, err := app.storage.StorageGetSnippets(userID)
	if err != nil {
		ErrorToAPI(c, http.StatusBadRequest, err)
		return
	}

	// If found any - caching
	for snippet := range snippets {
		err := app.cache.CacheSnippet(snippets[snippet])
		if err != nil {
			ErrorToAPI(c, http.StatusInternalServerError, err)
			return
		}
	}

	// Providing with HTTP 200 response and retrieved snippets in JSON
	c.JSON(http.StatusOK, snippets)
}

/*
//
//
//
//
//
//
//
//
//
//
*/
// API HANDER FOR UPDATING A SNIPPET
func (app *Application) HandleUpdateSnippet(c *gin.Context) {

	// This handler is being reached after JWT authorization function presented in ./middlewares/jwt/jwt.go

	// Getting user ID from Gin parameters, converting it from any to int
	u, _ := c.Get("user")
	userID, _ := u.(int)

	// Retrieving snippet id from the address, converting to int
	s_id := c.Param("id")
	snippetID, err := strconv.Atoi(s_id)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, errors.New("could not convert gin address parameter to int"))
		return
	}

	// Retrieving snippet patches from the request body
	reqJSON := models.Snippet{}
	if err := c.ShouldBindBodyWith(&reqJSON, binding.JSON); err != nil {
		ErrorToAPI(c, http.StatusNotAcceptable, err)
		return
	}

	// Validating user input
	if err := validateSnippetData(fmt.Sprint(snippetID), "", "", ""); err != nil {
		ErrorToAPI(c, http.StatusNotAcceptable, err)
		return
	}
	if fmt.Sprint(reqJSON.ID) != "" && fmt.Sprint(reqJSON.User_ID) != "" && reqJSON.Title != "" && reqJSON.Content != "" {
		if err := validateSnippetData(fmt.Sprint(reqJSON.ID), fmt.Sprint(reqJSON.User_ID), reqJSON.Title, reqJSON.Content); err != nil {
			ErrorToAPI(c, http.StatusNotAcceptable, err)
			return
		}
	} else {
		ErrorToAPI(c, http.StatusBadRequest, errors.New("not enough data provided"))
		return
	}

	// Requesting database to update snippet with provided data
	updatedSnippet, err := app.storage.StorageUpdateSnippet(userID, snippetID, reqJSON.Title, reqJSON.Content)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Caching the snippet
	err = app.cache.CacheSnippet(updatedSnippet)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Providing with HTTP 200 response
	c.JSON(http.StatusOK, updatedSnippet)
}

/*
//
//
//
//
//
//
//
//
//
//
*/
// API FOR DELETING SNIPPET
func (app *Application) HandleDeleteSnippet(c *gin.Context) {

	// This handler is being reached after JWT authorization function presented in ./middlewares/jwt/jwt.go

	// Getting user ID from Gin parameters, converting it from any to int
	u, _ := c.Get("user")
	userID, _ := u.(int)

	// Retrieving snippet id from the address, converting to int
	s_id := c.Param("id")
	snippetID, err := strconv.Atoi(s_id)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, errors.New("could not convert gin address parameter to int"))
		return
	}

	// Validating user input
	if err := validateSnippetData(fmt.Sprint(snippetID), "", "", ""); err != nil {
		ErrorToAPI(c, http.StatusBadRequest, err)
		return
	}

	// Requesting storage to delete snippet, getting deleted snippet id
	deletedSnippetID, err := app.storage.StorageDeleteSnippet(userID, snippetID)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
		return
	}

	// Requesting cache to delete snippet
	err = app.cache.UncacheSnippet(userID, deletedSnippetID)
	if err != nil {
		ErrorToAPI(c, http.StatusInternalServerError, err)
	}

	// Providing with HTTP 200 response
	c.JSON(http.StatusOK, deletedSnippetID)
}

/*
//
//
//
//
//
//
//
//
//
//
*/
// FUNC FOR WRITING ERRORS TO HTTP RESPONSES
func ErrorToAPI(c *gin.Context, statusCode int, err error) {
	c.JSON(statusCode, gin.H{"error": err.Error()})
}

/*
//
//
//
//
//
//
//
//
//
//
*/
// FUNC FOR VALIDATING USER DATA WITH REGEX
func validateUserData(email, username, password, jwt_token string) error {
	if email != "" {
		emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
		re := regexp.MustCompile(emailRegex)
		if !re.MatchString(email) {
			return errors.New("validateUserData: wrong email format")
		}
	}
	if username != "" {
		usernameRegex := `^[a-zA-Z0-9]{3,20}$`
		re := regexp.MustCompile(usernameRegex)
		if !re.MatchString(username) {
			return errors.New("validateUserData: wrong username format")
		}
	}
	if password != "" {
		if strings.ContainsAny(password, "!@#$%^&*()_+-={}[]|\\:;\"'<>,.?/") ||
			strings.Contains(password, "'") ||
			strings.Contains(password, ";") ||
			strings.Contains(password, "--") {
			return errors.New("validateUserData: wrong password format")
		}
	}
	if jwt_token != "" {
		jwtRegex := `^[\w-]+\.[\w-]+\.[\w-]+$`
		re := regexp.MustCompile(jwtRegex)
		if !re.MatchString(jwt_token) {
			return errors.New("validateUserData: wrong jwt_token format")
		}
	}
	if email == "" && username == "" && password == "" && jwt_token == "" {
		return errors.New("validateUserData: no data provided")
	}
	return nil
}

/*
//
//
//
//
//
//
//
//
//
//
*/
// FUNC FOR VALIDATING SNIPPET DATA WITH REGEX
func validateSnippetData(snippetID, userID, snippetTitle, snippetContent string) error {
	if snippetID != "" {
		snippetIDregex := `^\d{0,8}$`
		re := regexp.MustCompile(snippetIDregex)
		if !re.MatchString(fmt.Sprint(snippetID)) {
			return errors.New("validateSnippetData: wrong snippet id format")
		}
	}
	if userID != "" {
		userIDregex := `^\d{0,8}$`
		re := regexp.MustCompile(userIDregex)
		if !re.MatchString(fmt.Sprint(userID)) {
			return errors.New("validateSnippetData: wrong user id format")
		}
	}
	if snippetTitle != "" {
		snippetTitleRegex := `^[a-zA-Z0-9\s]{3,100}$`
		re := regexp.MustCompile(snippetTitleRegex)
		if !re.MatchString(fmt.Sprint(snippetTitle)) {
			return errors.New("validateSnippetData: wrong snippet title format")
		}
	}
	if snippetContent != "" {
		if !(utf8.RuneCountInString(snippetContent) < 50) && !(utf8.RuneCountInString(snippetContent) > 5000) {
			snippetContentRegex := `^[[:alnum:][:space:].,!?;:'"-]+$`
			re := regexp.MustCompile(snippetContentRegex)
			if !re.MatchString(snippetContent) {
				return errors.New("validateSnippetData: wrong snippet content format")
			}
		} else {
			return errors.New("validateSnippetData: wrong snippet content format")
		}
	}
	if snippetID == "" && userID == "" && snippetTitle == "" && snippetContent == "" {
		return errors.New("validateSnippetData: no data provided")
	}
	return nil
}
