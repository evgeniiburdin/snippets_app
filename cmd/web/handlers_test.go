package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/evgeniiburdin/gin_postgres_jwt_practice_1/pkg/models"
	"github.com/evgeniiburdin/gin_postgres_jwt_practice_1/pkg/models/postgres"
	"github.com/gin-gonic/gin"
)

const HandleCreateAccountTestData string = `{"Email": "test@example.com", "Username": "testusername", "Password": "testPassword1"}`
const HandleLoginTestData string = `{"Username": "testusername", "Password": "testPassword1"}`
const HandleRefreshTokensTestData string = `testjwt.testjwt.testjwt`
const HandleUpdateAccountTestData string = `{"Email": "updated@example.com", "Username": "updatedusername", "Password": "updatedPassword1"}`
const HandleCreateSnippetTestData string = `{"ID": 32, "User_ID": 43, "Title": "testtitle", "Content": "testcontenttestcontenttestcontenttestcontenttestcontenttestcontenttestcontenttestcontenttestcontenttestcontenttestcontent"}`
const HandleUpdateSnippetTestData string = `{"ID": 32, "User_ID": 43, "Title": "testtitle", "Content": "testcontenttestcontenttestcontenttestcontenttestcontenttestcontenttestcontenttestcontenttestcontenttestcontenttestcontent"}`

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
// Mock storage implementation
type mockStorage struct{}

func (m *mockStorage) StorageCreateAccount(email, username, password string) (*models.Account, error) {
	return &models.Account{
		ID:       1,
		Email:    email,
		Username: username,
		Password: password,
	}, nil
}

func (m *mockStorage) StorageGetAccountByID(account_id int) (*models.Account, error) {
	return &models.Account{
		ID:       account_id,
		Email:    "testemail",
		Username: "testusername",
		Password: "testpassword",
	}, nil
}

func (m *mockStorage) StorageLogin(username string, password string) (*models.Account, error) {
	return &models.Account{
		ID:       1,
		Email:    "testemail",
		Username: username,
		Password: password,
	}, nil
}

func (m *mockStorage) StorageUpdateAccount(account_id int, email, username, password string) (*models.Account, error) {
	return &models.Account{
		ID:       account_id,
		Email:    email,
		Username: username,
		Password: password,
	}, nil
}

func (m *mockStorage) StorageDeleteAccount(account_id int) (int, error) {
	return account_id, nil
}

func (m *mockStorage) StorageCreateSnippet(user_id int, snippet_title, snippet_content string) (*models.Snippet, error) {
	return &models.Snippet{
		ID:      1,
		User_ID: user_id,
		Title:   snippet_title,
		Content: snippet_content,
	}, nil
}

func (m *mockStorage) StorageGetSnippetByID(user_id int, snippet_id int) (*models.Snippet, error) {
	return &models.Snippet{
		ID:      snippet_id,
		User_ID: user_id,
		Title:   "testtitle",
		Content: "testcontent",
	}, nil
}

func (m *mockStorage) StorageGetSnippets(user_id int) ([]*models.Snippet, error) {
	return []*models.Snippet{
		{
			ID:      1,
			User_ID: user_id,
			Title:   "testtitle",
			Content: "testcontent",
		},
		{
			ID:      2,
			User_ID: user_id,
			Title:   "testtitle",
			Content: "testcontent",
		},
	}, nil
}

func (m *mockStorage) StorageUpdateSnippet(user_id, snippet_id int, snippet_title, snippet_content string) (*models.Snippet, error) {
	return &models.Snippet{
		ID:      snippet_id,
		User_ID: user_id,
		Title:   snippet_title,
		Content: snippet_content,
	}, nil
}

func (m *mockStorage) StorageDeleteSnippet(user_id int, snippet_id int) (int, error) {
	return snippet_id, nil
}

func (m *mockStorage) StorageUpdateJWT(userID int, refreshToken string) error {
	return nil
}

func (m *mockStorage) StorageFindRT(refreshToken string) (int, error) {
	testUserID := 21
	return testUserID, nil
}

func (m *mockStorage) StorageBlacklistJWTs(userID int, accessToken string) error {
	return nil
}

func (m *mockStorage) StorageJWTCheckBlacklisted(accessToken string) (bool, error) {
	return false, nil
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
// Mock cache implementation
type mockCache struct{}

func (c *mockCache) CacheAccount(account *models.Account) error {
	return nil
}

func (c *mockCache) RetrieveAccount(userID int) (*models.Account, error) {
	return &models.Account{
		ID:       userID,
		Email:    "testemail",
		Username: "testusername",
		Password: "testpassword",
	}, nil
}

func (c *mockCache) UncacheAccountAndSnippets(userID int) error {
	return nil
}

func (c *mockCache) CacheSnippet(snippet *models.Snippet) error {
	return nil
}

func (c *mockCache) RetrieveSnippet(userID int, snippetID int) (*models.Snippet, error) {
	return &models.Snippet{
		ID:      snippetID,
		User_ID: userID,
		Title:   "testtitle",
		Content: "testcontent",
	}, nil
}

func (c *mockCache) UncacheSnippet(userID, deletedSnippetID int) error {
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
// Mock auth implementation
type mockAuth struct{}

func (am *mockAuth) GetJWTs(id int, s postgres.Storage) (string, string, error) {
	return "testjwt", "testjwt", nil
}
func (am *mockAuth) ValidateRefreshToken(refreshToken string, s postgres.Storage) (int, error) {
	var testUserID int = 32
	return testUserID, nil
}
func (am *mockAuth) InvalidateJWTs(user_id int, accessToken string, s postgres.Storage) error {
	return nil
}
func (am *mockAuth) WithJWTAuth(s postgres.Storage) gin.HandlerFunc {
	return func(c *gin.Context) {
		var testUserID int = 32

		c.Set("user", testUserID)
		c.Set("accessToken", "testjwt")

		c.Next()
	}
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
// Mock app implementation
func runMockApp() *gin.Engine {
	mockStorage := &mockStorage{}
	mockCache := &mockCache{}
	mockAuth := &mockAuth{}

	mockApp := &Application{
		errorLog: nil,
		infoLog:  nil,
		storage:  mockStorage,
		cache:    mockCache,
		auth:     mockAuth,
	}

	mockRouter := gin.Default()
	mockRouter.POST("/register", mockApp.HandleCreateAccount)
	mockRouter.POST("/login", mockApp.HandleLogin)
	mockRouter.POST("/logout", mockApp.auth.WithJWTAuth(mockApp.storage), mockApp.HandleLogout)
	mockRouter.POST("/trefresh", mockApp.HandleRefreshTokens)
	mockRouter.GET("/account", mockApp.auth.WithJWTAuth(mockApp.storage), mockApp.HandleGetAccountByID)
	mockRouter.POST("/account/update", mockApp.auth.WithJWTAuth(mockApp.storage), mockApp.HandleUpdateAccount)
	mockRouter.POST("account/delete", mockApp.auth.WithJWTAuth(mockApp.storage), mockApp.HandleDeleteAccount)
	mockRouter.POST("/snippet/create", mockApp.auth.WithJWTAuth(mockApp.storage), mockApp.HandleCreateSnippet)
	mockRouter.GET("/snippet/:id", mockApp.auth.WithJWTAuth(mockApp.storage), mockApp.HandleGetSnippetByID)
	mockRouter.GET("/snippets", mockApp.auth.WithJWTAuth(mockApp.storage), mockApp.HandleGetSnippets)
	mockRouter.POST("/snippet/:id/update", mockApp.auth.WithJWTAuth(mockApp.storage), mockApp.HandleUpdateSnippet)
	mockRouter.POST("/snippet/:id/delete", mockApp.auth.WithJWTAuth(mockApp.storage), mockApp.HandleDeleteSnippet)

	return mockRouter
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
func TestHandleCreateAccount(t *testing.T) {

	mockRouter := runMockApp()

	reqBody := []byte(HandleCreateAccountTestData)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	respRecorder := httptest.NewRecorder()

	mockRouter.ServeHTTP(respRecorder, req)

	if respRecorder.Code != http.StatusOK {
		t.Errorf("Exprected status %d, got %d", http.StatusOK, respRecorder.Code)
	}

	respBody := respRecorder.Body.Bytes()

	var responseBody map[string]interface{}

	err := json.Unmarshal(respBody, &responseBody)
	if err != nil {
		t.Errorf("Could not recognize response body: %v Error: %v", respBody, err)
	}

	if _, ok := responseBody["accessJWT"]; !ok || responseBody["accessJWT"] == nil {
		t.Errorf("No 'accessJWT' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["refreshJWT"]; !ok || responseBody["refreshJWT"] == nil {
		t.Errorf("No 'refreshJWT' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	accountMap, _ := responseBody["account:"].(map[string]interface{})
	if accountMap == nil {
		t.Errorf("No 'account' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
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
func TestHandleLogin(t *testing.T) {
	mockRouter := runMockApp()

	reqBody := []byte(HandleLoginTestData)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	respRecorder := httptest.NewRecorder()

	mockRouter.ServeHTTP(respRecorder, req)

	if respRecorder.Code != http.StatusOK {
		t.Errorf("Exprected status %d, got %d", http.StatusOK, respRecorder.Code)
	}

	respBody := respRecorder.Body.Bytes()

	var responseBody map[string]interface{}

	err := json.Unmarshal(respBody, &responseBody)
	if err != nil {
		t.Errorf("Could not recognize response body: %v Error: %v", respBody, err)
	}

	if _, ok := responseBody["accessJWT"]; !ok || responseBody["accessJWT"] == nil {
		t.Errorf("No 'accessJWT' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["refreshJWT"]; !ok || responseBody["refreshJWT"] == nil {
		t.Errorf("No 'refreshJWT' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	accountMap, _ := responseBody["account"].(map[string]interface{})
	if accountMap == nil {
		t.Errorf("No 'account' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
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
func TestHandleLogout(t *testing.T) {
	mockRouter := runMockApp()

	reqBody := []byte(HandleLoginTestData)
	req, _ := http.NewRequest("POST", "/logout", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	respRecorder := httptest.NewRecorder()

	mockRouter.ServeHTTP(respRecorder, req)

	if respRecorder.Code != http.StatusOK {
		t.Errorf("Exprected status %d, got %d", http.StatusOK, respRecorder.Code)
	}

	respBody := respRecorder.Body.Bytes()

	var responseBody map[string]interface{}

	err := json.Unmarshal(respBody, &responseBody)
	if err != nil {
		t.Errorf("Could not recognize response body: %v Error: %v", respBody, err)
	}

	if _, ok := responseBody["logged out"]; !ok {
		t.Errorf("No 'logged out' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
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
func TestHandleRefreshTokens(t *testing.T) {
	mockRouter := runMockApp()

	req, _ := http.NewRequest("POST", "/trefresh", nil)
	req.Header.Set("Authorization", fmt.Sprint("Bearer ", HandleRefreshTokensTestData))

	respRecorder := httptest.NewRecorder()

	mockRouter.ServeHTTP(respRecorder, req)

	if respRecorder.Code != http.StatusOK {
		t.Errorf("Exprected status %d, got %d", http.StatusOK, respRecorder.Code)
	}

	respBody := respRecorder.Body.Bytes()

	var responseBody map[string]interface{}

	err := json.Unmarshal(respBody, &responseBody)
	if err != nil {
		t.Errorf("Could not recognize response body: %v Error: %v", respBody, err)
	}

	if _, ok := responseBody["accessJWT"]; !ok || responseBody["accessJWT"] == nil {
		t.Errorf("No 'accessJWT' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["refreshJWT"]; !ok || responseBody["refreshJWT"] == nil {
		t.Errorf("No 'refreshJWT' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["account id"]; !ok || responseBody["account id"] == -1 {
		t.Errorf("No 'account id' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
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
func TestHandleGetAccountByID(t *testing.T) {
	mockRouter := runMockApp()

	req, _ := http.NewRequest("GET", "/account", nil)
	req.Header.Set("Authorization", fmt.Sprint("Bearer ", HandleRefreshTokensTestData))

	respRecorder := httptest.NewRecorder()

	mockRouter.ServeHTTP(respRecorder, req)

	if respRecorder.Code != http.StatusOK {
		t.Errorf("Exprected status %d, got %d", http.StatusOK, respRecorder.Code)
	}

	respBody := respRecorder.Body.Bytes()

	var responseBody map[string]interface{}

	err := json.Unmarshal(respBody, &responseBody)
	if err != nil {
		t.Errorf("Could not recognize response body: %v Error: %v", respBody, err)
	}

	if _, ok := responseBody["ID"]; !ok || responseBody["ID"] == -1 {
		t.Errorf("No 'ID' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["Username"]; !ok || responseBody["Username"] == "" {
		t.Errorf("No 'Username' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["Email"]; !ok || responseBody["Email"] == "" {
		t.Errorf("No 'Email' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["Password"]; !ok {
		t.Errorf("No 'Password' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
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
func TestHandleUpdateAccount(t *testing.T) {
	mockRouter := runMockApp()

	reqBody := []byte(HandleUpdateAccountTestData)
	req, _ := http.NewRequest("POST", "/account/update", bytes.NewBuffer(reqBody))
	req.Header.Set("Authorization", fmt.Sprint("Bearer ", HandleRefreshTokensTestData))

	respRecorder := httptest.NewRecorder()

	mockRouter.ServeHTTP(respRecorder, req)

	if respRecorder.Code != http.StatusOK {
		t.Errorf("Exprected status %d, got %d", http.StatusOK, respRecorder.Code)
	}

	respBody := respRecorder.Body.Bytes()

	var responseBody map[string]interface{}

	err := json.Unmarshal(respBody, &responseBody)
	if err != nil {
		t.Errorf("Could not recognize response body: %v Error: %v", respBody, err)
	}

	if _, ok := responseBody["ID"]; !ok || responseBody["ID"] == -1 {
		t.Errorf("No 'ID' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["Username"]; !ok || responseBody["Username"] == "" {
		t.Errorf("No 'Username' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["Email"]; !ok || responseBody["Email"] == "" {
		t.Errorf("No 'Email' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["Password"]; !ok {
		t.Errorf("No 'Password' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
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
func TestHandleDeleteAccount(t *testing.T) {
	mockRouter := runMockApp()

	req, _ := http.NewRequest("POST", "/account/delete", nil)
	req.Header.Set("Authorization", fmt.Sprint("Bearer ", HandleRefreshTokensTestData))

	respRecorder := httptest.NewRecorder()

	mockRouter.ServeHTTP(respRecorder, req)

	if respRecorder.Code != http.StatusOK {
		t.Errorf("Exprected status %d, got %d", http.StatusOK, respRecorder.Code)
	}

	respBody := respRecorder.Body.Bytes()

	var responseBody map[string]interface{}

	err := json.Unmarshal(respBody, &responseBody)
	if err != nil {
		t.Errorf("Could not recognize response body: %v Error: %v", respBody, err)
	}

	if _, ok := responseBody["account deleted"]; !ok || responseBody["account deleted"] == -1 {
		t.Errorf("No 'account deleted' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
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
func TestHandleCreateSnippet(t *testing.T) {
	mockRouter := runMockApp()

	reqBody := []byte(HandleCreateSnippetTestData)
	req, _ := http.NewRequest("POST", "/snippet/create", bytes.NewBuffer(reqBody))
	req.Header.Set("Authorization", fmt.Sprint("Bearer ", HandleRefreshTokensTestData))

	respRecorder := httptest.NewRecorder()

	mockRouter.ServeHTTP(respRecorder, req)

	if respRecorder.Code != http.StatusOK {
		t.Errorf("Exprected status %d, got %d", http.StatusOK, respRecorder.Code)
	}

	respBody := respRecorder.Body.Bytes()

	var responseBody map[string]interface{}

	err := json.Unmarshal(respBody, &responseBody)
	if err != nil {
		t.Errorf("Could not recognize response body: %v Error: %v", respBody, err)
	}

	if _, ok := responseBody["ID"]; !ok || responseBody["ID"] == -1 {
		t.Errorf("No 'ID' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["User_ID"]; !ok || responseBody["User_ID"] == -1 {
		t.Errorf("No 'User_ID' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["Title"]; !ok || responseBody["Title"] == "" {
		t.Errorf("No 'Title' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["Content"]; !ok || responseBody["Content"] == "" {
		t.Errorf("No 'Content' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
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
func TestHandleGetSnippetByID(t *testing.T) {
	mockRouter := runMockApp()

	req, _ := http.NewRequest("GET", "/snippet/27", nil)
	req.Header.Set("Authorization", fmt.Sprint("Bearer ", HandleRefreshTokensTestData))

	respRecorder := httptest.NewRecorder()

	mockRouter.ServeHTTP(respRecorder, req)

	if respRecorder.Code != http.StatusOK {
		t.Errorf("Exprected status %d, got %d", http.StatusOK, respRecorder.Code)
	}

	respBody := respRecorder.Body.Bytes()

	var responseBody map[string]interface{}

	err := json.Unmarshal(respBody, &responseBody)
	if err != nil {
		t.Errorf("Could not recognize response body: %v Error: %v", respBody, err)
	}

	if _, ok := responseBody["ID"]; !ok || responseBody["ID"] == -1 {
		t.Errorf("No 'ID' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["User_ID"]; !ok || responseBody["User_ID"] == -1 {
		t.Errorf("No 'User_ID' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["Title"]; !ok || responseBody["Title"] == "" {
		t.Errorf("No 'Title' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if _, ok := responseBody["Content"]; !ok || responseBody["Content"] == "" {
		t.Errorf("No 'Content' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
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
func TestHandleGetSnippets(t *testing.T) {
	mockRouter := runMockApp()

	req, _ := http.NewRequest("GET", "/snippets", nil)
	req.Header.Set("Authorization", fmt.Sprint("Bearer ", HandleRefreshTokensTestData))

	respRecorder := httptest.NewRecorder()

	mockRouter.ServeHTTP(respRecorder, req)

	if respRecorder.Code != http.StatusOK {
		t.Errorf("Exprected status %d, got %d", http.StatusOK, respRecorder.Code)
	}

	respBody := respRecorder.Body.Bytes()

	var responseBody []models.Snippet

	err := json.Unmarshal(respBody, &responseBody)
	if err != nil {
		t.Errorf("Could not recognize response body: %v Error: %v", respBody, err)
	}

	log.Println(responseBody)
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
func TestHandleUpdateSnippet(t *testing.T) {
	mockRouter := runMockApp()

	reqBody := []byte(HandleUpdateSnippetTestData)
	req, _ := http.NewRequest("POST", "/snippet/27/update", bytes.NewBuffer(reqBody))
	req.Header.Set("Authorization", fmt.Sprint("Bearer ", HandleRefreshTokensTestData))

	respRecorder := httptest.NewRecorder()

	mockRouter.ServeHTTP(respRecorder, req)

	if respRecorder.Code != http.StatusOK {
		t.Errorf("Exprected status %d, got %d", http.StatusOK, respRecorder.Code)
	}

	respBody := respRecorder.Body.Bytes()

	responseBody := &models.Snippet{}

	err := json.Unmarshal(respBody, &responseBody)
	log.Println(string(respBody))
	if err != nil {
		t.Errorf("Could not recognize response body: %v Error: %v", respBody, err)
	}

	if responseBody.ID == -1 {
		t.Errorf("No 'ID' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if responseBody.User_ID == -1 {
		t.Errorf("No 'User_ID' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if responseBody.Title == "" {
		t.Errorf("No 'Title' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
	if responseBody.Content == "" {
		t.Errorf("No 'Content' key in response body or value equals nil: \n%v\n", responseBody)
		return
	}
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
func TestHandleDeleteSnippet(t *testing.T) {
	mockRouter := runMockApp()

	req, _ := http.NewRequest("POST", "/snippet/27/delete", nil)
	req.Header.Set("Authorization", fmt.Sprint("Bearer ", HandleRefreshTokensTestData))

	respRecorder := httptest.NewRecorder()

	mockRouter.ServeHTTP(respRecorder, req)

	if respRecorder.Code != http.StatusOK {
		t.Errorf("Exprected status %d, got %d", http.StatusOK, respRecorder.Code)
	}

	respBody := respRecorder.Body.Bytes()

	var responseBody int

	err := json.Unmarshal(respBody, &responseBody)
	log.Println(string(respBody))
	if err != nil {
		t.Errorf("Could not recognize response body: %v Error: %v", respBody, err)
	}

	if responseBody == -1 {
		t.Errorf("wrong deleted id value in response body: \n%v\n", responseBody)
		return
	}

}
