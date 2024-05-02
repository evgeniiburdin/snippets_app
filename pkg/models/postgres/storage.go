package postgres

import (
	"database/sql"

	"github.com/evgeniiburdin/gin_postgres_jwt_practice_1/pkg/models"
	"golang.org/x/crypto/bcrypt"
)

type PostgresStorage struct {
	DB *sql.DB
}

type Storage interface {
	StorageCreateAccount(string, string, string) (*models.Account, error)      // CREATE ACCOUNT
	StorageGetAccountByID(int) (*models.Account, error)                        // RETRIEVE ACCOUNT BY ID
	StorageLogin(string, string) (*models.Account, error)                      // CHECK PASS AND RETRIEVE ACCOUNT
	StorageUpdateAccount(int, string, string, string) (*models.Account, error) // UPDATE ACCOUNT
	StorageDeleteAccount(int) (int, error)                                     // DELETE ACCOUNT
	StorageCreateSnippet(int, string, string) (*models.Snippet, error)         // CREATE SNIPPET
	StorageGetSnippetByID(int, int) (*models.Snippet, error)                   // RETRIEVE SNIPPET BY ID
	StorageGetSnippets(int) ([]*models.Snippet, error)                         // RETRIEVE ALL SNIPPETS
	StorageUpdateSnippet(int, int, string, string) (*models.Snippet, error)    // UPDATE SNIPPET
	StorageDeleteSnippet(int, int) (int, error)                                // DELETE SNIPPET
	StorageUpdateJWT(int, string) error                                        // UPDATE JWTs INFO
	StorageFindRT(string) (int, error)                                         // VALIDATE REFRESH JWT
	StorageBlacklistJWTs(int, string) error                                    // BLACKLIST JWTs
	StorageJWTCheckBlacklisted(string) (bool, error)                           // CHECK IF JWT BLACKLISTED
}

// ACCOUNT OPERATIONS STORAGE HANDLERS
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
// CREATE USER ACCOUNT
func (s *PostgresStorage) StorageCreateAccount(email, username, password string) (*models.Account, error) {

	// Encrypting password with bcrypt algorhitm before sending to storage
	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Beginning storage transaction
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}

	// Defer Rollback
	defer tx.Rollback()

	// Quering storage to create an account
	query := `insert into account (email, username, password) values ($1, $2, $3) on conflict(email) do nothing returning id, email, username`
	createdAccount := &models.Account{}
	err = tx.QueryRow(query, email, username, encryptedPassword).Scan(&createdAccount.ID, &createdAccount.Email, &createdAccount.Username)
	if err != nil {
		return nil, err
	}

	// Quering storage to update refresh token
	query = `insert into token (user_id) values ($1)`
	_, err = tx.Exec(query, createdAccount.ID)
	if err != nil {
		return nil, err
	}

	// Committing transaction
	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	// Returning created account
	return createdAccount, nil
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
// RETRIEVE ACCOUNT BY ID
func (s *PostgresStorage) StorageGetAccountByID(account_id int) (*models.Account, error) {
	retrievedAccount := &models.Account{}
	query := `select id, email, username from account where id = $1`
	err := s.DB.QueryRow(query, account_id).Scan(&retrievedAccount.ID, &retrievedAccount.Email, &retrievedAccount.Username)
	if err != nil {
		return nil, err
	}
	return retrievedAccount, nil
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
// CHECK PASSWORD AND RETURN ACCOUNT
func (s *PostgresStorage) StorageLogin(username string, password string) (*models.Account, error) {

	retrievedAccount := &models.Account{}
	stmt := `select id, email, username, password from account where username = $1`
	err := s.DB.QueryRow(stmt, username).Scan(&retrievedAccount.ID, &retrievedAccount.Email, &retrievedAccount.Username, &retrievedAccount.Password)
	if err != nil {
		return nil, err
	}
	// Password check
	if err := bcrypt.CompareHashAndPassword([]byte(retrievedAccount.Password), []byte(password)); err != nil {
		return nil, err
	}
	return retrievedAccount, nil
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
// UPDATE EXISTING ACCOUNT
func (s *PostgresStorage) StorageUpdateAccount(account_id int, email, username, password string) (*models.Account, error) {
	updatedAccount := &models.Account{}

	// Beginning transaction
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}

	// Defer Rollback
	defer tx.Rollback()

	// Quering storage to update account
	if email != "" {
		query := `update account set email = $2 where id = $1 returning id, email, username`
		err := tx.QueryRow(query, account_id, email).Scan(&updatedAccount.ID, &updatedAccount.Email, &updatedAccount.Username)
		if err != nil {
			return nil, err
		}
	}
	if username != "" {
		query := `update account set username = $2 where id = $1 returning id, email, username`
		err := tx.QueryRow(query, account_id, username).Scan(&updatedAccount.ID, &updatedAccount.Email, &updatedAccount.Username)
		if err != nil {
			return nil, err
		}
	}
	if password != "" {
		query := `update account set password = $2 where id = $1 returning id, email, username`

		// Encrypting password with bcrypt algorithm before pushing to storage
		encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		err = tx.QueryRow(query, account_id, encryptedPassword).Scan(&updatedAccount.ID, &updatedAccount.Email, &updatedAccount.Username)
		if err != nil {
			return nil, err
		}
	}

	// Committing transaction
	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	// Returning updated account
	return updatedAccount, nil
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
// DELETE ACCOUNT
func (s *PostgresStorage) StorageDeleteAccount(account_id int) (int, error) {

	// Beginning transaction
	tx, err := s.DB.Begin()
	if err != nil {
		return -1, err
	}

	// Defer Rollback
	defer tx.Rollback()
	query := `delete from account where id = $1`
	_, err = tx.Exec(query, account_id)
	if err != nil {
		return -1, err
	}
	query = `delete from token where user_id = $1`
	_, err = tx.Exec(query, account_id)
	if err != nil {
		return -1, err
	}
	query = `delete from snippet where user_id = $1`
	_, err = tx.Exec(query, account_id)
	if err != nil {
		return -1, err
	}

	// Committing transaction
	err = tx.Commit()
	if err != nil {
		return -1, err
	}

	// Returning deleted account id
	return account_id, nil
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
// SNIPPET OPERATIONS STORAGE HANDLERS
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
// CREATE SNIPPET
func (s *PostgresStorage) StorageCreateSnippet(user_id int, snippet_title, snippet_content string) (*models.Snippet, error) {

	// Quering storage to create snippet with provided data
	query := `insert into snippet (user_id, title, content) values ($1, $2, $3) returning snippet_id, user_id, title, content`
	createdSnippet := &models.Snippet{}
	err := s.DB.QueryRow(query, user_id, snippet_title, snippet_content).Scan(&createdSnippet.ID, &createdSnippet.User_ID, &createdSnippet.Title, &createdSnippet.Content)
	if err != nil {
		return nil, err
	}

	// Returning created snippet
	return createdSnippet, nil
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
// READ SNIPPET BY ID
func (s *PostgresStorage) StorageGetSnippetByID(user_id int, snippet_id int) (*models.Snippet, error) {

	// Quering storage to get snippet
	retrievedSnippet := models.Snippet{}
	query := `select snippet_id, user_id, content, title from snippet where snippet_id = $1 and user_id = $2`
	err := s.DB.QueryRow(query, snippet_id, user_id).Scan(&retrievedSnippet.ID, &retrievedSnippet.User_ID, &retrievedSnippet.Content, &retrievedSnippet.Title)
	if err != nil {
		return nil, err
	}

	// Returning retrieved snippet
	return &retrievedSnippet, nil
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
// READ ALL SNIPPETS
func (s *PostgresStorage) StorageGetSnippets(user_id int) ([]*models.Snippet, error) {

	// Quering storage to retrieve all user snippets
	query := `select * from snippet where user_id = $1`
	rows, err := s.DB.Query(query, user_id)
	if err != nil {
		return nil, err
	}
	snippets := []*models.Snippet{}
	for rows.Next() {
		snippet := models.Snippet{}
		err = rows.Scan(&snippet.ID, &snippet.User_ID, &snippet.Content, &snippet.Title)
		if err != nil {
			return nil, err
		}
		snippets = append(snippets, &snippet)
	}

	// Returning snippets
	return snippets, nil
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
// UPDATE SNIPPET
func (s *PostgresStorage) StorageUpdateSnippet(user_id, snippet_id int, snippet_title, snippet_content string) (*models.Snippet, error) {
	updatedSnippet := new(models.Snippet)

	// Beginning transaction
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}

	// Defer Rollback
	defer tx.Rollback()

	// Quering storage to update snippet
	if snippet_title != "" {
		query := `update snippet set title = $1 where user_id = $2 and snippet_id = $3 returning snippet_id, user_id, title, content`
		err := tx.QueryRow(query, snippet_title, user_id, snippet_id).Scan(&updatedSnippet.ID, &updatedSnippet.User_ID, &updatedSnippet.Title, &updatedSnippet.Content)
		if err != nil {
			return nil, err
		}
	}
	if snippet_content != "" {
		query := `update snippet set content = $1 where user_id = $2 and snippet_id = $3 returning snippet_id, user_id, title, content`
		err := tx.QueryRow(query, snippet_content, user_id, snippet_id).Scan(&updatedSnippet.ID, &updatedSnippet.User_ID, &updatedSnippet.Title, &updatedSnippet.Content)
		if err != nil {
			return nil, err
		}
	}

	// Committing transaction
	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	// Rerturning ipdated snippet
	return updatedSnippet, nil
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
// DELETE SNIPPET
func (s *PostgresStorage) StorageDeleteSnippet(user_id int, snippet_id int) (int, error) {

	// Quering storage to delete snippet
	query := `delete from snippet where snippet_id = $1 and user_id = $2 returning snippet_id`
	var deletedSnippetID int
	err := s.DB.QueryRow(query, snippet_id, user_id).Scan(&deletedSnippetID)
	if err != nil {
		return -1, err
	}

	// Returning deleted snippet id
	return deletedSnippetID, nil
}

// JWT OPERATIONS STORAGE HANDLERS
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
// SET REFRESH JWT
func (s *PostgresStorage) StorageUpdateJWT(userID int, refreshToken string) error {

	// Quering storage to set refresh JWT
	query := `update token set refresh_token = $2 where user_id = $1`
	_, err := s.DB.Exec(query, userID, refreshToken)
	if err != nil {
		return err
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
// FIND REFRESH JWT
func (s *PostgresStorage) StorageFindRT(refreshToken string) (int, error) {

	// Quering storage to find refresh JWT
	var userID int
	err := s.DB.QueryRow(`select user_id from token where refresh_token = $1`, refreshToken).Scan(&userID)
	if err != nil {
		return -1, err
	}

	// Returning id of user that owns jwt
	return userID, nil
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
// BLACKLIST JWTs
func (s *PostgresStorage) StorageBlacklistJWTs(userID int, accessToken string) error {

	// Beginning transaction
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}

	// Defer Rollback
	defer tx.Rollback()

	// Quering storage to blacklist access JWT
	query := `insert into jwt_blacklisted values ($1)`
	_, err = tx.Exec(query, accessToken)
	if err != nil {
		return err
	}

	// Invalidating refresh token
	query = `update token set refresh_token = $2 where user_id = $1`
	_, err = tx.Exec(query, userID, "")
	if err != nil {
		return err
	}

	// Committing transaction
	err = tx.Commit()
	if err != nil {
		return err
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
// CHECK IF JWT BLACKLISTED
func (s *PostgresStorage) StorageJWTCheckBlacklisted(accessToken string) (bool, error) {

	// Quering storage to check if provided jwt is blacklisted
	var blacklisted bool
	err := s.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM jwt_blacklisted WHERE access_token = $1)", accessToken).Scan(&blacklisted)
	if err != nil {
		return false, err
	}
	return blacklisted, nil
}
