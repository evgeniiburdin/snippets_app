package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/evgeniiburdin/gin_postgres_jwt_practice_1/pkg/models"
	"github.com/go-redis/redis/v8"
)

type RedisCache struct {
	RedisI *redis.Client
	RedisC *context.Context
}

type Cache interface {
	CacheAccount(*models.Account) error
	UncacheAccountAndSnippets(int) error
	RetrieveAccount(int) (*models.Account, error)
	CacheSnippet(*models.Snippet) error
	RetrieveSnippet(int, int) (*models.Snippet, error)
	UncacheSnippet(int, int) error
}

func (c *RedisCache) CacheAccount(account *models.Account) error {
	jsonMarshalledAccount, err := json.Marshal(account)
	if err != nil {
		return err
	}
	err = c.RedisI.Set(*c.RedisC, fmt.Sprint("account", account.ID), jsonMarshalledAccount, time.Hour).Err()
	if err != nil {
		return err
	}
	return nil
}

func (c *RedisCache) RetrieveAccount(userID int) (*models.Account, error) {
	retrievedAccount, err := c.RedisI.Get(*c.RedisC, fmt.Sprint("account", userID)).Result()
	if err != nil {
		return nil, err
	}
	account := &models.Account{}
	err = json.Unmarshal([]byte(retrievedAccount), account)
	if err != nil {
		return nil, err
	}
	return account, nil

}

func (c *RedisCache) UncacheAccountAndSnippets(userID int) error {
	err := c.RedisI.Del(*c.RedisC, fmt.Sprint("account", userID)).Err()
	if err != nil {
		return err
	}
	snippetsKeys, _ := c.RedisI.Keys(*c.RedisC, fmt.Sprint("account", userID, "snippet*")).Result()
	for _, key := range snippetsKeys {
		err = c.RedisI.Del(*c.RedisC, key).Err()
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *RedisCache) CacheSnippet(snippet *models.Snippet) error {
	jsonCreatedSnippet, err := json.Marshal(snippet)
	if err != nil {
		return err
	}
	err = c.RedisI.Set(*c.RedisC, fmt.Sprint("account", snippet.User_ID, "snippet", snippet.ID), string(jsonCreatedSnippet), time.Hour).Err()
	if err != nil {
		return err
	}
	return nil
}

func (c *RedisCache) RetrieveSnippet(userID int, snippetID int) (*models.Snippet, error) {
	retrievedSnippet, err := c.RedisI.Get(*c.RedisC, fmt.Sprint("account", userID, "snippet", snippetID)).Result()
	if err != nil {
		return nil, err
	}
	snippet := &models.Snippet{}
	err = json.Unmarshal([]byte(retrievedSnippet), snippet)
	if err != nil {
		return nil, err
	}
	return snippet, nil
}

func (c *RedisCache) UncacheSnippet(userID, deletedSnippetID int) error {
	err := c.RedisI.Del(*c.RedisC, fmt.Sprint("account", userID, "snippet", deletedSnippetID)).Err()
	if err != nil {
		return err
	}
	return nil
}
