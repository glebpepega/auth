package db

import (
	"context"
	"encoding/base64"
	"log"
	"os"
	"time"

	"github.com/glebpepega/auth/internal/hashtoken"
	"github.com/glebpepega/auth/internal/models"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type DB struct {
	Client     *mongo.Client
	Collection *mongo.Collection
}

func New() *DB {
	return &DB{}
}

func (d *DB) Connect() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(os.Getenv("DBCONN")))
	if err != nil {
		log.Fatal(err)
	}
	d.Client = client
	d.Collection = d.Client.Database("auth").Collection("users")
}

func (d *DB) InsertRefresh(guid string, refreshToken string) error {
	ht := hashtoken.HashRefresh(refreshToken)
	s := models.Session{RefreshToken: ht, CreatedAt: time.Now()}
	user := models.User{Guid: guid, Session: s}
	res, err := d.Collection.InsertOne(context.TODO(), user)
	if err != nil {
		return err
	}
	log.Println("record inserted: ", res)
	return nil
}

func (d *DB) UpdateRefresh(oldRefresh string) (newRefresh string, err error) {
	ht := hashtoken.HashRefresh(newRefresh)
	newRefresh = base64.StdEncoding.EncodeToString([]byte(uuid.New().String()))
	filter := bson.M{"session.refreshToken": ht}
	update := bson.M{"$set": bson.M{"session": models.Session{RefreshToken: newRefresh}}}
	if _, err := d.Collection.UpdateOne(context.TODO(), filter, update); err != nil {
		return "", err
	}
	log.Println("record updated, new refresh ", newRefresh)
	return newRefresh, nil
}

func (d *DB) FindRefresh(oldRefresh string) (guid string, err error) {
	ht := hashtoken.HashRefresh(oldRefresh)
	filter := bson.M{"session.refreshToken": ht}
	u := models.User{}
	if err := d.Collection.FindOne(context.TODO(), filter).Decode(&u); err != nil {
		return "", err
	}
	return u.Guid, nil
}
