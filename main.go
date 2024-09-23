package main

import (
	"context"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"net/http"
	"os"
	"time"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

var client *mongo.Client
var usersCol *mongo.Collection
var chatsCol *mongo.Collection
var messagesCol *mongo.Collection
var friendsCol *mongo.Collection

type Message struct {
	Sender    string `bson:"sender" json:"sender"`
	Recipient string `bson:"recipient" json:"recipient"`
	Content   string `bson:"content" json:"content"`
	Id        int64  `bson:"id" json:"id"`
}

func ServeWs(w http.ResponseWriter, r *http.Request, hub *Hub) {
	upgrader.CheckOrigin = func(r *http.Request) bool {
		return true
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	name := r.URL.Query().Get("login")
	if err != nil {
		log.Println(err)
		return
	}

	if err != nil {
		log.Println(err)
		return
	}
	client := Client{
		name:  name,
		read:  make(chan *Message),
		write: make(chan *Message),
		conn:  conn,
		hub:   hub,
	}
	hub.register <- &client
	go client.startReading()
	go client.startWriting()
}

func decodeJson(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	err := json.NewDecoder(r.Body).Decode(&dst)
	return err
}

func main() {
	file, err := os.OpenFile("logs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(file)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017")) // TODO: read host from env variable
	if err != nil {
		panic(err)
	}
	defer func() {
		if err = client.Disconnect(ctx); err != nil {
			panic(err)
		}
	}()

	usersCol = client.Database("vk-chat").Collection("users")
	chatsCol = client.Database("vk-chat").Collection("chats")
	messagesCol = client.Database("vk-chat").Collection("messages")
	friendsCol = client.Database("vk-chat").Collection("friends")

	router := mux.NewRouter()

	hub := Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan *Message),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}

	go hub.run()

	router.HandleFunc("/api/1/register", Register)
	router.HandleFunc("/api/1/jwt", Login)

	router.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		ServeWs(w, r, &hub)
	})
	router.HandleFunc("/api/1/user", GetUser)
	router.HandleFunc("/api/1/chat", GetChatWithFriend)
	router.HandleFunc("/api/1/sendMessage", func(w http.ResponseWriter, r *http.Request) {
		SendMessage(w, r, &hub)
	})
	router.HandleFunc("/api/1/friends", ShowFriends)
	log.Println(http.ListenAndServe("localhost:8090", router))
}