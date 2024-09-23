package main

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	"log"
)

type Client struct {
	read  chan *Message
	write chan *Message
	hub   *Hub
	conn  *websocket.Conn
	name  string
}

func (c *Client) startReading() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			log.Print(err)
			return
		}
		var message Message
		json.Unmarshal(msg, &message)
		c.hub.increaseMessageId()
		message.Id = c.hub.messageId()
		c.hub.broadcast <- &message
	}
}

func (c *Client) startWriting() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	for {
		select {
		case msg := <-c.write:
			c.conn.WriteJSON(msg)
		}
	}
}