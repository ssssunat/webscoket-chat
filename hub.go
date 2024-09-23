package main

type Hub struct {
	// Registered clients.
	clients map[*Client]bool

	// Inbound messages from the clients.
	broadcast chan *Message

	// Register requests from the clients.
	register chan *Client

	// Unregister requests from clients.
	unregister chan *Client

	counter int64
}

func (h *Hub) increaseMessageId() {
	h.counter++
}

func (h *Hub) messageId() int64 {
	return h.counter
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
		case client := <-h.unregister:
			h.clients[client] = false
		case msg := <-h.broadcast:
			for client := range h.clients {
				if msg.Recipient == client.name {
					select {
					case client.write <- msg:
					default:
						close(client.write)
						delete(h.clients, client)
					}
				}
			}
		}
	}

}