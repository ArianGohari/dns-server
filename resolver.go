package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

const ROOT_SERVERS = "198.41.0.4,199.9.14.201,192.33.4.12,199.7.91.13,192.203.230.10,192.5.5.241,192.112.36.4,198.97.190.53"

// Read root servers from const string
func getRootServers() []net.IP {
	rootServers := []net.IP{}
	for _, rootServer := range strings.Split(ROOT_SERVERS, ",") {
		rootServers = append(rootServers, net.ParseIP(rootServer))
	}

	return rootServers
}

func outgoingDnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error) {
	fmt.Printf("New outgoing dns query for %s, servers: %+v\n", question.Name.String(), servers)

	// Setting max to maximum usigned int 16 (65535) -> bitwise 1111111111111111 -> inverted 0000000000000000
	max := ^uint16(0)

	// Creating random number between 0 and max (65535)
	randomNumber, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return nil, nil, err
	}

	// Create dns message struct containing ID, response flag, opcode and questions
	message := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       uint16(randomNumber.Int64()),
			Response: false,
			OpCode:   dnsmessage.OpCode(0),
		},
		Questions: []dnsmessage.Question{question},
	}
	// Write dns message into buffer
	buf, err := message.Pack()
	if err != nil {
		return nil, nil, err
	}

	// Try connection with any of the servers from list
	var conn net.Conn
	for _, server := range servers {

		// Connect to server using dial with UDP on port 53
		conn, err = net.Dial("udp", server.String()+":53")

		// Stop for loop if connection succeeded / no error
		if err == nil {
			break
		}
	}

	// If no connection return error
	if conn == nil {
		return nil, nil, fmt.Errorf("Failed to make connection to servers: %s", err)
	}

	// Write buffer into connection
	_, err = conn.Write(buf)
	if err != nil {
		return nil, nil, err
	}

	// Create new byte array buffer for answer
	answer := make([]byte, 512)

	// Read answer from connection into answer
	n, err := bufio.NewReader(conn).Read(answer)
	if err != nil {
		return nil, nil, err
	}

	// Close connection
	conn.Close()

	// Define parser
	var p dnsmessage.Parser

	// Parse headers from answer buffer
	headers, err := p.Start(answer[:n])
	if err != nil {
		return nil, nil, fmt.Errorf("Parser start error %s", err)
	}

	// Parse questions from answer buffer
	questions, err := p.AllQuestions()

	// Compare answer questions length to initial message questions length to check validity
	if len(questions) != len(message.Questions) {
		return nil, nil, fmt.Errorf("Answer package doesn't have the same amount of questions")
	}

	// Skip questions
	err = p.SkipAllQuestions()
	if err != nil {
		return nil, nil, err
	}

	// Return parser and headers
	return &p, &headers, nil
}

// Resolve a DNS query using given root servers
func dnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Message, error) {
	fmt.Printf("Question: %+v\n", question)

	// Limt outgoing dns queries to 3 iterations
	for i := 0; i < 3; i++ {

		// Try to resolve dns query with given servers
		dnsAnswer, header, err := outgoingDnsQuery(servers, question)
		if err != nil {
			return nil, err
		}

		// Parse all answers from dns answer
		parsedAnswers, err := dnsAnswer.AllAnswers()
		if err != nil {
			return nil, err
		}

		// If authoritative, return dns message with parsed answers
		if header.Authoritative {
			return &dnsmessage.Message{
				Header: dnsmessage.Header{
					Response: true,
				},
				Answers: parsedAnswers,
			}, nil
		}

		// If not authoritative, get all authorities
		authorities, err := dnsAnswer.AllAuthorities()
		if err != nil {
			return nil, err
		}

		// If authorities empty, return dns name error message
		if len(authorities) == 0 {
			return &dnsmessage.Message{
				Header: dnsmessage.Header{
					RCode: dnsmessage.RCodeNameError,
				},
			}, nil
		}

		// Define string array for nameservers
		nameservers := make([]string, len(authorities))

		// For each authority if name server add to nameservers array
		for k, authority := range authorities {
			if authority.Header.Type == dnsmessage.TypeNS {
				nameservers[k] = authority.Body.(*dnsmessage.NSResource).NS.String()
			}
		}

		// Get additionals from dns answer
		additionals, err := dnsAnswer.AllAdditionals()
		if err != nil {
			return nil, err
		}

		// Define newServersFound flag false
		newServersFound := false

		// Define array for server ip addresses
		servers = []net.IP{}

		// For each additional if A record check if nameservers are equal
		// If true, set newServersFound flag true, add ip address to servers array
		for _, additional := range additionals {
			if additional.Header.Type == dnsmessage.TypeA {
				for _, nameserver := range nameservers {
					if additional.Header.Name.String() == nameserver {
						newServersFound = true
						servers = append(servers, additional.Body.(*dnsmessage.AResource).A[:])
					}
				}
			}
		}

		// If not authoritative and new servers found, iterate over nameservers
		if !newServersFound {
			// For each nameserver, if no new servers found, recursively call dnsQuery
			// given new name and root servers
			for _, nameserver := range nameservers {
				if !newServersFound {
					response, err := dnsQuery(getRootServers(), dnsmessage.Question{
						Name:  dnsmessage.MustNewName(nameserver),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					})

					// If error returned, log warning, else set newServersFound true
					if err != nil {
						fmt.Printf("Warning: Lookup of nameserver %s has failed: %err\n", nameserver, err)
					} else {
						newServersFound = true

						// For each anser, read ip address from A record, add to servers array
						for _, answer := range response.Answers {
							if answer.Header.Type == dnsmessage.TypeA {
								servers = append(servers, answer.Body.(*dnsmessage.AResource).A[:])
							}
						}
					}
				}
			}
		}
	}

	// If not authoritative and no new servers found, even after recursion, return dns server failure message
	return &dnsmessage.Message{
		Header: dnsmessage.Header{
			RCode: dnsmessage.RCodeServerFailure,
		},
	}, nil
}

// / Handle an incoming dns message packet
func handlePacket(pc net.PacketConn, addr net.Addr, buf []byte) error {
	// Define parser
	p := dnsmessage.Parser{}

	// Parse header from packet buffer
	header, err := p.Start(buf)
	if err != nil {
		return err
	}

	// Parse question from packet buffer
	question, err := p.Question()
	if err != nil {
		return err
	}

	// Resolve question using root servers
	response, err := dnsQuery(getRootServers(), question)
	if err != nil {
		return err
	}

	// Set id of response packet
	response.ID = header.ID

	// Write response into response buffer
	responseBuf, err := response.Pack()
	if err != nil {
		return err
	}

	// Write response to packet connection
	_, err = pc.WriteTo(responseBuf, addr)
	if err != nil {
		return err
	}

	return nil
}

// Public wrapper function to run handlePacket from goroutines
func HandlePacket(pc net.PacketConn, addr net.Addr, buf []byte) {
	if err := handlePacket(pc, addr, buf); err != nil {
		fmt.Printf("Error while calling handlePacket [%s]: %s\n", addr.String(), err)
	}
}
