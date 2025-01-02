// Command minifed sets up web servers for hosting various OIDF entities.
//
// It supports configuration of federations with arbitrary layouts. See Config for the
// configuration file layout.
//
// Run with `go run . config.yaml`.
//
// Once the web servers are running, manipulate the Host header to talk to them, e.g.
// `curl http://localhost:8080/fetch?sub=https://im.example.com -H "Host: ta.example.com"`
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/jwa"
	oidcfed "github.com/zachmann/go-oidfed/pkg"
	"github.com/zachmann/go-oidfed/pkg/fedentities"
	"github.com/zachmann/go-oidfed/pkg/fedentities/storage"
	"gopkg.in/yaml.v3"
)

// EntityKind is the type of the entity. It doesn't necessarily map 1:1 to OIDF Entities, but
// instead different kind of entites that can exist in a minifed federation.
type EntityKind string

const (
	// EntityKindLeaf is a OIDF leaf that does nothing.
	EntityKindLeaf         EntityKind = "leaf"
	EntityKindTrustAnchor  EntityKind = "trust-anchor"
	EntityKindIntermediate EntityKind = "intermediate"
	// EntityKindTrustAnchorACMEProvider?
	// EntityKindIntermediateACMEProvider?
)

type Config struct {
	Entities map[string]struct {
		Kind       EntityKind
		Identifier string
	}
	Edges []string
}

type Entity struct {
	Superiors         []*Entity
	Subordinates      []*Entity
	Name              string
	Kind              EntityKind
	Identifier        *url.URL
	SigningPrivateKey crypto.Signer
	FedEntity         *fedentities.FedEntity
	Storage           *storage.BadgerStorage
}

func (e *Entity) String() string {
	var superiors []string
	for _, superior := range e.Superiors {
		superiors = append(superiors, superior.Name)
	}
	var subordinates []string
	for _, subordinate := range e.Subordinates {
		subordinates = append(subordinates, subordinate.Name)
	}
	return fmt.Sprintf("EntityNode{Superiors:%+v, Subordinates:%+v, Name:%s, Kind:%s, Identifier:%s}", superiors, subordinates, e.Name, e.Kind, e.Identifier)
}

func mustGenerateECDSAPrivateKey() *ecdsa.PrivateKey {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return sk
}

func mustParseConfig() map[string]*Entity {
	var config Config
	filename := os.Args[1]
	content, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	if err := yaml.Unmarshal(content, &config); err != nil {
		log.Fatal(err)
	}

	for key, entity := range config.Entities {
		if entity.Kind == "" {
			log.Fatalf("%s: kind must be present", key)
		}
		if entity.Identifier == "" {
			log.Fatalf("%s: identifier must be present", key)
		}
	}

	slog.Debug("read config", slog.Any("config", config))

	entityNodes := map[string]*Entity{}
	for index, edge := range config.Edges {
		split := strings.Split(edge, "->")
		head, tail := strings.TrimSpace(split[0]), strings.TrimSpace(split[1])

		headConfig, ok := config.Entities[head]
		if !ok {
			log.Fatalf("undefined reference to node %s in edge %d", head, index)
		}
		tailConfig, ok := config.Entities[tail]
		if !ok {
			log.Fatalf("undefined reference to node %s in edge %d", head, index)
		}

		headNode, ok := entityNodes[head]
		if !ok {
			headIdentifier, err := url.Parse(headConfig.Identifier)
			if err != nil {
				log.Fatalf("invalid url for node %s: %s", head, err)
			}
			headNode = &Entity{
				Name:              head,
				Kind:              headConfig.Kind,
				Identifier:        headIdentifier,
				SigningPrivateKey: mustGenerateECDSAPrivateKey(),
			}
			entityNodes[head] = headNode
		}

		tailNode, ok := entityNodes[tail]
		if !ok {
			tailIdentifier, err := url.Parse(tailConfig.Identifier)
			if err != nil {
				log.Fatalf("invalid url for node %s: %s", tail, err)
			}
			tailNode = &Entity{
				Name:              tail,
				Kind:              tailConfig.Kind,
				Identifier:        tailIdentifier,
				SigningPrivateKey: mustGenerateECDSAPrivateKey(),
			}
			entityNodes[tail] = tailNode
		}

		headNode.Subordinates = append(headNode.Subordinates, tailNode)
		tailNode.Superiors = append(tailNode.Superiors, headNode)
	}

	slog.Info("parsed entities", "entityNodes", entityNodes)
	return entityNodes
}

func main() {
	entities := mustParseConfig()
	mux := http.NewServeMux()
	for _, entity := range entities {
		slog.Debug("starting server for entity", slog.Any("entity", entity))
		var authorityHints []string
		for _, authority := range entity.Superiors {
			authorityHints = append(authorityHints, authority.Identifier.String())
		}

		// I'm not sure whether this function is correct for starting a leaf entity. There is
		// oidcfed.NewFederationLeaf() which seems more suitable, but then you have to register your own
		// HTTP handlers. It _seems_ like fedentity is a higher level package for running a federation
		// entity, but it feels like it's assuming that you'd only use it when operating a TA or
		// intermediate, not a leaf.
		//
		// Regardless, if we take a fedentity with the correct metadata, we can treat it as a leaf anyway
		// and get the .well-known/openid-federation handler for free.
		fedentity, err := fedentities.NewFedEntity(
			entity.Identifier.String(),
			authorityHints,
			// oidcfed will take care of adding the federation entity metadata when we register the various
			// federation endpoints
			&oidcfed.Metadata{},
			entity.SigningPrivateKey,
			// This must align with the type of signing key.
			jwa.ES512,
			60*60*24*365,
			fedentities.SubordinateStatementsConfig{
				// Nothing interesting here... for now. (perhaps metadata policies can be plumbed through
				// the config).
			},
		)
		if err != nil {
			log.Fatalf("%s: %s", entity, err)
		}
		entity.FedEntity = fedentity

		if entity.Kind == EntityKindIntermediate || entity.Kind == EntityKindTrustAnchor {
			db, err := storage.NewInMemoryBadgerStorage()
			if err != nil {
				log.Fatalf("%s: %s", entity, err)
			}
			subDb := db.SubordinateStorage()
			trustDb := db.TrustMarkedEntitiesStorage()

			fedentity.AddSubordinateListingEndpoint(fedentities.EndpointConf{Path: "/list"}, subDb, trustDb)
			fedentity.AddFetchEndpoint(fedentities.EndpointConf{Path: "/fetch"}, subDb)

			// TODO: This endpoint doesn't work right now. It wants to call out to various entity configuration
			// endpoints, which won't work without name resolution and TLS.
			fedentity.AddResolveEndpoint(fedentities.EndpointConf{Path: "/resolve"})

			entity.Storage = db
		}

		handleFunc := fedentity.HttpHandlerFunc()
		host := entity.Identifier.Hostname() // n.b. the port number is ignored

		mux.HandleFunc(host+"/", handleFunc)
		slog.Info("registered entity", "host", host)
	}

	for _, entity := range entities {
		for _, subordinate := range entity.Subordinates {
			entityConfig := subordinate.FedEntity.EntityConfigurationPayload()
			info := storage.SubordinateInfo{
				JWKS:        entityConfig.JWKS,
				EntityTypes: []string{}, // TODO: what should these be?,
				EntityID:    subordinate.Identifier.String(),
				Status:      storage.StatusActive,
			}
			if err := entity.Storage.SubordinateStorage().Write(
				subordinate.Identifier.String(), info,
			); err != nil {
				log.Fatalf("%s -> %s: %s", entity, subordinate, err)
			}
			slog.Info(
				"established trust",
				"parent", entity.Identifier.String(),
				"child", subordinate.Identifier.String(),
			)
		}
	}

	// TODO: TLS with certs issued from self-signed root certificate. Also means we'd need to deal
	// with SNI for making requests.
	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	slog.Info("listening on :8080")
	log.Fatal(server.ListenAndServe())
}
