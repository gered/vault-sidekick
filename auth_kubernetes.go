package main

import (
	"io/ioutil"
	"os"

	"github.com/hashicorp/vault/api"
)

type authKubernetesPlugin struct {
	client *api.Client
}

type kubernetesLogin struct {
	Role string `json:"role"`
	JWT  string `json:"jwt"`
}

func NewKubernetesPlugin(client *api.Client) AuthInterface {
	return &authKubernetesPlugin{
		client: client,
	}
}

func (p authKubernetesPlugin) Create(cfg *vaultAuthOptions) (string, error) {
	if cfg.RoleID == "" {
		cfg.RoleID = os.Getenv("VAULT_SIDEKICK_K8S_ROLE")
	}
	if cfg.FileName == "" {
		cfg.FileName = os.Getenv("VAULT_SIDEKICK_K8S_TOKEN_FILE")
		// default to the typical location for this
		if cfg.FileName == "" {
			cfg.FileName = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		}
	}

	// read kubernetes serviceaccount token file (a jwt token)
	tokenBytes, err := ioutil.ReadFile(cfg.FileName)
	if err != nil {
		return "", err
	}

	// create token request
	request := p.client.NewRequest("POST", "/v1/auth/kubernetes/login")
	body := kubernetesLogin{Role: cfg.RoleID, JWT: string(tokenBytes)}
	err = request.SetJSONBody(body)
	if err != nil {
		return "", err
	}

	// execute api request
	resp, err := p.client.RawRequest(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// parse secret response
	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return "", err
	}

	return secret.Auth.ClientToken, nil
}
