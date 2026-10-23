package main

import (
	"context"
	"net/http"
)

const qoderProtocolVersion = "1.1.74"

type credentialCodec interface {
	Encrypt(context.Context, string, string) (string, error)
	Decrypt(context.Context, string, string) (string, error)
}

type runtimeFieldInput struct {
	UID                string   `json:"uid"`
	SecurityOAuthToken string   `json:"security_oauth_token,omitempty"`
	OrganizationID     string   `json:"organization_id"`
	OrganizationTags   []string `json:"organization_tags"`
	DataPolicyAgreed   bool     `json:"data_policy_agreed"`
}

type runtimeFieldOutput struct {
	EncryptUserInfo string `json:"encrypt_user_info"`
	Key             string `json:"key"`
}

type runtimeFieldGenerator interface {
	Generate(context.Context, runtimeFieldInput) (runtimeFieldOutput, error)
}

type modelCacheDecryptor interface {
	Decrypt(context.Context, string, string) ([]byte, error)
}

type protocolUserInfo struct {
	UID              string   `json:"uid"`
	EncryptUserInfo  string   `json:"encrypt_user_info"`
	Key              string   `json:"key"`
	OrganizationID   string   `json:"organization_id"`
	OrganizationTags []string `json:"organization_tags"`
	DataPolicyAgreed bool     `json:"data_policy_agreed"`
}

type protocolScene struct {
	ClientType      string `json:"client_type"`
	BusinessProduct string `json:"business_product"`
	BusinessType    string `json:"business_type"`
	Scene           string `json:"scene"`
}

type protocolContextConfig struct {
	MachineID string
	Version   string
	User      protocolUserInfo
	Scene     protocolScene
}

type inferRequestInput struct {
	Endpoint    string
	Body        []byte
	ModelKey    string
	ModelSource string
}

type preparedRequest struct {
	URL    string
	Header http.Header
	Body   []byte
}

type protocolContextFactory interface {
	New(context.Context, protocolContextConfig) (protocolContext, error)
}

type protocolContext interface {
	PrepareInferRequest(context.Context, inferRequestInput) (*preparedRequest, error)
	Close() error
}

func defaultProtocolScene() protocolScene {
	return protocolScene{
		ClientType:      "5",
		BusinessProduct: "cli",
		BusinessType:    "agent",
		Scene:           "assistant",
	}
}

func qoderUserAgent() string { return "qoder/" + qoderProtocolVersion }
