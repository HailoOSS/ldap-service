// Code generated by protoc-gen-go.
// source: github.com/hailooss/ldap-service/proto/readusers/readusers.proto
// DO NOT EDIT!

/*
Package com_hailooss_service_ldap_readusers is a generated protocol buffer package.

It is generated from these files:
	github.com/hailooss/ldap-service/proto/readusers/readusers.proto

It has these top-level messages:
	Request
	Response
*/
package com_hailooss_service_ldap_readusers

import proto "github.com/hailooss/protobuf/proto"
import json "encoding/json"
import math "math"
import com_hailooss_service_ldap "github.com/hailooss/ldap-service/proto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = &json.SyntaxError{}
var _ = math.Inf

type Request struct {
	Ids              []string `protobuf:"bytes,1,rep,name=ids" json:"ids,omitempty"`
	XXX_unrecognized []byte   `json:"-"`
}

func (m *Request) Reset()         { *m = Request{} }
func (m *Request) String() string { return proto.CompactTextString(m) }
func (*Request) ProtoMessage()    {}

func (m *Request) GetIds() []string {
	if m != nil {
		return m.Ids
	}
	return nil
}

type Response struct {
	Users            []*com_hailooss_service_ldap.User `protobuf:"bytes,1,rep,name=users" json:"users,omitempty"`
	XXX_unrecognized []byte                            `json:"-"`
}

func (m *Response) Reset()         { *m = Response{} }
func (m *Response) String() string { return proto.CompactTextString(m) }
func (*Response) ProtoMessage()    {}

func (m *Response) GetUsers() []*com_hailooss_service_ldap.User {
	if m != nil {
		return m.Users
	}
	return nil
}

func init() {
}
