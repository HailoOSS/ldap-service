// Code generated by protoc-gen-go.
// source: github.com/hailooss/ldap-service/proto/common.proto
// DO NOT EDIT!

/*
Package com_hailooss_service_ldap is a generated protocol buffer package.

It is generated from these files:
	github.com/hailooss/ldap-service/proto/common.proto

It has these top-level messages:
	User
*/
package com_hailooss_service_ldap

import proto "github.com/hailooss/protobuf/proto"
import json "encoding/json"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = &json.SyntaxError{}
var _ = math.Inf

type User struct {
	Username         *string  `protobuf:"bytes,1,opt,name=username" json:"username,omitempty"`
	UserID           *string  `protobuf:"bytes,2,opt,name=userID" json:"userID,omitempty"`
	Groups           []string `protobuf:"bytes,3,rep,name=groups" json:"groups,omitempty"`
	Roles            []string `protobuf:"bytes,4,rep,name=roles" json:"roles,omitempty"`
	XXX_unrecognized []byte   `json:"-"`
}

func (m *User) Reset()         { *m = User{} }
func (m *User) String() string { return proto.CompactTextString(m) }
func (*User) ProtoMessage()    {}

func (m *User) GetUsername() string {
	if m != nil && m.Username != nil {
		return *m.Username
	}
	return ""
}

func (m *User) GetUserID() string {
	if m != nil && m.UserID != nil {
		return *m.UserID
	}
	return ""
}

func (m *User) GetGroups() []string {
	if m != nil {
		return m.Groups
	}
	return nil
}

func (m *User) GetRoles() []string {
	if m != nil {
		return m.Roles
	}
	return nil
}

func init() {
}
