package base

import "time"

//Request type constants
const (
	//Room request type
	Room = "room"
)

//Other constants
const (
	//a service user
	SERVICEUSER = "service"
)

//Request represents a request sent into the authorization controller
type Request struct {
	AccessKey       string          `json:"access-key"`       //The access key granted to the service making the call
	UserInformation UserInformation `json:"user-information"` //The user information associated with the authorization request
}

//UserInformation .
type UserInformation struct {
	CommonInfo
	ResourceID string `json:"resource-id"` //the resource being accessed
}

//Response repressents the repsonse send in response to a Request
type Response struct {
	CommonInfo
	Permissions map[string][]string `json:"permissions"` //permissionsh
	TTL         time.Time
}

//CommonInfo is the information shared between requests and responses
type CommonInfo struct {
	ID           string `json:"_id"`           //The id of the user requesting access
	AuthMethod   string `json:"auth-method"`   //The auth method used by the user
	ResourceType string `json:"resource-type"` //The resource type being accessed
	Data         []byte `json:"data"`
}

//PermissionsRecord represents a permissions object stored in the databse
type PermissionsRecord struct {
	ID            string                   `json:"_id"`
	ResourceType  string                   `json:"resource-type"`
	Allow         map[string]PermissionSet `json:"allow"`
	Deny          map[string]PermissionSet `json:"deny"`
	ResourceList  ResourceList             `json:"resource-list"`  //this is used in teh top level '*' document
	ResourceTiers int                      `json:"resource-tiers"` //this is used in the top level '*' document
	SubResources  []string                 `json:"-"`              //this is for use when the resource requested doesn't correspond to a leaf node - this is all the 'leaves' that are connected to the node requested.
}

//PermissionSet represents roles granted/denied to specific groups within a permissions record
type PermissionSet struct {
	Roles []string `json:"roles"`         //roles
	TTL   *int     `json:"TTL,omitempty"` //The amount of time to grant the selected permission set for, may be left blank to just set to the default
	//We can add other attributes here like 'ID card', 'schedule' etc. etc.
}

// ResourceList .
type ResourceList struct {
	Type    string `json:"type"`
	Address string `json:"addr"`
	Pass    string `json:"pass"`
	User    string `json:"user"`
}

//KeyRecord .
type KeyRecord struct {
	ID  string `json:"_id"`
	Rev string `json:"_rev"`

	Key                string    `json:"key"`
	Valid              bool      `json:"Valid"`
	LastUsed           time.Time `json:"last-used,omitempty"`
	Service            bool      `json:"Service"`
	Groups             []string  `json:"Groups,omitempty"`
	AllowedAuthMethods []string  `json:"AllowedAuthMethods,omitempty"`
}

func (kr *KeyRecord) HasAuthMethod(method string) bool {
	for _, m := range kr.AllowedAuthMethods {
		if m == method {
			return true
		}
	}
	return false
}
