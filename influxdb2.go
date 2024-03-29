package influxdb2

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/database/dbplugin"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/helper/template"
	"github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/domain"
)

const (
	influxdb2TypeName = "influxdb2"
	// defaultUserNameTemplate = `{{ printf "v_%s_%s_%s_%s" (.DisplayName | truncate 15) (.RoleName | truncate 15) (random 20) (unix_time) | truncate 100 | replace "-" "_" | lowercase }}`
	// Ephemeral usernames are a bad idea with InfluxDB v2 since created tasks (etc?) are bound to a specific user
	// Since usernames are irrelevant for authentication or authorization (ironically), by default, use one bound to the role
	defaultUserNameTemplate    = `{{ printf "v_%s" (.RoleName) | replace "-" "_" | lowercase }}`
	defaultDescriptionTemplate = `{{ printf "%s %s" (.DisplayName) (.RoleName) }}`
)

// Fail to compile if InfluxDB2 does not adhere to interface
var _ dbplugin.Database = &InfluxDB2{}

func New() (interface{}, error) {
	connProducer := &influxDB2ConnectionProducer{}
	connProducer.Type = influxdb2TypeName
	db := &InfluxDB2{
		influxDB2ConnectionProducer: connProducer,
		buckets:                     make(map[string]*domain.Bucket),
		orgs:                        make(map[string]*domain.Organization),
	}
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
}

// implement Database interface.
type InfluxDB2 struct {
	*influxDB2ConnectionProducer
	mux sync.RWMutex

	// When the usernameTemplate generates unique usernames, we need to delete the user.
	// By default, this plugin maps usernames to Vault roles, which should not be deleted regularly.
	EphemeralUsers bool `json:"ephemeral_users" structs:"ephemeral_users" mapstructure:"ephemeral_users"`

	usernameProducer    template.StringTemplate
	descriptionProducer template.StringTemplate

	// lookup caches
	buckets  map[string]*domain.Bucket
	orgs     map[string]*domain.Organization
	rootUser *domain.User
}

type UsernameMetadata struct {
	DisplayName string
	RoleName    string
}

func (db *InfluxDB2) Init(ctx context.Context, conf map[string]interface{}, verifyConnection bool) (map[string]interface{}, error) {
	usernameTemplate, err := strutil.GetString(conf, "username_template")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve username_template: %w", err)
	}
	if usernameTemplate == "" {
		usernameTemplate = defaultUserNameTemplate
	}

	up, err := template.NewTemplate(template.Template(usernameTemplate))
	if err != nil {
		return nil, fmt.Errorf("unable to initialize username template: %w", err)
	}
	db.usernameProducer = up

	descriptionTemplate, err := strutil.GetString(conf, "description_template")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve description_template: %w", err)
	}
	if descriptionTemplate == "" {
		descriptionTemplate = defaultDescriptionTemplate
	}

	dp, err := template.NewTemplate(template.Template(descriptionTemplate))
	if err != nil {
		return nil, fmt.Errorf("unable to initialize description template: %w", err)
	}
	db.descriptionProducer = dp

	_, err = db.usernameProducer.Generate(UsernameMetadata{})
	if err != nil {
		return nil, fmt.Errorf("invalid username template: %w", err)
	}

	_, err = db.descriptionProducer.Generate(UsernameMetadata{})
	if err != nil {
		return nil, fmt.Errorf("invalid description template: %w", err)
	}

	return db.influxDB2ConnectionProducer.Init(ctx, conf, verifyConnection)
}

func (db *InfluxDB2) getConnection(ctx context.Context) (influxdb2.Client, error) {
	client, err := db.Connection(ctx)
	if err != nil {
		return nil, err
	}

	return client.(influxdb2.Client), nil
}

func (db *InfluxDB2) CreateUser(ctx context.Context, statements dbplugin.Statements, usernameConfig dbplugin.UsernameConfig, expiration time.Time) (string, string, error) {
	db.Lock()
	defer db.Unlock()

	username, err := db.usernameProducer.Generate(usernameConfig)
	if err != nil {
		return "", "", fmt.Errorf("Could not generate username: %w", err)
	}

	description, err := db.descriptionProducer.Generate(usernameConfig)
	if err != nil {
		return "", "", fmt.Errorf("Could not generate description: %w", err)
	}

	defs, err := newCreationStatement(statements)
	if err != nil {
		return "", "", fmt.Errorf("Unable to parse creation_statements: %w", err)
	}

	client, err := db.getConnection(ctx)
	if err != nil {
		return "", "", fmt.Errorf("Could not create connection: %w", err)
	}

	orgName := defs.Organization
	if orgName == "" {
		orgName = db.Organization
	}
	org, err := db.getOrganizationByName(orgName, client)
	if err != nil {
		return "", "", fmt.Errorf("Failed fetching organization %s: %w", db.Organization, err)
	}

	permissions, err := db.hydratePermissions(defs, org, client)
	if err != nil {
		return "", "", fmt.Errorf("Could not parse creation statement permissions: %w", err)
	}

	// We need an actual user account for vault to keep track of for ephemeral users
	var user *domain.User

	if !db.EphemeralUsers {
		user, _ = client.UsersAPI().FindUserByName(ctx, username)
	}

	if user == nil {
		user, err = client.UsersAPI().CreateUserWithName(ctx, username)
		if user == nil || err != nil {
			err_cause := fmt.Errorf("Failed to create user: %w", err)
			return "", "", db.attemptRollbackUser(ctx, client, user, err_cause)
		}

		// In case multiple organizations per user should be supported,
		// this would need an update - eg. org as owner of authorization, orgs as user membership
		_, err = client.OrganizationsAPI().AddMember(ctx, &org, user)
		if err != nil {
			err_cause := fmt.Errorf("Failed to add user to organization: %w", err)
			return "", "", db.attemptRollbackUser(ctx, client, user, err_cause)
		}
	}

	auth := &domain.Authorization{
		AuthorizationUpdateRequest: domain.AuthorizationUpdateRequest{
			Description: &description,
		},
		OrgID:       org.Id,
		Permissions: permissions,
		UserID:      user.Id,
	}

	authCreated, err := client.AuthorizationsAPI().CreateAuthorization(ctx, auth)
	if authCreated == nil || err != nil {
		err_cause := fmt.Errorf("Failed to create authorization: %w", err)
		if !db.EphemeralUsers {
			return "", "", err_cause
		}
		return "", "", db.attemptRollbackUser(ctx, client, user, err_cause)
	}

	if db.EphemeralUsers {
		// for ephemeral users, we need the actual username to keep track of
		return username, *authCreated.Token, nil
	}
	// for non-ephemeral users, we need to delete the actual authorization later
	return *authCreated.Id, *authCreated.Token, nil
}

func (db *InfluxDB2) attemptRollbackUser(ctx context.Context, client influxdb2.Client, user *domain.User, err_cause error) error {
	if user == nil {
		return err_cause
	}
	err := client.UsersAPI().DeleteUser(ctx, user)
	if err != nil {
		return fmt.Errorf("%s; Failed to rollback user: %w", err_cause, err)
	}
	return err_cause
}

func (db *InfluxDB2) attemptRollbackAuth(ctx context.Context, client influxdb2.Client, auth *domain.Authorization, err_cause error) error {
	if auth == nil {
		return err_cause
	}
	err := client.AuthorizationsAPI().DeleteAuthorization(ctx, auth)
	if err != nil {
		return fmt.Errorf("%s; Failed to rollback authorization: %w", err_cause, err)
	}
	return err_cause
}

func (db *InfluxDB2) RenewUser(ctx context.Context, statements dbplugin.Statements, username string, expiration time.Time) error {
	// unsupported
	return nil
}

func (db *InfluxDB2) RevokeUser(ctx context.Context, _ dbplugin.Statements, username string) error {
	if db.EphemeralUsers {
		return db.revokeEphemeralUser(ctx, username)
	}
	return db.revokeUserAuth(ctx, username)
}

func (db *InfluxDB2) revokeEphemeralUser(ctx context.Context, username string) error {
	db.Lock()
	defer db.Unlock()

	client, err := db.getConnection(ctx)
	if err != nil {
		return fmt.Errorf("Could not create connection: %w", err)
	}

	user, err := client.UsersAPI().FindUserByName(ctx, username)
	if err != nil {
		return fmt.Errorf("Failed to lookup user: %w", err)
	}

	// Deleting a user does not always revoke all authorizations associated with it
	auths, err := client.AuthorizationsAPI().FindAuthorizationsByUserID(ctx, *user.Id)
	if err != nil {
		return fmt.Errorf("Failed to lookup user authorizations: %w", err)
	}

	for _, auth := range *auths {
		err = client.AuthorizationsAPI().DeleteAuthorization(ctx, &auth)
		if err != nil {
			return fmt.Errorf("Failed to delete authorization: %w", err)
		}
	}

	err = client.UsersAPI().DeleteUser(ctx, user)
	if err != nil {
		return fmt.Errorf("Failed to revoke user: %w", err)
	}
	return nil
}

func (db *InfluxDB2) revokeUserAuth(ctx context.Context, authId string) error {
	db.Lock()
	defer db.Unlock()

	client, err := db.getConnection(ctx)
	if err != nil {
		return fmt.Errorf("Could not create connection: %w", err)
	}

	err = client.AuthorizationsAPI().DeleteAuthorizationWithID(ctx, authId)
	if err != nil {
		return fmt.Errorf("Failed to delete authorization: %w", err)
	}

	return nil
}

func (db *InfluxDB2) GenerateCredentials(ctx context.Context) (string, error) {
	// Unsupported, but required to not error (otherwise, the plugin crashes)
	return "", nil
}

func (db *InfluxDB2) RotateRootCredentials(ctx context.Context, statements []string) (config map[string]interface{}, err error) {
	db.Lock()
	defer db.Unlock()

	client, err := db.getConnection(ctx)
	if err != nil {
		return db.rawConfig, fmt.Errorf("Could not create connection: %w", err)
	}

	rootUser, err := db.getRootUser(client)
	if err != nil {
		return db.rawConfig, err
	}

	org, err := db.getOrganizationByName(db.Organization, client)
	if err != nil {
		return db.rawConfig, err
	}

	// Find current authentication to revoke later.
	// Something about this fails if it is done after
	// creating a new auth, so do this before
	rootAuths, err := client.AuthorizationsAPI().FindAuthorizationsByUserID(ctx, *rootUser.Id)
	if err != nil {
		return db.rawConfig, fmt.Errorf("Failed to lookup root authorizations: %w", err)
	}
	var rootAuth *domain.Authorization
	for _, auth := range *rootAuths {
		// Would be oldToken if done after, but still fails (finds the new auth)
		// @TODO check why
		if *auth.Token == db.Token {
			rootAuth = &auth
		}
	}
	if rootAuth == nil {
		return db.rawConfig, fmt.Errorf("Failed to find old authorization")
	}

	description := "Vault root token"

	auth := &domain.Authorization{
		AuthorizationUpdateRequest: domain.AuthorizationUpdateRequest{
			Description: &description,
		},
		OrgID:       org.Id,
		Permissions: rootAuth.Permissions, // inherit permissions because they might vary
		UserID:      rootUser.Id,
	}

	authCreated, err := client.AuthorizationsAPI().CreateAuthorization(ctx, auth)
	if err != nil {
		return db.rawConfig, fmt.Errorf("Failed to create authorization: %w", err)
	}
	oldToken := db.rawConfig["password"].(string)
	db.rawConfig["password"] = *authCreated.Token
	db.Token = *authCreated.Token

	err = client.AuthorizationsAPI().DeleteAuthorization(ctx, rootAuth)
	if err != nil {
		db.rawConfig["password"] = oldToken
		db.Token = oldToken
		err_cause := fmt.Errorf("Failed to revoke old root authorization: %w", err)
		return db.rawConfig, db.attemptRollbackAuth(ctx, client, authCreated, err_cause)
	}

	return db.rawConfig, nil
}

func (db *InfluxDB2) Type() (string, error) {
	return influxdb2TypeName, nil
}

// represents permissions for a role
type creationStatement struct {
	Read         []domain.ResourceType `json:"read"`
	Write        []domain.ResourceType `json:"write"`
	ReadBucket   []string              `json:"read_bucket"`
	WriteBucket  []string              `json:"write_bucket"`
	Organization string                `json:"org"`
}

func newCreationStatement(statements dbplugin.Statements) (*creationStatement, error) {
	if len(statements.Creation) == 0 {
		return nil, dbutil.ErrEmptyCreationStatement
	}
	if len(statements.Creation) > 1 {
		return nil, fmt.Errorf("only 1 creation statement supported for creation")
	}
	stmt := &creationStatement{}
	if err := json.Unmarshal([]byte(statements.Creation[0]), stmt); err != nil {
		return nil, fmt.Errorf("unable to unmarshal %s: %w", []byte(statements.Creation[0]), err)
	}
	return stmt, nil
}

func (db *InfluxDB2) SetCredentials(ctx context.Context, statements dbplugin.Statements, staticUser dbplugin.StaticUserConfig) (username, password string, err error) {
	return "", "", dbutil.Unimplemented()
}

func (db *InfluxDB2) hydratePermissions(defs *creationStatement, org domain.Organization, client influxdb2.Client) (*[]domain.Permission, error) {
	var perms []domain.Permission
	// read all of type
	for _, resource := range defs.Read {
		perm := &domain.Permission{
			Action: domain.PermissionActionRead,
			Resource: domain.Resource{
				Type: resource,
			},
		}
		// There is no concept of sub-organizations
		if resource != "orgs" {
			perm.Resource.OrgID = org.Id
		}
		perms = append(perms, *perm)
	}
	// write all of type
	for _, resource := range defs.Write {
		perm := &domain.Permission{
			Action: domain.PermissionActionWrite,
			Resource: domain.Resource{
				Type: resource,
			},
		}
		if resource != "orgs" {
			perm.Resource.OrgID = org.Id
		}
		perms = append(perms, *perm)
	}
	// read specific buckets
	for _, name := range defs.ReadBucket {
		bucket, err := db.getBucketByName(name, client)
		if err != nil {
			return nil, err
		}
		perm := &domain.Permission{
			Action: domain.PermissionActionRead,
			Resource: domain.Resource{
				Type: domain.ResourceTypeBuckets,
				Id:   bucket.Id,
			},
		}
		perms = append(perms, *perm)
	}
	// write specific buckets
	for _, name := range defs.WriteBucket {
		bucket, err := db.getBucketByName(name, client)
		if err != nil {
			return nil, err
		}
		perm := &domain.Permission{
			Action: domain.PermissionActionWrite,
			Resource: domain.Resource{
				Type: domain.ResourceTypeBuckets,
				Id:   bucket.Id,
			},
		}
		perms = append(perms, *perm)
	}
	return &perms, nil
}

func (db *InfluxDB2) getBucketByName(name string, client influxdb2.Client) (domain.Bucket, error) {
	bucket, ok := db.buckets[name]
	if !ok {
		var err error
		bucket, err = client.BucketsAPI().FindBucketByName(context.Background(), name)
		if err != nil {
			return domain.Bucket{}, fmt.Errorf("Failed looking up bucket with name %s: %w", name, err)
		}
		db.buckets[name] = bucket
	}
	return *bucket, nil
}

func (db *InfluxDB2) getOrganizationByName(name string, client influxdb2.Client) (domain.Organization, error) {
	org, ok := db.orgs[name]
	if !ok {
		var err error
		org, err = client.OrganizationsAPI().FindOrganizationByName(context.Background(), name)
		if err != nil {
			return domain.Organization{}, fmt.Errorf("Failed looking up organization with name %s: %w", org, err)
		}
		db.orgs[name] = org
	}
	return *org, nil
}

func (db *InfluxDB2) getRootUser(client influxdb2.Client) (domain.User, error) {
	if db.rootUser == nil {
		rootUser, err := client.UsersAPI().Me(context.Background())
		if err != nil {
			return domain.User{}, fmt.Errorf("Failed to lookup root user: %w", err)
		}
		db.rootUser = rootUser
	}
	return *db.rootUser, nil
}
