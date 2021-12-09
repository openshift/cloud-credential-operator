package alibabacloud

import (
	"errors"
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"strings"
	"time"
)

const (
	arnDelimiter = ":"
	arnSections  = 5
	arnPrefix    = "acs:"
	arnUser      = "user"

	// zero-indexed
	sectionPartition = 0
	sectionService   = 1
	sectionRegion    = 2
	sectionAccountID = 3
	sectionResource  = 4

	// errors
	invalidPrefix   = "acs: invalid prefix"
	invalidSections = "acs: not enough sections"
	emptyRegion     = "RegionId is empty, please set a valid RegionId."
	newEmptyRegion  = "Parameter region is empty, please set a valid region id."

	//ram error code
	errorUserAlreadyExists        = "EntityAlreadyExists.User"
	errorUserNotExists            = "EntityNotExist.User"
	errorDeleteConlictPolicyUser  = "DeleteConflict.Policy.User"
	errorUserAleadyAttachedPolicy = "EntityAlreadyExists.User.Policy"
	errorPolicyNotExists          = "EntityNotExist.Policy"
	errorAKLimitExceeded          = "LimitExceeded.User.AccessKey"

	//ram accesskey status
	ramActiveStatus = "Active"
)

// ARN captures the individual fields of an RAM Resource Name.
type ARN struct {
	// The partition that the resource is in.
	Partition string

	// The service namespace that identifies the product (for example, RAM).
	Service string

	// The region the resource resides in. Note that the ARNs for some resources do not require a region, so this
	// component might be omitted.
	Region string

	// The ID of the RAM account that owns the resource, without the hyphens. For example, 123456789012. Note that the
	// ARNs for some resources don't require an account number, so this component might be omitted.
	AccountID string

	// The content of this part of the ARN varies by service.
	Resource string
}

// Parse parses an ARN into its constituent parts.
//
// Some example ARNs:
// acs:ram::123456789012:user/tester
// acs:ram::123456789012:role/defaultrole​​​
func parseArn(arn string) (ARN, error) {
	if !strings.HasPrefix(arn, arnPrefix) {
		return ARN{}, errors.New(invalidPrefix)
	}
	sections := strings.SplitN(arn, arnDelimiter, arnSections)
	if len(sections) != arnSections {
		return ARN{}, errors.New(invalidSections)
	}
	return ARN{
		Partition: sections[sectionPartition],
		Service:   sections[sectionService],
		Region:    sections[sectionRegion],
		AccountID: sections[sectionAccountID],
		Resource:  sections[sectionResource],
	}, nil
}

//getRAMUserName return the RAM username in the given ARN
func getRAMUserName(arn string) (string, error) {
	parsed, err := parseArn(arn)
	if err != nil {
		return "", fmt.Errorf("arn '%s' is invalid: %v", arn, err)
	}
	parts := strings.Split(parsed.Resource, "/")
	resource := parts[0]

	if resource != arnUser || len(parts) != 2 {
		return "", fmt.Errorf("arn '%s' is not ram user's format", arn)
	}
	return parts[1], nil
}

//generateRAMUserName generate ram user name and displayname(the max length of display name is 128 characters)
func generateRAMUserName(userName string) (string, string) {
	var shortenedUserName string
	if len(userName) > 64 {
		shortenedUserName = userName[0:64]
	} else {
		shortenedUserName = userName
	}

	displayName := fmt.Sprintf("ccoctl user for %s", userName)
	if len(displayName) > 128 {
		displayName = displayName[0:128]
	}
	return shortenedUserName, displayName
}

//generatePolicyName generate ram policy for given name, the max length of policy name is 128 characters
func generatePolicyName(name string) string {
	if len(name) > 121 {
		name = name[0:121]
	}
	return fmt.Sprintf("%s-policy", name)
}

func refineMissingRegionIdErr(err error) error {
	if err.Error() == emptyRegion {
		return errors.New(newEmptyRegion)
	}
	return err
}

//getDeleteAccessKeys return which accesskey would be deleted, including the older one and the ones with in-active status
func getDeleteAccessKeys(keys []ram.AccessKeyInListAccessKeys) ([]ram.AccessKeyInListAccessKeys, error) {
	var deleteAccessKeys = make([]ram.AccessKeyInListAccessKeys, 0)
	var keysCreated = make([]time.Time, 2)
	for i, key := range keys {
		if key.Status != ramActiveStatus {
			deleteAccessKeys = append(deleteAccessKeys, key)
		}
		t, err := time.Parse(time.RFC3339, key.CreateDate)
		if err != nil {
			return deleteAccessKeys, err
		}
		keysCreated[i] = t
	}
	if keysCreated[0].Before(keysCreated[1]) {
		deleteAccessKeys = append(deleteAccessKeys, keys[0])
	} else {
		deleteAccessKeys = append(deleteAccessKeys, keys[1])
	}
	return deleteAccessKeys, nil
}
