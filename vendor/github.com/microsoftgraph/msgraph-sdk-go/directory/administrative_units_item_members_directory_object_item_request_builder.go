package directory

import (
    i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f "github.com/microsoft/kiota-abstractions-go"
)

// AdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilder builds and executes requests for operations under \directory\administrativeUnits\{administrativeUnit-id}\members\{directoryObject-id}
type AdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilder struct {
    // Path parameters for the request
    pathParameters map[string]string
    // The request adapter to use to execute the requests.
    requestAdapter i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestAdapter
    // Url template to use to build the URL for the current request builder
    urlTemplate string
}
// NewAdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilderInternal instantiates a new DirectoryObjectItemRequestBuilder and sets the default values.
func NewAdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilderInternal(pathParameters map[string]string, requestAdapter i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestAdapter)(*AdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilder) {
    m := &AdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilder{
    }
    m.urlTemplate = "{+baseurl}/directory/administrativeUnits/{administrativeUnit%2Did}/members/{directoryObject%2Did}";
    urlTplParams := make(map[string]string)
    for idx, item := range pathParameters {
        urlTplParams[idx] = item
    }
    m.pathParameters = urlTplParams
    m.requestAdapter = requestAdapter
    return m
}
// NewAdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilder instantiates a new DirectoryObjectItemRequestBuilder and sets the default values.
func NewAdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilder(rawUrl string, requestAdapter i2ae4187f7daee263371cb1c977df639813ab50ffa529013b7437480d1ec0158f.RequestAdapter)(*AdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilder) {
    urlParams := make(map[string]string)
    urlParams["request-raw-url"] = rawUrl
    return NewAdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilderInternal(urlParams, requestAdapter)
}
// GraphApplication casts the previous resource to application.
func (m *AdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilder) GraphApplication()(*AdministrativeUnitsItemMembersItemGraphApplicationRequestBuilder) {
    return NewAdministrativeUnitsItemMembersItemGraphApplicationRequestBuilderInternal(m.pathParameters, m.requestAdapter)
}
// GraphDevice casts the previous resource to device.
func (m *AdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilder) GraphDevice()(*AdministrativeUnitsItemMembersItemGraphDeviceRequestBuilder) {
    return NewAdministrativeUnitsItemMembersItemGraphDeviceRequestBuilderInternal(m.pathParameters, m.requestAdapter)
}
// GraphGroup casts the previous resource to group.
func (m *AdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilder) GraphGroup()(*AdministrativeUnitsItemMembersItemGraphGroupRequestBuilder) {
    return NewAdministrativeUnitsItemMembersItemGraphGroupRequestBuilderInternal(m.pathParameters, m.requestAdapter)
}
// GraphOrgContact casts the previous resource to orgContact.
func (m *AdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilder) GraphOrgContact()(*AdministrativeUnitsItemMembersItemGraphOrgContactRequestBuilder) {
    return NewAdministrativeUnitsItemMembersItemGraphOrgContactRequestBuilderInternal(m.pathParameters, m.requestAdapter)
}
// GraphServicePrincipal casts the previous resource to servicePrincipal.
func (m *AdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilder) GraphServicePrincipal()(*AdministrativeUnitsItemMembersItemGraphServicePrincipalRequestBuilder) {
    return NewAdministrativeUnitsItemMembersItemGraphServicePrincipalRequestBuilderInternal(m.pathParameters, m.requestAdapter)
}
// GraphUser casts the previous resource to user.
func (m *AdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilder) GraphUser()(*AdministrativeUnitsItemMembersItemGraphUserRequestBuilder) {
    return NewAdministrativeUnitsItemMembersItemGraphUserRequestBuilderInternal(m.pathParameters, m.requestAdapter)
}
// Ref provides operations to manage the collection of directory entities.
func (m *AdministrativeUnitsItemMembersDirectoryObjectItemRequestBuilder) Ref()(*AdministrativeUnitsItemMembersItemRefRequestBuilder) {
    return NewAdministrativeUnitsItemMembersItemRefRequestBuilderInternal(m.pathParameters, m.requestAdapter)
}
