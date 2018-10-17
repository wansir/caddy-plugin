package admission

import (
	"net/http"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/kubernetes/pkg/util/slice"
	"kubesphere.io/caddy-plugin/addmission/informer"
	"fmt"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type Admission struct {
	Rules []Rule
	Next  httpserver.Handler
}

type Rule struct {
	Path     string
	APIGroup string
	Resource string
}

func (c Admission) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	attrs, err := filters.GetAuthorizerAttributes(r.Context())

	if err == nil {

		var attrsRecord *authorizer.AttributesRecord
		attrsRecord = attrs.(*authorizer.AttributesRecord)

		for _, rule := range c.Rules {
			if httpserver.Path(r.URL.Path).Matches(rule.Path) {
				if rule.APIGroup != "" {
					attrsRecord.APIGroup = rule.APIGroup
				}
				if rule.Resource != "" {
					attrsRecord.Resource = rule.Resource
				}
			}
		}

		err := admit(attrs)

		if err != nil {
			return handleForbidden(w, r, err.Error()), nil
		}

	}

	return c.Next.ServeHTTP(w, r)
}

func handleForbidden(w http.ResponseWriter, r *http.Request, reason string) int {
	message := fmt.Sprintf("Forbidden,%s", reason)
	w.Header().Add("WWW-Authenticate", message)
	return http.StatusForbidden
}

func admit(attrs authorizer.Attributes) error {

	if clusterRoleCheck(attrs) {
		return nil
	}

	if attrs.GetNamespace() != "" && roleCheck(attrs) {
		return nil
	}

	return errors.NewForbidden(schema.GroupResource{Group: attrs.GetAPIGroup(), Resource: attrs.GetResource()}, attrs.GetName(), fmt.Errorf("permission undefined"))
}
func roleCheck(attrs authorizer.Attributes) bool {

	roleBindings, err := informer.RoleBindingInformer.Lister().RoleBindings(attrs.GetNamespace()).List(labels.Everything())

	if err != nil {
		return false
	}

	for _, roleBinding := range roleBindings {

		for _, subj := range roleBinding.Subjects {

			if (subj.Kind == v1.UserKind && subj.Name == attrs.GetUser().GetName()) ||
				(subj.Kind == v1.GroupKind && slice.ContainsString(attrs.GetUser().GetGroups(), subj.Name, nil)) {
				role, err := informer.RoleInformer.Lister().Roles(attrs.GetNamespace()).Get(roleBinding.RoleRef.Name)

				// TODO exception handle
				if err != nil {
					continue
				}

				if attrs.IsResourceRequest() {
					if verbValidate(role.Rules, attrs.GetAPIGroup(), "", attrs.GetResource(), attrs.GetName(), attrs.GetVerb()) {
						return true
					}
				} else if verbValidate(role.Rules, attrs.GetAPIGroup(), attrs.GetPath(), "", "", attrs.GetVerb()) {
					return true
				}

			}
		}
	}

	return false
}

func clusterRoleCheck(attrs authorizer.Attributes) bool {

	if attrs.GetResource() == "users" && attrs.GetUser().GetName() == attrs.GetName() {
		return true
	}

	clusterRoleBindings, err := informer.ClusterRoleBindingInformer.Lister().List(labels.Everything())

	if err != nil {
		return false
	}

	for _, clusterRoleBinding := range clusterRoleBindings {

		for _, subj := range clusterRoleBinding.Subjects {

			if (subj.Kind == v1.UserKind && subj.Name == attrs.GetUser().GetName()) ||
				(subj.Kind == v1.GroupKind && slice.ContainsString(attrs.GetUser().GetGroups(), subj.Name, nil)) {
				clusterRole, err := informer.ClusterRoleInformer.Lister().Get(clusterRoleBinding.RoleRef.Name)

				// TODO exception handle
				if err != nil {
					continue
				}

				if attrs.IsResourceRequest() {
					if verbValidate(clusterRole.Rules, attrs.GetAPIGroup(), "", attrs.GetResource(), attrs.GetName(), attrs.GetVerb()) {
						return true
					}
				} else if verbValidate(clusterRole.Rules, "", attrs.GetPath(), "", "", attrs.GetVerb()) {
					return true
				}

			}
		}
	}

	return false
}

func verbValidate(rules []v1.PolicyRule, apiGroup string, nonResourceURL string, resource string, resourceName string, verb string) bool {
	for _, rule := range rules {

		if nonResourceURL == "" {
			if slice.ContainsString(rule.APIGroups, apiGroup, nil) ||
				slice.ContainsString(rule.APIGroups, v1.APIGroupAll, nil) {
				if slice.ContainsString(rule.Verbs, verb, nil) ||
					slice.ContainsString(rule.Verbs, v1.VerbAll, nil) {
					if slice.ContainsString(rule.Resources, v1.ResourceAll, nil) {
						return true
					} else if slice.ContainsString(rule.Resources, resource, nil) {
						if len(rule.ResourceNames) > 0 {
							if slice.ContainsString(rule.ResourceNames, resourceName, nil) {
								return true
							}
						} else if resourceName == "" {
							return true
						}
					}
				}
			}

		} else if slice.ContainsString(rule.NonResourceURLs, nonResourceURL, nil) ||
			slice.ContainsString(rule.NonResourceURLs, v1.NonResourceAll, nil) {
			if slice.ContainsString(rule.Verbs, verb, nil) ||
				slice.ContainsString(rule.Verbs, v1.VerbAll, nil) {
				return true
			}
		}
	}
	return false
}
