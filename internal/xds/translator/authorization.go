// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"errors"
	"fmt"
	"net"

	v32 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	frbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/envoyproxy/gateway/internal/ir"
	"github.com/envoyproxy/gateway/internal/xds/types"
)

const (
	authorizationFilter = "envoy.filters.http.rbac"
)

func init() {
	registerHTTPFilter(&authorization{})
}

type authorization struct {
}

var _ httpFilter = &authorization{}

func (*authorization) patchHCM(mgr *hcmv3.HttpConnectionManager, irListener *ir.HTTPListener) error {
	var errs error
	if mgr == nil {
		return errors.New("hcm is nil")
	}

	if irListener == nil {
		return errors.New("ir listener is nil")
	}

	for _, route := range irListener.Routes {
		if !routeContainsAuthorization(route) {
			continue
		}

		for i, rule := range route.Authorization.Rules {
			filter, err := buildHCMAuthorizationFilter(rule, authorizationFilterName(route, i))
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to build authorization filter for route %s: %w", route.Name, err))
				return errs
			}
			mgr.HttpFilters = append(mgr.HttpFilters, filter)
		}
	}
	return errs
}

// buildHCMAuthorizationFilter returns an authorization HTTP filter from the provided IR HTTPRoute.
func buildHCMAuthorizationFilter(rule *ir.Rule, name string) (*hcmv3.HttpFilter, error) {
	authProto, err := authorizationConfig(rule)
	if err != nil {
		return nil, err
	}
	if err := authProto.ValidateAll(); err != nil {
		return nil, err
	}

	aclAny, err := anypb.New(authProto)
	if err != nil {
		return nil, err
	}

	return &hcmv3.HttpFilter{
		Name: name,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{
			TypedConfig: aclAny,
		},
	}, nil
}

func authorizationConfig(rule *ir.Rule) (*frbacv3.RBAC, error) {
	var action rbacv3.RBAC_Action
	switch rule.Action {
	case ir.AllowRuleType:
		action = rbacv3.RBAC_ALLOW
	case ir.DenyRuleType:
		action = rbacv3.RBAC_DENY
	case ir.LogRuleType:
		action = rbacv3.RBAC_LOG
	default:
		return nil, fmt.Errorf("unknown action type: %s", rule.Action)
	}

	config := &frbacv3.RBAC{
		Rules: &rbacv3.RBAC{
			Action: action,
		},
	}

	var principals []*rbacv3.Principal
	for _, selector := range rule.ClientSelectors {
		// TODO: loop other selector rules here like jwt...etc
		for _, cidr := range selector.ClientCIDRs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, err
			}
			prefixLen, _ := ipnet.Mask.Size()
			principals = append(principals, &rbacv3.Principal{
				Identifier: &rbacv3.Principal_SourceIp{
					SourceIp: &v32.CidrRange{
						AddressPrefix: ipnet.IP.String(),
						PrefixLen: &wrapperspb.UInt32Value{
							Value: uint32(prefixLen),
						},
					},
				},
			})
		}
	}

	// TODO: permissions needs to be configurable in API.
	// otherwise its not possible to like block for instance /admin from normal user
	config.Rules.Policies = map[string]*rbacv3.Policy{
		"policy": {
			Permissions: []*rbacv3.Permission{
				{
					Rule: &rbacv3.Permission_Any{
						Any: true,
					},
				},
			},
			Principals: principals,
		},
	}

	return config, nil
}

func authorizationFilterName(route *ir.HTTPRoute, ruleIndex int) string {
	return perRouteFilterName(authorizationFilter, fmt.Sprintf("%s_%d", route.Name, ruleIndex))
}

// routeContainsAuthorization returns true if authorization exists for the provided route.
func routeContainsAuthorization(irRoute *ir.HTTPRoute) bool {
	if irRoute == nil {
		return false
	}

	if irRoute != nil &&
		irRoute.Authorization != nil {
		return true
	}

	return false
}

func (*authorization) patchResources(tCtx *types.ResourceVersionTable,
	routes []*ir.HTTPRoute) error {
	return nil
}

func (*authorization) patchRoute(route *routev3.Route, irRoute *ir.HTTPRoute) error {
	if route == nil {
		return errors.New("xds route is nil")
	}
	if irRoute == nil {
		return errors.New("ir route is nil")
	}
	if irRoute.Authorization == nil {
		return nil
	}

	filterCfg := route.GetTypedPerFilterConfig()
	for i, rule := range irRoute.Authorization.Rules {
		filterName := authorizationFilterName(irRoute, i)

		conf, err := authorizationConfig(rule)
		if err != nil {
			return fmt.Errorf("failed to build authorization config for route %s: %w", irRoute.Name, err)
		}

		routeCfgProto := &frbacv3.RBACPerRoute{
			Rbac: conf,
		}

		routeCfgAny, err := anypb.New(routeCfgProto)
		if err != nil {
			return fmt.Errorf("failed to marshal authorization config for route %s: %w", irRoute.Name, err)
		}

		if filterCfg == nil {
			route.TypedPerFilterConfig = make(map[string]*anypb.Any)
		}

		route.TypedPerFilterConfig[filterName] = routeCfgAny
	}

	return nil
}

// patchRouteCfg patches the provided route configuration with the acl filter
// if applicable.
func (*authorization) patchRouteConfig(routeCfg *routev3.RouteConfiguration, irListener *ir.HTTPListener) error {
	return nil
}
